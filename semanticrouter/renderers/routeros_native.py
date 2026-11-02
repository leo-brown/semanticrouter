"""Complete same-family RouterOS export with a source document and semantic edits.

The document is a separate import artifact, never part of public model JSON. Original
statements, credentials, scripts, comments, selectors and vendor-only properties stay
intact. Only changed modeled properties are rewritten. Re-importing the result must
recover the requested functional model before completeness is reported.
"""

import re
from dataclasses import asdict, dataclass, field

from ..adapters.routeros.parser import parse
from ..adapters.routeros.router import RouterOSRouter
from ..definitions import definition
from .base import ExportResult, UnsupportedExport
from .routeros import quote, route_expression


def _clean(value):
    if isinstance(value, dict):
        return {key: _clean(item) for key, item in value.items() if key != "source"}
    if isinstance(value, list):
        return [_clean(item) for item in value]
    return value


def functional(router):
    """Compare functional data, excluding import metadata and inventory labels."""
    values = router.to_dict()
    for rule in values["bgp"]["policies"]:
        if rule["action"] == "discard":
            rule["action"] = "reject"
    return {
        key: _clean(value)
        for key, value in values.items()
        if key not in {"name", "role", "platform", "diagnostics", "unexported"}
    }


def signature(item):
    """Native statement identity, independent of quoting, whitespace and source lines."""
    return (item.path, item.verb, tuple(sorted(item.attributes.items())), item.selector)


def _tokens(text):
    """Keep literal tokens, including quotes and bracket selectors, without eval."""
    result, start, quoted, depth, escape = [], None, False, 0, False
    for index, char in enumerate(text):
        if start is None and not char.isspace():
            start = index
        if escape:
            escape = False
        elif char == "\\":
            escape = True
        elif char == '"':
            quoted = not quoted
        elif not quoted and char == "[":
            depth += 1
        elif not quoted and char == "]":
            depth -= 1
        elif not quoted and not depth and char.isspace() and start is not None:
            result.append(text[start:index])
            start = None
    if start is not None:
        result.append(text[start:])
    return result


@dataclass
class Statement:
    """Output plus its independently derived native contract; never repr credentials."""

    text: str = field(repr=False)
    expected: tuple = field(repr=False)


def new_statement(path, verb, attrs):
    for key in attrs:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", key):
            raise UnsupportedExport("Invalid RouterOS property name in model edit")
    values = {key: str(value) for key, value in attrs.items() if value is not None}
    text = (
        path
        + " "
        + verb
        + " "
        + " ".join(key + "=" + quote(value) for key, value in values.items())
    )
    return Statement(text, (path, verb, tuple(sorted(values.items())), ""))


class Document:
    """Order-preserving edits to physical source spans, not generated fragments."""

    def __init__(self, adapter):
        self.adapter = adapter
        self.lines = adapter.text.splitlines(keepends=True)
        self.commands = {item.source.line: item for item in adapter.commands}
        self.replacements = {}
        self.after = {}
        self.appended = []
        self.rewritten = 0
        self.expected = []

    def end(self, line):
        end = line
        while self.lines[end - 1].rstrip().endswith("\\") and end < len(self.lines):
            end += 1
        return end

    def original(self, line, absolute=False):
        text = "".join(self.lines[line - 1 : self.end(line)]).rstrip("\r\n")
        if absolute and not text.lstrip().startswith("/"):
            text = self.commands[line].path + " " + text.lstrip()
        return text

    def edit(self, line, updates):
        """Preserve literal values of unedited properties and selector expressions."""
        item = self.commands[line]
        logical = re.sub(r"\\\r?\n\s*", " ", self.original(line))
        words = _tokens(logical)
        verb = next(i for i, word in enumerate(words) if word == item.verb)
        selector, attributes, group = [], {}, ""
        for word in words[verb + 1 :]:
            if word.startswith("[") or "=" not in word:
                selector.append(word)
                continue
            key, value = word.split("=", 1)
            if key.startswith("."):
                key = group + key
            elif "." in key:
                group = key.rsplit(".", 1)[0]
            else:
                group = ""
            if key in attributes:
                raise UnsupportedExport(
                    "Cannot edit a statement with duplicate properties: " + item.path
                )
            attributes[key] = value
        expected_attrs = dict(item.attributes)
        for key, value in updates.items():
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", key):
                raise UnsupportedExport("Invalid RouterOS property name in model edit")
            if value is None:
                expected_attrs.pop(key, None)
            else:
                expected_attrs[key] = str(value)
            if value is None:
                attributes.pop(key, None)
            else:
                attributes[key] = quote(value)
        result = " ".join(
            [
                item.path,
                item.verb,
                *selector,
                *(key + "=" + value for key, value in attributes.items()),
            ]
        )
        self.rewritten += 1
        if attributes or selector:
            return Statement(
                result,
                (
                    item.path,
                    item.verb,
                    tuple(sorted(expected_attrs.items())),
                    item.selector,
                ),
            )
        return None

    def collection(self, before, after, encode):
        """Reconcile additions/removals/order while retaining unrelated statements."""
        originals = {item.source.line: item for item in before if item.source}
        slots = list(originals)
        rendered = []
        used = set()
        for position, item in enumerate(after):
            line = item.source.line if item.source else None
            previous = originals.get(line)
            if previous and line in used:
                raise UnsupportedExport(
                    "Two objects refer to the same source statement"
                )
            if previous:
                used.add(line)
                if _clean(asdict(previous)) == _clean(asdict(item)):
                    text = Statement(
                        self.original(line, absolute=True),
                        signature(self.commands[line]),
                    )
                else:
                    path, old_attrs = encode(previous)
                    new_path, attrs = encode(item)
                    if path != new_path:
                        raise UnsupportedExport(
                            "Changing interface kind requires editing the source definition"
                        )
                    updates = {
                        key: attrs.get(key)
                        for key in old_attrs.keys() | attrs.keys()
                        if old_attrs.get(key) != attrs.get(key)
                    }
                    text = self.edit(line, updates)
            else:
                path, attrs = encode(item)
                if path == "/interface ethernet":
                    raise UnsupportedExport(
                        "Physical interface settings need their original set/find definition; do not add a hardware port."
                    )
                if path == "/routing bgp connection" and not item.role:
                    raise UnsupportedExport(
                        "A new BGP connection needs an explicit local role."
                    )
                text = new_statement(path, "add", attrs)
                self.rewritten += 1
            rendered.append(text)
        for index, line in enumerate(slots):
            self.replacements[line] = rendered[index] if index < len(rendered) else None
        extras = rendered[len(slots) :]
        if extras:
            if slots:
                self.after.setdefault(self.end(slots[-1]), []).extend(extras)
            else:
                self.appended.extend(extras)

    def setting(self, path, updates):
        matches = [
            item
            for item in self.adapter.commands
            if item.path == path and item.verb == "set"
        ]
        if matches:
            item = matches[-1]
            self.replacements[item.source.line] = self.edit(item.source.line, updates)
        else:
            self.appended.append(new_statement(path, "set", updates))
            self.rewritten += 1

    def text(self):
        output = []
        self.expected = []

        def emit(statement):
            output.append(statement.text.rstrip("\r\n") + "\n")
            self.expected.append(statement.expected)

        index = 1
        while index <= len(self.lines):
            if index in self.replacements:
                end = self.end(index)
                if self.replacements[index]:
                    emit(self.replacements[index])
            elif index in self.commands:
                end = self.end(index)
                # Absolute paths make retained statements independent of the last
                # section when objects are inserted, deleted or reordered.
                emit(
                    Statement(
                        self.original(index, absolute=True),
                        signature(self.commands[index]),
                    )
                )
            else:
                end = index
                output.append(self.lines[index - 1])
            for extra in self.after.get(end, []):
                emit(extra)
            index = end + 1
        for extra in self.appended:
            emit(extra)
        return "".join(output).rstrip("\r\n") + "\n"


def _enabled(item):
    return "no" if item.enabled else "yes"


def address(item):
    return "/ip address", {
        "address": item.address,
        "network": item.peer,
        "interface": item.interface,
        "disabled": _enabled(item),
    }


def interface(item):
    if item.kind not in {"ethernet", "bridge", "bonding", "vlan"}:
        raise UnsupportedExport(
            "This interface needs a complete native source definition: " + item.kind
        )
    return "/interface " + item.kind, {
        "name": item.name,
        "disabled": _enabled(item),
        "slaves": ",".join(item.members) or None,
        "mode": item.mode,
        "interface": item.parent,
        "vlan-id": item.vlan,
        "comment": item.comment or None,
    }


def firewall(item, path="/ip firewall filter"):
    attrs = {
        "chain": item.chain,
        "action": item.action,
        "protocol": item.protocol,
        "src-address": item.source_network,
        "src-address-list": item.source_group,
        "dst-address": item.destination_network,
        "dst-address-list": item.destination_group,
        "dst-port": item.destination_ports,
        "src-port": item.source_ports,
        "in-interface": item.ingress,
        "out-interface": item.egress,
        "disabled": _enabled(item),
    }
    attrs.update(
        {key: value for key, value in item.extra.items() if not key.startswith("_")}
    )
    return path, attrs


def group(item):
    return "/ip firewall address-list", {
        "list": item.name,
        "address": item.network,
        "disabled": _enabled(item),
    }


def peer(item):
    return "/routing bgp connection", {
        "name": item.name,
        "remote.address": item.remote_address,
        "remote.as": item.remote_as,
        "local.address": item.local_address,
        "local.role": item.role,
        "as": item.local_as,
        "router-id": item.router_id,
        "input.filter": item.import_policy,
        "output.filter-chain": item.export_policy,
        "output.redistribute": ",".join(item.redistribute) or None,
        "output.default-originate": item.default_originate,
        "disabled": _enabled(item),
    }


def peer6(item):
    return "/routing bgp peer", {
        "name": item.name,
        "remote-address": item.remote_address,
        "remote-as": item.remote_as,
        "update-source": item.local_address,
        "in-filter": item.import_policy,
        "out-filter": item.export_policy,
        "disabled": _enabled(item),
    }


def policy6(item):
    if not item.supported:
        raise UnsupportedExport(
            "An unresolved legacy route filter must be edited in its original source."
        )
    return "/routing filter", {
        "chain": item.chain,
        "action": "discard" if item.action == "reject" else item.action,
        "prefix": item.prefix,
        "prefix-length": str(item.min_length) + "-" + str(item.max_length),
        "disabled": _enabled(item),
    }


def policy(item):
    return "/routing filter rule", {
        "chain": item.chain,
        "rule": route_expression(item),
        "disabled": _enabled(item),
    }


def ppp_server(item):
    return "/interface pppoe-server server", {
        "interface": item.interface,
        "max-mtu": item.mtu,
        "authentication": ",".join(item.authentication),
        "default-profile": item.profile,
        "disabled": _enabled(item),
    }


def radius(item):
    return "/radius", {
        "address": item.address,
        "src-address": item.source_address,
        "timeout": str(item.timeout_ms) + "ms" if item.timeout_ms is not None else None,
        "disabled": _enabled(item),
    }


def profile_name(item):
    name = item.attributes.get("name", item.selector)
    if "find" in name:
        match = re.search(r"name\s*=\s*([^\s\]]+)", name)
        name = match[1] if match else name
    return name


def render_complete(router, version, source, source_version=None):
    """Export all source statements and verify functional edits by re-importing."""
    if re.search(r"\[REDACTED\]|# \[(?:credential-bearing|device identifier)", source):
        raise UnsupportedExport(
            "A complete export needs the original configuration, not a redacted review copy."
        )
    adapter = RouterOSRouter(
        router.name, source, path=router.name + ".cfg", version=source_version
    )
    if any(item.verb not in {"add", "set"} for item in adapter.commands):
        raise UnsupportedExport(
            "Complete source-aware export requires a configuration snapshot, not an executable edit script."
        )
    before = adapter.to_common()
    layout = definition("routeros-7.20")
    modern = before.platform.family != "6" and any(
        item.path == layout["native_marker"] for item in adapter.commands
    )
    boundary = tuple(map(int, layout["native_min_version"].split(".")))
    if (
        modern
        and before.platform.version
        and re.match(r"7\.(\d+)", before.platform.version)
        and int(re.match(r"7\.(\d+)", before.platform.version)[1]) < boundary[1]
    ):
        raise UnsupportedExport(
            "Declared source version conflicts with its RouterOS 7.20+ BGP instance syntax."
        )
    if version != "source":
        if not re.fullmatch(r"7\.\d+(?:\.\d+)?", version):
            raise UnsupportedExport(
                "Choose original source syntax or a concrete RouterOS 7 release."
            )
        connections = any(
            item.path == layout["connection_path"] for item in adapter.commands
        )
        target = tuple(map(int, version.split(".")))
        if target < (7, 1):
            raise UnsupportedExport(
                "Choose RouterOS 7.1 or later, or source to preserve the original format."
            )
        boundary = tuple(map(int, layout["native_min_version"].split(".")))
        if modern and target < boundary:
            raise UnsupportedExport(
                "Source uses the RouterOS 7.20+ BGP instance layout. Choose source (original syntax) or a 7.20+ target; do not silently downgrade it to 7.19."
            )
        if connections and not modern and target >= boundary:
            raise UnsupportedExport(
                "This source uses pre-7.20 BGP connections. Select source to preserve them; converting the instance layout requires a migration mapping."
            )

    def native_peer(item):
        path, attrs = peer(item)
        if modern:
            attrs.pop(
                "router-id", None
            )  # Instance-owned; a model-only change must fail round-trip proof.
        return path, attrs

    peer_lines = {item.source.line for item in before.bgp.peers if item.source}
    if modern and any(
        not item.source or item.source.line not in peer_lines
        for item in router.bgp.peers
    ):
        raise UnsupportedExport(
            "A new instance-based BGP connection needs its complete instance definition in the source configuration."
        )
    doc = Document(adapter)
    if before.identity != router.identity:
        doc.setting("/system identity", {"name": router.identity})
    if before.dns != router.dns:
        doc.setting("/ip dns", {"servers": ",".join(router.dns)})
    if before.firewall_v4.connection_tracking != router.firewall_v4.connection_tracking:
        value = router.firewall_v4.connection_tracking
        doc.setting(
            "/ip firewall connection tracking",
            {"enabled": "yes" if value is True else "no" if value is False else "auto"},
        )
    if (before.snmp_enabled, before.snmp_location) != (
        router.snmp_enabled,
        router.snmp_location,
    ):
        updates = {}
        if before.snmp_enabled != router.snmp_enabled:
            updates["enabled"] = "yes" if router.snmp_enabled else "no"
        if before.snmp_location != router.snmp_location:
            updates["location"] = router.snmp_location
        doc.setting("/snmp", updates)
    for old, new, encoder in [
        (before.interfaces, router.interfaces, interface),
        (before.addresses, router.addresses, address),
        (before.firewall_v4.groups, router.firewall_v4.groups, group),
        (before.firewall_v4.rules, router.firewall_v4.rules, firewall),
        (
            before.firewall_v6,
            router.firewall_v6,
            lambda item: firewall(item, "/ipv6 firewall filter"),
        ),
        (
            before.bgp.peers,
            router.bgp.peers,
            peer6 if before.platform.family == "6" else native_peer,
        ),
        (
            before.bgp.policies,
            router.bgp.policies,
            policy6 if before.platform.family == "6" else policy,
        ),
        (before.ppp_servers, router.ppp_servers, ppp_server),
        (before.radius, router.radius, radius),
    ]:
        doc.collection(old, new, encoder)
    if before.ppp_local_addresses != router.ppp_local_addresses:
        for name, value in router.ppp_local_addresses.items():
            if before.ppp_local_addresses.get(name) == value:
                continue
            candidates = [
                item
                for item in adapter.commands
                if item.path == "/ppp profile" and profile_name(item) == name
            ]
            if candidates:
                item = candidates[-1]
                doc.replacements[item.source.line] = doc.edit(
                    item.source.line, {"local-address": value}
                )
            else:
                doc.appended.append(
                    new_statement(
                        "/ppp profile", "add", {"name": name, "local-address": value}
                    )
                )
        for name in set(before.ppp_local_addresses) - set(router.ppp_local_addresses):
            candidates = [
                item
                for item in adapter.commands
                if item.path == "/ppp profile" and profile_name(item) == name
            ]
            if not candidates:
                raise UnsupportedExport(
                    "PPP profile source definition is not available: " + name
                )
            item = candidates[-1]
            doc.replacements[item.source.line] = doc.edit(
                item.source.line, {"local-address": None}
            )
    if before.ospf_interfaces != router.ospf_interfaces:
        removed = set(before.ospf_interfaces) - set(router.ospf_interfaces)
        added = set(router.ospf_interfaces) - set(before.ospf_interfaces)
        for item in adapter.commands:
            if item.path != "/routing ospf interface-template":
                continue
            names = item.attributes.get("interfaces", "").split(",")
            if removed.intersection(names):
                remaining = [name for name in names if name not in removed]
                doc.replacements[item.source.line] = doc.edit(
                    item.source.line,
                    {
                        "interfaces": ",".join(remaining),
                        **({"disabled": "yes"} if not remaining else {}),
                    },
                )
        if added:
            raise UnsupportedExport(
                "A new OSPF adjacency needs area/template settings. Add it in the complete source configuration first."
            )
    text = (
        "# SemanticRouter complete RouterOS export; target="
        + version
        + "\n"
        + doc.text()
    )
    restored = RouterOSRouter(
        router.name,
        text,
        path=router.name + ".cfg",
        version=before.platform.version if version == "source" else version,
    ).to_common()
    original_match = functional(before) == functional(router)
    actual = [signature(item) for item in parse(text)]
    original_statements_match = actual == [signature(item) for item in adapter.commands]
    if original_match and not original_statements_match:
        raise UnsupportedExport(
            "An unchanged model did not preserve the original statement sequence."
        )
    if actual != doc.expected:
        raise UnsupportedExport(
            "Native statement comparison failed; source properties or statement order would be lost."
        )
    if functional(restored) != functional(router):
        differing = [
            key
            for key, value in functional(router).items()
            if functional(restored).get(key) != value
        ]
        raise UnsupportedExport(
            "Source export could not reproduce these model changes: "
            + ", ".join(differing)
            + ". Edit their full source definitions rather than accepting omitted settings."
        )
    return ExportResult(
        text,
        True,
        [],
        mode="source-aware",
        preserved_commands=len(adapter.commands),
        rewritten_commands=doc.rewritten,
        verification={
            "semantic_match": True,
            "original_model_unchanged": original_match,
            "original_statements_match": original_statements_match,
            "native_statement_match": True,
            "input_statements": len(adapter.commands),
            "output_statements": len(actual),
        },
    )
