"""Resolve RouterOS BGP inheritance and translate the supported filter grammar.

Firmware definitions supply property mappings. Instance defaults, inherited
templates and connection overrides are applied in that order. Expressions outside
the supported route-policy grammar remain explicitly unknown."""

import re
from dataclasses import dataclass, field

from ...definitions import definition
from ...model import BGP, BGPPeer, Diagnostic, RouteRule
from .parser import Command
from .values import enabled


def route_rule(c):
    """Translate one v6 field-based or narrowly supported v7 expression-based rule.

    Only terminal accept/reject and simple destination/length conditions are proved.
    Attribute mutations, jumps and complex boolean expressions remain unsupported;
    a matching prefix string inside them is not evidence of an accept policy."""
    a = c.attributes
    if c.path == "/routing filter":
        known = {"chain", "action", "prefix", "prefix-length", "disabled", "comment"}
        p = a.get("prefix")
        lo, hi = (int(p.split("/")[1]), 32) if p else (0, 32)
        if a.get("prefix-length"):
            parts = a["prefix-length"].split("-")
            lo = int(parts[0])
            hi = int(parts[-1])
        return RouteRule(
            a.get("chain", ""),
            a.get("action", "unknown"),
            p,
            lo,
            hi,
            False,
            enabled(a),
            set(a) <= known and a.get("action") in ("accept", "discard", "reject"),
            c.source,
        )
    s = a.get("rule", "").strip().rstrip(";").strip()
    if s in ("accept", "reject"):
        return RouteRule(a.get("chain", ""), s, enabled=enabled(a), source=c.source)
    # Deliberately narrow grammar. Attribute mutations, jumps and complex expressions stay unknown.
    m = re.fullmatch(
        r"if\s*\(\s*dst\s+(in|==)\s+([\d./]+)\s*(?:&&\s*dst-len\s*(>|>=|==|<=|<)\s*(\d+))?\s*\)\s*\{\s*(accept|reject)\s*;?\s*\}",
        s,
    )
    if not m:
        return RouteRule(
            a.get("chain", ""),
            "unknown",
            enabled=enabled(a),
            supported=False,
            source=c.source,
        )
    op, p, cmp, n, action = m.groups()
    if "/" not in p:
        p += "/32"
    lo, hi = 0, 32
    if cmp:
        n = int(n)
        if cmp == ">":
            lo = n + 1
        if cmp == ">=":
            lo = n
        if cmp == "==":
            lo = hi = n
        if cmp == "<":
            hi = n - 1
        if cmp == "<=":
            hi = n
    return RouteRule(
        a.get("chain", ""), action, p, lo, hi, op == "==", enabled(a), True, c.source
    )


@dataclass
class RouterOSBGP:
    """BGP adapter carrying the source syntax family and inheritance diagnostics."""

    commands: list[Command]
    family: str | None
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def to_common(self):
        """Resolve instance/template/connection precedence and preserve policy order.

        A missing or cyclic template emits a diagnostic. ROS6 redistribution flags are
        normalized to route-class names; they must not be mistaken for route filters."""
        b = BGP()
        if not self.family:
            return b
        d = definition("routeros-" + self.family)
        templates = {
            c.attributes.get("name", c.selector): c.attributes
            for c in self.commands
            if c.path == "/routing bgp template"
        }
        instances = {
            c.attributes.get("name", c.selector): c.attributes
            for c in self.commands
            if c.path == "/routing bgp instance"
        }

        def inherit(name, trail=()):
            """Merge a template ancestry in parent-first order, detecting cycles and missing names."""
            if name in trail or name not in templates:
                self.diagnostics.append(
                    Diagnostic(
                        "bgp-inheritance", "Unresolved/cyclic BGP template: " + name
                    )
                )
                return {}
            a = templates[name]
            merged = {}
            for parent in filter(None, a.get("templates", "").split(",")):
                merged.update(inherit(parent, trail + (name,)))
            merged.update(a)
            return merged

        for c in self.commands:
            if c.path in ("/routing filter rule", "/routing filter"):
                b.policies.append(route_rule(c))
                continue
            if c.path != d["bgp_path"]:
                continue
            instance = c.attributes.get("instance", "default")
            a = dict(instances.get(instance, {}))
            if self.family == "7":
                for t in filter(
                    None,
                    c.attributes.get(
                        "templates", "default" if "default" in templates else ""
                    ).split(","),
                ):
                    a.update(inherit(t))
            a.update(c.attributes)
            kw = {v: a[k] for k, v in d["bgp_fields"].items() if k in a}
            redist = (
                a.get("output.redistribute", "").split(",")
                if a.get("output.redistribute")
                else []
            )
            if self.family == "6":
                redist = [
                    v for k, v in d["redistribute_flags"].items() if a.get(k) == "yes"
                ]
                kw["local_as"] = a.get("as")
                kw["router_id"] = a.get("router-id")
                kw["role"] = (
                    ("ibgp" if kw.get("local_as") == kw.get("remote_as") else "ebgp")
                    if kw.get("local_as") and kw.get("remote_as")
                    else None
                )
            b.peers.append(
                BGPPeer(
                    c.attributes.get("name", "unnamed"),
                    redistribute=redist,
                    enabled=enabled(a),
                    source=c.source,
                    **kw,
                )
            )
        return b
