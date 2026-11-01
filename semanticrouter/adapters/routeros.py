"""Non-executing RouterOS export parser and semantic adapter.

Accepts terse and section-based exports. Selectors are preserved, never executed.
"""
from dataclasses import dataclass, field
from pathlib import Path
import re
from ..model import (Router, Source, Diagnostic, Address, Interface, AddressGroup,
                     FirewallRule, BGPPeer, RouteRule, PPPServer, RadiusServer)
from ..definitions import detect, definition


@dataclass
class Command:
    path: str
    verb: str
    attributes: dict[str, str]
    selector: str
    source: Source
    opaque: bool = False


def tokens(line):
    # RouterOS double quotes, escaped characters, and bracketed selectors.
    out, buf, quoted, depth, i = [], '', False, 0, 0
    while i < len(line):
        c = line[i]
        if c == '\\':
            i += 1
            if i >= len(line):
                raise ValueError('Trailing escape')
            c = line[i]
            if i + 1 < len(line) and re.fullmatch('[0-9a-fA-F]{2}', line[i:i+2]):
                c = chr(int(line[i:i+2], 16)); i += 1
            else:
                c = {'n': '\n', 'r': '\r', 't': '\t'}.get(c, c)
            buf += c
        elif c == '"':
            quoted = not quoted
        elif not quoted and c == '[':
            depth += 1; buf += c
        elif not quoted and c == ']':
            depth -= 1; buf += c
        elif not quoted and depth == 0 and c.isspace():
            if buf: out.append(buf); buf = ''
        else:
            buf += c
        i += 1
    if quoted or depth:
        raise ValueError('Unclosed quote or selector')
    if buf: out.append(buf)
    return out


def parse(text, path='<memory>'):
    section, pending, start = '', '', 0
    for no, physical in enumerate(text.splitlines(), 1):
        if not pending: start = no
        line = pending + physical.strip()
        if line.endswith('\\'):
            pending = line[:-1] + ' '; continue
        pending = ''
        if not line or line.startswith('#'): continue
        ts = tokens(line)
        verb_index = next((i for i, t in enumerate(ts) if t in ('add', 'set', 'remove', 'enable', 'disable')), None)
        if line.startswith('/'):
            if verb_index is None:
                section = '/' + ' '.join(line.strip('/').replace('/', ' ').split())
                if any(x in line for x in (';', '{', '}', '=', '[', ']')):
                    yield Command(section, 'unsupported', {}, '', Source(path, start), True)
                continue
            section = '/' + ' '.join(' '.join(ts[:verb_index]).strip('/').replace('/', ' ').split())
        elif verb_index != 0:
            yield Command(section, 'unsupported', {}, '', Source(path, start), True); continue
        if verb_index is None: continue
        attrs, selector, group, opaque = {}, [], '', False
        for t in ts[verb_index+1:]:
            if t.startswith('[') or '=' not in t:
                selector.append(t)
                continue
            k, v = t.split('=', 1)
            if k.startswith('.'):
                k = group + k
            elif '.' in k:
                group = k.rsplit('.', 1)[0]
            else:
                group = ''
            if k in attrs: opaque = True
            attrs[k] = v
        # Scripts may look like commands; never claim full interpretation.
        if ';' in line and not any(k in attrs for k in ('rule', 'comment')): opaque = True
        yield Command(section, ts[verb_index], attrs, ' '.join(selector), Source(path, start), opaque)
    if pending: raise ValueError(f'{path}:{start}: unfinished continuation')


def enabled(a):
    return a.get('disabled', 'no') != 'yes'


def milliseconds(value):
    m = re.fullmatch(r'([\d.]+)(ms|s)', value or '')
    return int(float(m[1]) * (1000 if m[2] == 's' else 1)) if m else None


def route_rule(c):
    a = c.attributes
    if c.path == '/routing filter':
        known = {'chain','action','prefix','prefix-length','disabled','comment'}
        p = a.get('prefix')
        lo, hi = (int(p.split('/')[1]), 32) if p else (0,32)
        if a.get('prefix-length'):
            parts = a['prefix-length'].split('-'); lo = int(parts[0]); hi = int(parts[-1])
        return RouteRule(a.get('chain',''), a.get('action','unknown'), p, lo, hi, False,
                         enabled(a), set(a) <= known and a.get('action') in ('accept','discard','reject'), c.source)
    s = a.get('rule','').strip().rstrip(';').strip()
    if s in ('accept','reject'):
        return RouteRule(a.get('chain',''), s, enabled=enabled(a), source=c.source)
    # Deliberately narrow grammar. Attribute mutations, jumps and complex expressions stay unknown.
    m = re.fullmatch(r'if\s*\(\s*dst\s+(in|==)\s+([\d./]+)\s*(?:&&\s*dst-len\s*(>|>=|==|<=|<)\s*(\d+))?\s*\)\s*\{\s*(accept|reject)\s*;?\s*\}',s)
    if not m:
        return RouteRule(a.get('chain',''), 'unknown', enabled=enabled(a), supported=False, source=c.source)
    op, p, cmp, n, action = m.groups()
    if '/' not in p: p += '/32'
    lo, hi = 0, 32
    if cmp:
        n = int(n)
        if cmp == '>': lo = n+1
        if cmp == '>=': lo = n
        if cmp == '==': lo = hi = n
        if cmp == '<': hi = n-1
        if cmp == '<=': hi = n
    return RouteRule(a.get('chain',''), action, p, lo, hi, op=='==',enabled(a), True,c.source)


@dataclass
class RouterOSFirewallV4:
    commands: list[Command]

    def to_common(self):
        from ..model import FirewallV4
        f = FirewallV4()
        mapping = {'protocol':'protocol','src-address':'source_network','src-address-list':'source_group',
                   'dst-address':'destination_network','dst-address-list':'destination_group',
                   'dst-port':'destination_ports','src-port':'source_ports',
                   'in-interface':'ingress','out-interface':'egress'}
        for c in self.commands:
            a = c.attributes
            if c.path == '/ip firewall address-list':
                if a.get('list') and a.get('address'):
                    f.groups.append(AddressGroup(a['list'],a['address'],enabled(a),c.source))
            elif c.path == '/ip firewall filter':
                f.rules.append(firewall_rule(c, mapping))
            elif c.path == '/ip firewall connection tracking':
                if a.get('enabled') in ('yes','no'): f.connection_tracking = a['enabled']=='yes'
        return f


def firewall_rule(c, mapping=None):
    mapping = mapping or {'protocol':'protocol','src-address':'source_network','src-address-list':'source_group',
                         'dst-address':'destination_network','dst-address-list':'destination_group',
                         'dst-port':'destination_ports','src-port':'source_ports','in-interface':'ingress','out-interface':'egress'}
    a = c.attributes
    kw = {target:a[k] for k,target in mapping.items() if k in a}
    extra = {k:v for k,v in a.items() if k not in set(mapping)|{'chain','action','disabled','comment'}}
    if c.selector or c.opaque: extra['_unresolved'] = 'yes'
    return FirewallRule(a.get('chain','input'), a.get('action','accept'), enabled=enabled(a), extra=extra,source=c.source, **kw)


@dataclass
class RouterOSBGP:
    commands: list[Command]
    family: str | None
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def to_common(self):
        from ..model import BGP
        b = BGP()
        if not self.family: return b
        d = definition('routeros-' + self.family)
        templates = {c.attributes.get('name',c.selector): c.attributes for c in self.commands if c.path=='/routing bgp template'}
        instances = {c.attributes.get('name',c.selector): c.attributes for c in self.commands if c.path=='/routing bgp instance'}
        def inherit(name, trail=()):
            if name in trail or name not in templates:
                self.diagnostics.append(Diagnostic('bgp-inheritance', 'Unresolved/cyclic BGP template: '+name))
                return {}
            a = templates[name]; merged = {}
            for parent in filter(None,a.get('templates','').split(',')):
                merged.update(inherit(parent,trail+(name,)))
            merged.update(a); return merged
        for c in self.commands:
            if c.path in ('/routing filter rule','/routing filter'):
                b.policies.append(route_rule(c)); continue
            if c.path != d['bgp_path']: continue
            instance = c.attributes.get('instance','default')
            a = dict(instances.get(instance,{}))
            if self.family=='7':
                for t in filter(None,c.attributes.get('templates','default' if 'default' in templates else '').split(',')):
                    a.update(inherit(t))
            a.update(c.attributes)
            kw = {v:a[k] for k,v in d['bgp_fields'].items() if k in a}
            redist = a.get('output.redistribute','').split(',') if a.get('output.redistribute') else []
            if self.family=='6':
                redist = [v for k,v in d['redistribute_flags'].items() if a.get(k)=='yes']
                kw['local_as'] = a.get('as')
                kw['router_id'] = a.get('router-id')
                kw['role'] = ('ibgp' if kw.get('local_as') == kw.get('remote_as') else 'ebgp') if kw.get('local_as') and kw.get('remote_as') else None
            b.peers.append(BGPPeer(c.attributes.get('name','unnamed'),redistribute=redist,enabled=enabled(a),source=c.source,**kw))
        return b


@dataclass
class RouterOSRouter:
    name: str
    text: str = field(repr=False)
    path: str = '<memory>'
    version: str | None = None
    commands: list[Command] = field(init=False,repr=False)

    def __post_init__(self):
        self.commands = list(parse(self.text,self.path))

    @property
    def firewall_v4(self):
        return RouterOSFirewallV4(self.commands)

    @property
    def bgp(self):
        p = detect(self.text,[c.path for c in self.commands], self.version)
        return RouterOSBGP(self.commands,p.family)

    def to_common(self):
        role = re.match(r'[a-z]+', self.name.lower())
        r = Router(self.name,role.group() if role else 'unknown')
        r.platform = detect(self.text,[c.path for c in self.commands],self.version)
        if not r.platform.version:
            r.diagnostics.append(Diagnostic('version-unknown','Exact firmware absent; syntax family is evidence, not an exact version.'))
        r.firewall_v4 = self.firewall_v4.to_common()
        bgp = self.bgp; r.bgp = bgp.to_common(); r.diagnostics.extend(bgp.diagnostics)
        for c in self.commands:
            a,p = c.attributes,c.path
            # All commands must be accounted for by the exporter independently.
            r.unexported.append(c.source)
            if c.opaque or c.verb not in ('add','set'):
                r.diagnostics.append(Diagnostic('unresolved-command','Command was not evaluated.',c.source)); continue
            if c.selector and p not in ('/interface ethernet','/ppp profile','/routing bgp template','/routing bgp instance'):
                r.diagnostics.append(Diagnostic('unresolved-selector','Selector requires device defaults/state.',c.source))
            if p=='/system identity': r.identity = a.get('name')
            elif p=='/ip dns': r.dns = a.get('servers','').split(',') if a.get('servers') else []
            elif p=='/ip address' and 'address' in a:
                addr=a['address']
                if '/' not in addr: addr += '/32'
                r.addresses.append(Address(addr,a.get('interface',''),a.get('network'),enabled(a),c.source))
            elif p in ('/interface bridge','/interface bonding','/interface vlan','/interface ethernet'):
                if a.get('name'):
                    r.interfaces.append(Interface(a['name'],p.split()[-1],enabled(a),a.get('slaves','').split(',') if a.get('slaves') else [],a.get('mode'),a.get('interface'),int(a['vlan-id']) if 'vlan-id' in a else None,a.get('comment',''),c.source))
            elif p=='/snmp':
                r.snmp_enabled = a.get('enabled')=='yes'; r.snmp_location=a.get('location')
            elif p=='/ipv6 firewall filter': r.firewall_v6.append(firewall_rule(c))
            elif p=='/interface pppoe-server server':
                r.ppp_servers.append(PPPServer(a.get('interface',''),int(a['max-mtu']) if 'max-mtu' in a else None,a.get('authentication','').split(','),a.get('default-profile'),enabled(a),c.source))
            elif p=='/ppp profile' and a.get('local-address'):
                name=a.get('name',c.selector)
                if 'find' in name:
                    m=re.search(r'name\s*=\s*([^\s\]]+)',name); name=m[1] if m else name
                r.ppp_local_addresses[name]=a['local-address']
            elif p=='/radius': r.radius.append(RadiusServer(a.get('address',''),a.get('src-address'),milliseconds(a.get('timeout')),enabled(a),c.source))
            elif p=='/routing ospf interface-template' and enabled(a):
                r.ospf_interfaces.extend(filter(None,a.get('interfaces','').split(',')))
        from ..export import mark_import_coverage
        mark_import_coverage(r, self.commands)
        if r.platform.family == '6':
            for chain in {p.chain for p in r.bgp.policies}:
                rules = [p for p in r.bgp.policies if p.chain == chain and p.enabled]
                if not any(p.supported and p.prefix is None and p.action in ('accept', 'reject', 'discard') for p in rules):
                    r.diagnostics.append(Diagnostic('route-policy-fallthrough', 'ROS6 chain requires an explicit terminal action before migration: ' + chain))
        return r


def load(path, version=None):
    p=Path(path)
    return RouterOSRouter(p.stem,p.read_text(),str(p),version).to_common()
