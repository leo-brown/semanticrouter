"""Capability-checked configuration fragments. No device application code."""
from dataclasses import dataclass, field
import re
from ipaddress import ip_network, ip_address, ip_interface
from .definitions import definition


class UnsupportedExport(ValueError): pass


@dataclass
class ExportResult:
    text: str
    complete: bool
    diagnostics: list[str] = field(default_factory=list)


# Imported commands are exportable only when every field has a semantic mapping.
# Even on one vendor, raw commands are never replayed into another version.
IMPORT_COVERAGE = {
 '/system identity': {'name'}, '/ip dns': {'servers'},
 '/ip address': {'address','network','interface','disabled'},
 '/ip firewall address-list': {'address','list','disabled','comment'},
 '/ip firewall filter': {'chain','action','protocol','src-address','src-address-list','dst-address','dst-address-list','dst-port','src-port','in-interface','out-interface','disabled','comment'},
 '/routing filter': {'chain','action','prefix','prefix-length','disabled','comment'},
 '/routing filter rule': {'chain','rule','disabled','comment'},
 '/routing bgp instance': {'name','as','router-id'},
 '/routing bgp peer': {'name','remote-address','update-source','remote-as','in-filter','out-filter','instance','disabled','comment'},
 '/routing bgp connection': {'name','remote.address','local.address','remote.as','as','router-id','local.role','input.filter','output.filter-chain','output.redistribute','output.default-originate','templates','instance','disabled','comment'},
 '/routing bgp template': {'name','as','router-id','output.redistribute','disabled','templates'},
}


def mark_import_coverage(router, commands):
    router.unexported=[]
    for c in commands:
        attrs=c.attributes
        known=IMPORT_COVERAGE.get(c.path,set())
        if c.path=='/routing bgp instance' and router.platform.family=='6':
            known=known|{'redistribute-connected','redistribute-static','redistribute-ospf','redistribute-other-bgp','redistribute-rip'}
        if c.path=='/routing bgp peer' and attrs.get('update-source'):
            try: ip_network(attrs['update-source'],strict=False)
            except ValueError: known=set() # Interface-based update-source needs address resolution.
        if c.path in ('/routing bgp instance','/routing bgp template') and not router.bgp.peers:
            known=set()  # Unused local BGP definitions have no common-model representation.
        if c.path=='/ip address' and attrs.get('network') and attrs.get('address'):
            addr=attrs['address'].split('/')[0]
            conventional=str(ip_interface(attrs['address']).network.network_address)
            if attrs['network'] not in (addr,conventional): known=set() # Host-route peer semantics not yet portable.
        selector_ok=(c.verb=='add' or c.path in ('/system identity','/ip dns','/routing bgp instance','/routing bgp template')) and (not c.selector or (c.path in ('/routing bgp instance','/routing bgp template') and c.selector=='default'))
        if c.opaque or c.verb not in ('add','set') or not selector_ok or c.path not in IMPORT_COVERAGE or not set(attrs)<=known:
            router.unexported.append(c.source)


def quote(value):
    s=str(value)
    return '"'+s.replace('\\','\\\\').replace('"','\\"').replace('$','\\$').replace('\n','\\n').replace('\r','\\r')+'"'


def command(path,**attrs):
    return path+' add '+' '.join(k+'='+quote(v) for k,v in attrs.items() if v is not None)


def export_router(router,vendor,version,allow_partial=False):
    diagnostics=[]; lines=[]
    def issue(msg): diagnostics.append(msg)
    if vendor=='routeros':
        if not re.fullmatch(r'7\.\d+(?:\.\d+)?',version): raise UnsupportedExport('Choose a concrete stable RouterOS 7 version.')
        parts=tuple(map(int,version.split('.')))
        d=definition('routeros-7')
        minimum=tuple(map(int,d['export_min_version'].split('.')))
        maximum=tuple(map(int,d['export_max_version_exclusive'].split('.')))
        if not (minimum<=parts<maximum): raise UnsupportedExport(d['export_note'])
        if router.identity: lines.append('/system identity set name='+quote(router.identity))
        if router.dns: lines.append('/ip dns set servers='+quote(','.join(router.dns)))
        for a in router.addresses:
            if a.peer and a.peer not in (str(ip_interface(a.address).ip),str(ip_interface(a.address).network.network_address)):
                issue('Host-route peer addressing is not exported: '+a.interface); continue
            lines.append(command('/ip address',address=a.address,interface=a.interface,disabled='no' if a.enabled else 'yes'))
        for g in router.firewall_v4.groups:
            lines.append(command('/ip firewall address-list',address=g.network,list=g.name,disabled='no' if g.enabled else 'yes'))
        for f in router.firewall_v4.rules:
            if f.extra: issue('Unsupported firewall predicates at '+str(f.source)); continue
            if f.action not in ('accept','drop','reject','log','passthrough'): issue('Unsupported firewall action '+f.action); continue
            attrs={'chain':f.chain,'action':f.action,'protocol':f.protocol,'src-address':f.source_network,'src-address-list':f.source_group,'dst-address':f.destination_network,'dst-address-list':f.destination_group,'dst-port':f.destination_ports,'src-port':f.source_ports,'in-interface':f.ingress,'out-interface':f.egress,'disabled':'no' if f.enabled else 'yes'}
            lines.append(command('/ip firewall filter',**attrs))
        for rule in router.bgp.policies:
            if not rule.supported: issue('Unsupported routing policy at '+str(rule.source)); continue
            action='reject' if rule.action=='discard' else rule.action
            expr=action+';'
            if rule.prefix:
                condition='dst '+('==' if rule.exact else 'in')+' '+rule.prefix
                if rule.min_length==rule.max_length: condition+=' && dst-len == '+str(rule.min_length)
                else:
                    if rule.min_length: condition+=' && dst-len >= '+str(rule.min_length)
                    if rule.max_length<32: condition+=' && dst-len <= '+str(rule.max_length)
                expr='if ('+condition+') { '+action+'; }'
            lines.append(command('/routing filter rule',chain=rule.chain,rule=expr,disabled='no' if rule.enabled else 'yes'))
        for p in router.bgp.peers:
            if not p.remote_address or not p.local_as or not p.role: issue('Incomplete BGP peer '+p.name); continue
            attrs={'name':p.name,'remote.address':p.remote_address,'remote.as':p.remote_as,'local.address':p.local_address,'local.role':p.role,'as':p.local_as,'router-id':p.router_id,'input.filter':p.import_policy,'output.filter-chain':p.export_policy,'output.redistribute':','.join(p.redistribute) or None,'output.default-originate':p.default_originate,'disabled':'no' if p.enabled else 'yes'}
            lines.append(command('/routing bgp connection',**attrs))
        # These scalar settings have no individual source field; their import
        # coverage has already been checked, and they are emitted above.
    elif vendor=='cisco-ios':
        if not re.fullmatch(r'15(?:\.\d+)*',version): raise UnsupportedExport('Only Cisco IOS 15.x ACL artifact export is supported.')
        if router.identity:
            if not re.fullmatch('[A-Za-z0-9_.-]+',router.identity): issue('Invalid IOS hostname')
            else: lines.append('hostname '+router.identity)
        if router.dns:
            try:
                servers=[str(ip_address(server)) for server in router.dns]
                lines.append('ip name-server '+' '.join(servers))
            except ValueError:
                issue('IOS DNS servers must be IP literals.')
        # No implicit device-wide attachment: RouterOS input has no direct IOS ACL equivalent.
        lines.extend(['! IPv4 input ACL artifact; choose control-plane/interface attachment explicitly.','ip access-list extended SEMANTICROUTER-INPUT'])
        def endpoint(network,group):
            if group:
                if group.startswith('!'): raise UnsupportedExport('Negated address groups unsupported in IOS ACLs.')
                gs=[g.network for g in router.firewall_v4.groups if g.enabled and g.name==group]
                if not gs: raise UnsupportedExport('Missing address group '+group)
                return [address(x) for x in gs]
            return [address(network)]
        def address(value):
            if not value: return 'any'
            net=ip_network(value,strict=False)
            if net.version!=4: raise UnsupportedExport('IPv4 ACL requires IPv4 networks')
            if net.prefixlen==0: return 'any'
            return 'host '+str(net.network_address) if net.prefixlen==32 else str(net.network_address)+' '+str(net.hostmask)
        for f in router.firewall_v4.rules:
            if f.chain!='input': issue('IOS renderer only supports input ACL rules'); continue
            if not f.enabled: continue
            if (f.source_network and f.source_group) or (f.destination_network and f.destination_group):
                issue('Combined address and group predicates need intersection support for IOS.'); continue
            if f.extra or f.ingress or f.egress or f.source_ports or f.action not in ('accept','drop'):
                issue('Unsupported IOS firewall rule at '+str(f.source)); continue
            if f.protocol not in (None,'tcp','udp','icmp','ospf'):
                issue('Unsupported IOS protocol'); continue
            if f.destination_ports and (f.protocol not in ('tcp','udp') or not f.destination_ports.isdigit()):
                issue('IOS supports one destination port per rule in this renderer'); continue
            try:
                sources=endpoint(f.source_network,f.source_group); destinations=endpoint(f.destination_network,f.destination_group)
            except (UnsupportedExport,ValueError) as exc: issue(str(exc)); continue
            for src in sources:
                for dst in destinations:
                    line=' '+('permit' if f.action=='accept' else 'deny')+' '+(f.protocol or 'ip')+' '+src+' '+dst
                    if f.destination_ports: line+=' eq '+f.destination_ports
                    lines.append(line)
        if not any(f.enabled and f.chain=='input' and f.action in ('accept','drop') and f.unconditional for f in router.firewall_v4.rules):
            lines.append(' permit ip any any')  # Preserve RouterOS input fall-through acceptance.
        lines.append('exit')
        if router.bgp.peers or router.bgp.policies or router.addresses: issue('IOS BGP, route policies and interface addressing are not supported yet.')
    else: raise UnsupportedExport('Unknown target vendor '+vendor)
    if router.unexported:
        issue(f'{len(router.unexported)} source commands contain unmapped features/properties; full-device export is blocked.')
    if router.firewall_v4.connection_tracking is not None: issue('Connection tracking setting is not exported.')
    if router.interfaces or router.firewall_v6 or router.ppp_servers or router.radius or router.snmp_enabled is not None:
        issue('Interfaces, IPv6, PPP, RADIUS and SNMP are inspection-only in this release.')
    if router.diagnostics and any(d.code not in ('version-unknown',) for d in router.diagnostics): issue('Import has unresolved semantic diagnostics.')
    if any(not x.supported for x in router.bgp.policies): issue('Unresolved route-policy semantics.')
    # A manually constructed model can contain features without source provenance.
    if router.ospf_interfaces or router.ppp_local_addresses: issue('OSPF/PPP profile export unsupported.')
    complete=not diagnostics
    if not complete and not allow_partial: raise UnsupportedExport('\n'.join(diagnostics))
    header='#' if vendor=='routeros' else '!'
    banner=f'{header} SemanticRouter: '+('complete supported model' if complete else 'PARTIAL CONFIGURATION — omitted features; review diagnostics')
    return ExportResult(banner+'\n'+'\n'.join(lines)+'\n',complete,diagnostics)
