"""Configuration assertions over common objects. No device connections or probes."""
from dataclasses import dataclass, asdict
from ipaddress import ip_address, ip_interface, ip_network
from .model import Source


@dataclass
class Finding:
    device: str
    check: str
    severity: str
    message: str
    source: Source | None = None

    def to_dict(self): return asdict(self)


def network_contains(network, address):
    try:
        if network.startswith('!'): return not network_contains(network[1:],address)
        return ip_address(address.split('/')[0]) in ip_network(network,strict=False)
    except ValueError: return None


def in_group(router, name, address):
    negate=name.startswith('!'); name=name.lstrip('!')
    matches=[network_contains(g.network,address) for g in router.firewall_v4.groups if g.enabled and g.name==name]
    result=True if True in matches else (None if None in matches else False)
    return not result if negate and result is not None else result


def port_contains(spec,port):
    if not spec: return True
    try:
        return any(int(p.split('-')[0])<=port<=int(p.split('-')[-1]) for p in spec.split(','))
    except ValueError: return None


def input_decision(router, source, protocol='udp', port=161):
    """First-match evaluation, returning accept/drop/unknown (unknown is never pass).

    Unknown predicates fork both match and no-match paths; equal outcomes converge.
    """
    outcomes=set()
    for rule in router.firewall_v4.rules:
        if not rule.enabled or rule.chain!='input': continue
        tests=[rule.protocol in (None,protocol, '17' if protocol=='udp' else '6'),
               port_contains(rule.destination_ports,port)]
        if rule.source_network: tests.append(network_contains(rule.source_network,source))
        if rule.source_group: tests.append(in_group(router,rule.source_group,source))
        if any(x is False for x in tests): continue
        uncertain=any(x is None for x in tests) or any((rule.ingress,rule.egress,rule.destination_network,rule.destination_group,rule.source_ports,rule.extra))
        if rule.action in ('accept','drop','reject'):
            outcomes.add('drop' if rule.action=='reject' else rule.action)
            if not uncertain: return next(iter(outcomes)) if len(outcomes)==1 else 'unknown'
        elif rule.action in ('log','passthrough'): continue
        else: outcomes.add('unknown')
    outcomes.add('accept')  # RouterOS input fall-through accepts.
    return next(iter(outcomes)) if len(outcomes)==1 else 'unknown'


def route_decision(router, chain, prefix):
    """Small supported route-policy grammar; unknown rules block proof."""
    route=ip_network(prefix,strict=False)
    rules=[x for x in router.bgp.policies if x.chain==chain and x.enabled]
    if not chain or not rules: return 'unknown'
    for r in rules:
        if not r.supported: return 'unknown'
        if r.prefix:
            net=ip_network(r.prefix,strict=False)
            if not (route==net if r.exact else route.subnet_of(net)): continue
        if r.min_length<=route.prefixlen<=r.max_length:
            return 'reject' if r.action=='discard' else r.action
    return 'accept' if router.platform.family=='6' else 'reject'


def default_only(router,chain):
    """Prove every accepted route in a simple ordered chain is exactly the default."""
    rules=[x for x in router.bgp.policies if x.chain==chain and x.enabled]
    if not rules or route_decision(router,chain,'0.0.0.0/0')!='accept': return False
    for r in rules:
        if not r.supported: return None
        if r.action=='accept' and not (r.prefix=='0.0.0.0/0' and (r.exact or r.max_length==0)):
            return False
        if r.prefix is None and r.action in ('reject','discard'): return True
    return router.platform.family!='6'  # RouterOS 6 chain fall-through accepts.


def audit(routers, policy):
    findings=[]
    def add(r,check,severity,message,source=None):
        findings.append(Finding(r.name,check,severity,message,source))
    by_name={r.name:r for r in routers}
    public=policy.get('public_prefixes',[])
    borders=policy.get('borders',[])
    for r in routers:
        active=[x for x in r.firewall_v4.rules if x.chain=='input' and x.enabled]
        if not active or not (active[-1].action in ('drop','reject') and active[-1].unconditional):
            add(r,'firewall.input-final-drop','P1','Input policy must end with an enabled unconditional drop/reject.')
        for poller in policy.get('snmp_pollers',[]):
            result=input_decision(r,poller)
            if result!='accept': add(r,'snmp.poller','P1' if result=='drop' else 'UNKNOWN',f'UDP/161 from {poller}: {result}.')
        # A list entry alone is not proof: inspect every potentially SNMP-capable accept.
        for rule in active:
            if rule.action!='accept' or rule.protocol not in (None,'udp','17') or port_contains(rule.destination_ports,161) is False: continue
            if rule.ingress: continue  # Explicit interface-scoped management access.
            source_scoped=bool(rule.source_network or rule.source_group)
            if rule.source_network in ('0.0.0.0/0','!255.255.255.255/32'): source_scoped=False
            if rule.source_group and any(g.enabled and g.name==rule.source_group and g.network=='0.0.0.0/0' for g in r.firewall_v4.groups): source_scoped=False
            if source_scoped: continue
            add(r,'snmp.unrestricted','P1' if not rule.extra else 'UNKNOWN','Potential SNMP accept without a source restriction.',rule.source)
        for g in r.firewall_v4.groups:
            if g.enabled and g.name=='snmp' and g.network.split('/')[0] in policy.get('legacy_snmp_pollers',[]):
                add(r,'snmp.legacy-source','P2','Legacy monitoring source '+g.network,g.source)
            if g.enabled and g.name=='snmp' and g.network not in policy.get('snmp_pollers',[]):
                add(r,'snmp.extra-source','P2','SNMP list contains a source outside canonical pollers: '+g.network,g.source)
        if r.snmp_enabled and not r.snmp_location: add(r,'snmp.location','P2','Enabled SNMP has no explicit location.')
        if r.platform.family=='6': add(r,'firmware.family','P1','RouterOS 6 is prohibited by estate policy.')
        if not r.platform.version: add(r,'firmware.exact-version','UNKNOWN',f'Exact firmware not exported; inferred family={r.platform.family or "unknown"}, hardware={r.platform.hardware or "unknown"}.')
        if r.identity!=r.name and not (r.identity or '').startswith(r.name+'.'):
            add(r,'identity','P2',f'Configured identity {r.identity!r} differs from inventory name.')
        for interface in r.interfaces:
            if interface.kind=='bonding' and interface.mode!='802.3ad': add(r,'bond.mode','P1','Bond '+interface.name+' must explicitly use 802.3ad.',interface.source)
            if not interface.enabled and any(x in interface.name.lower() for x in ('border','bng','bond','uplink')):
                if not any(x in interface.comment.lower() for x in ('staged','spare','retired')):
                    add(r,'uplink.disabled','P2','Disabled production-looking uplink '+interface.name,interface.source)
        if r.role not in ('bng','border','edge','core'): continue
        if r.dns!=['8.8.8.8','1.1.1.1']: add(r,'dns','P2','Expected DNS servers 8.8.8.8,1.1.1.1.')
        loops=[a for a in r.addresses if a.enabled and 'loopback' in a.interface and ip_interface(a.address).network.prefixlen==32 and int(ip_address('193.16.0.1'))<=int(ip_interface(a.address).ip)<=int(ip_address('193.16.0.15'))]
        if not loops: add(r,'loopback','P1','Missing active infrastructure loopback /32.')
        if r.role!='bng': continue
        loop=str(ip_interface(loops[0].address).ip) if loops else None
        if r.firewall_v4.connection_tracking is not False: add(r,'bng.conntrack','P1','Connection tracking must explicitly be disabled.')
        servers=[s for s in r.ppp_servers if s.enabled]
        if not servers: add(r,'bng.pppoe','P1','No active PPPoE server.')
        for s in servers:
            if s.mtu!=1500 or s.interface!='vlan101-ppp' or set(s.authentication)!={'pap','chap'} or s.profile!='ppp':
                add(r,'bng.pppoe','P1','Expected vlan101-ppp, MTU 1500, pap/chap and profile ppp.',s.source)
        if not loop or r.ppp_local_addresses.get('ppp')!=loop: add(r,'bng.ppp-source','P1','PPP local address must equal loopback.')
        radius=[s for s in r.radius if s.enabled]
        if len(radius)!=2: add(r,'bng.radius-count','P1','Expected two active RADIUS servers.')
        for idx,s in enumerate(radius):
            expected=500 if idx==0 else 2000
            if s.source_address!=loop or s.timeout_ms!=expected: add(r,'bng.radius','P1',f'RADIUS {s.address}: expected loopback source and timeout {expected}ms.',s.source)
        if not any(i.enabled and any(x in i.name.lower() for x in ('switch','sw-','sw1','sw2')) for i in r.interfaces):
            add(r,'bng.distribution','P1','Missing active distribution-facing uplink.')
        for border_name in borders:
            border=by_name.get(border_name)
            if not border:
                add(r,'bng.mesh','UNKNOWN','Border not loaded: '+border_name); continue
            local_ips={str(ip_interface(a.address).ip) for a in r.addresses if a.enabled}
            remote_ips={str(ip_interface(a.address).ip) for a in border.addresses if a.enabled}
            peers=[p for p in r.bgp.peers if p.enabled and p.remote_address and p.remote_address.split('/')[0] in remote_ips]
            if not peers:
                add(r,'bng.mesh','P1','No active BGP session to '+border_name); continue
            for peer in peers:
                if set(peer.redistribute)!={'connected','vpn'}: add(r,'bng.redistribute','P1','Peer '+peer.name+' must redistribute connected,vpn.',peer.source)
                if peer.local_address not in local_ips: add(r,'bng.mesh-local-address','P1','BGP local address is not configured/enabled.',peer.source)
                reciprocals=[p for p in border.bgp.peers if p.enabled and p.remote_address and p.remote_address.split('/')[0]==peer.local_address and p.local_address==peer.remote_address.split('/')[0]]
                if not reciprocals: add(r,'bng.mesh-reciprocal','P1','No matching enabled reciprocal session on '+border_name,peer.source)
                if not any(a.enabled and border_name.lower() in a.interface.lower() for a in r.addresses):
                    add(r,'bng.mesh-transit','P1','No active addressed transit towards '+border_name)
                for a in r.addresses:
                    if not a.enabled or border_name.lower() not in a.interface.lower(): continue
                    if a.interface not in r.ospf_interfaces: add(r,'bng.mesh-ospf','P1','No active OSPF template on '+a.interface,a.source)
                    if not any(f.enabled and f.chain=='input' and f.action=='accept' and f.protocol=='ospf' and f.ingress==a.interface for f in r.firewall_v4.rules):
                        add(r,'bng.mesh-ospf-firewall','P1','No explicit OSPF input allow on '+a.interface,a.source)
                for aggregate in public:
                    net=ip_network(aggregate)
                    # Exhaustive for estate /24s: every /25 through /32 (510 routes).
                    if net.prefixlen != 24:
                        add(r,'bng.customer-export','UNKNOWN','Public prefix proof currently requires /24 aggregates.'); continue
                    probes=[str(sub) for length in range(25,33) for sub in net.subnets(new_prefix=length)]
                    decisions=[route_decision(r,peer.export_policy,p) for p in probes]
                    if any(d!='accept' for d in decisions): add(r,'bng.customer-export','UNKNOWN' if 'unknown' in decisions else 'P1',f'{peer.name}: customer more-specific checks fail for {aggregate}.',peer.source)
                    for reciprocal in reciprocals:
                        results=[route_decision(border,reciprocal.import_policy,p) for p in probes]
                        if any(d!='accept' for d in results): add(border,'border.customer-import','UNKNOWN' if 'unknown' in results else 'P1',f'{reciprocal.name}: customer more-specific checks fail for {aggregate}.',reciprocal.source)
                for reciprocal in reciprocals:
                    result=default_only(border,reciprocal.export_policy)
                    if result is not True: add(border,'border.default-only','UNKNOWN' if result is None else 'P1','BNG-facing output must accept only default: '+reciprocal.name,reciprocal.source)
    return findings
