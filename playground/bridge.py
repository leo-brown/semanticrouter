"""Browser transport: JSON in, JSON out; the same deterministic Python engine."""
import json
from dataclasses import asdict
from ipaddress import ip_address, ip_network
from semanticrouter.adapters.routeros import RouterOSRouter
from semanticrouter.serialization import router_from_dict
from semanticrouter.policy import audit, input_decision, route_decision
from semanticrouter.export import export_router, UnsupportedExport


def handle(request_json):
    try:
        request = json.loads(request_json)
        action = request['action']
        if action == 'import':
            router = RouterOSRouter(request['name'], request['text'], path=request['name']+'.cfg', version=request.get('version') or None).to_common()
            return json.dumps({'ok': True, 'router': router.to_dict()})
        routers = [router_from_dict(value) for value in request['routers']]
        if action == 'audit':
            policy = request['policy']
            allowed = {'devices','snmp_pollers','legacy_snmp_pollers','borders','public_prefixes'}
            if not isinstance(policy,dict) or set(policy)-allowed:
                raise ValueError('Policy must be an object containing only supported policy fields')
            for key, values in policy.items():
                if not isinstance(values,list) or any(not isinstance(value,str) for value in values):
                    raise ValueError('Policy '+key+' must be an array of strings')
                if key in ('snmp_pollers','legacy_snmp_pollers'):
                    if any(ip_address(value).version!=4 for value in values):
                        raise ValueError('SNMP pollers must be IPv4 addresses')
                if key=='public_prefixes':
                    if any(ip_network(value).version!=4 or ip_network(value).prefixlen!=24 for value in values):
                        raise ValueError('Customer-prefix proof currently supports IPv4 /24 aggregates')
            findings = audit(routers, policy)
            return json.dumps({'ok': True, 'findings': [asdict(f) for f in findings]})
        selected = next(r for r in routers if r.name == request['selected'])
        if action == 'probe':
            if request['kind'] == 'firewall':
                result = input_decision(selected, request['source'], request['protocol'], int(request['port']))
            else:
                result = route_decision(selected, request['chain'], request['prefix'])
            return json.dumps({'ok': True, 'verdict': result})
        if action == 'export':
            result = export_router(selected, request['vendor'], request['version'], request.get('partial', False))
            return json.dumps({'ok': True, **asdict(result)})
        raise ValueError('Unknown operation')
    except (ValueError, KeyError, TypeError, StopIteration) as exc:
        return json.dumps({'ok': False, 'error': str(exc) or 'Selected router is missing'})
