import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from .adapters.routeros import load
from .policy import audit
from .export import export_router, UnsupportedExport


def main(argv=None):
    p=argparse.ArgumentParser(prog='semanticrouter')
    sub=p.add_subparsers(dest='command',required=True)
    i=sub.add_parser('inspect'); i.add_argument('config'); i.add_argument('--source-version')
    a=sub.add_parser('audit'); a.add_argument('directory'); a.add_argument('--policy',required=True); a.add_argument('--output'); a.add_argument('--json',action='store_true')
    e=sub.add_parser('export'); e.add_argument('config'); e.add_argument('--vendor',required=True,choices=['routeros','cisco-ios']); e.add_argument('--version',required=True); e.add_argument('--source-version'); e.add_argument('--allow-partial',action='store_true'); e.add_argument('--output')
    args=p.parse_args(argv)
    try:
        if args.command=='inspect':
            print(json.dumps(load(args.config,args.source_version).to_dict(),indent=2)); return 0
        if args.command=='export':
            result=export_router(load(args.config,args.source_version),args.vendor,args.version,args.allow_partial)
            if args.output: Path(args.output).write_text(result.text)
            else: print(result.text,end='')
            for d in result.diagnostics: print(d,file=sys.stderr)
            return 0 if result.complete else 2
        policy=json.loads(Path(args.policy).read_text())
        routers=[load(Path(args.directory)/(name+'.cfg')) for name in policy['devices']]
        findings=audit(routers,policy)
        summary=dict(Counter(f.severity for f in findings))
        report={'kind':'configuration-only','devices':[{'name':r.name,'platform':r.to_dict()['platform'],'bgp_peers':len(r.bgp.peers),'firewall_rules':len(r.firewall_v4.rules),'unexported_commands':len(r.unexported),'diagnostics':r.to_dict()['diagnostics']} for r in routers],'summary':summary,'findings':[f.to_dict() for f in findings]}
        if args.output: Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
        if args.json: print(json.dumps(report,indent=2))
        else:
            print(f'Loaded {len(routers)} routers. Configuration assertions only. '+str(summary))
            for f in findings:
                location=f' ({f.source.path}:{f.source.line})' if f.source else ''
                print(f'{f.severity:7} {f.device:14} {f.check}: {f.message}{location}')
        return 1 if any(f.severity=='P1' for f in findings) else (2 if any(f.severity=='UNKNOWN' for f in findings) else 0)
    except (OSError,ValueError,KeyError) as exc:
        print(f'semanticrouter: {exc}',file=sys.stderr); return 2


if __name__=='__main__': raise SystemExit(main())
