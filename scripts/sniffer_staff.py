"""HXARK Sniffer desktop and command-line entry point."""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from iara.sniffer.trust import PUBLIC_KEY,CATALOG_URL,APP_VERSION
from iara.sniffer.updates import apply,fetch,default_store,read_bounded
from iara.sniffer.maintenance import inspect_build
from scripts.sniffer_record import record
from scripts.sniffer_decode_session import decode

DEFAULT_WOW=Path(r'C:\Program Files (x86)\World of Warcraft\_retail_\Wow.exe')


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--result',type=Path,help='Write a JSON result to a new file.')
    sub=p.add_subparsers(dest='command')
    sub.add_parser('version')
    sub.add_parser('ui-check',help='Check UI startup without starting capture.')
    sub.add_parser('interfaces-check',help='List the number of usable capture addresses.')
    probe=sub.add_parser('capture-check',help='Run a four-second localhost capture test.')
    probe.add_argument('output',type=Path)
    auto=sub.add_parser('auto-check',help='Test automatic capture with localhost traffic.')
    auto.add_argument('output',type=Path)
    auto.add_argument('--initial-auth',action='store_true',help='Test initial-login framing.')
    auto.add_argument('--changed-address',action='store_true',help='Test an address change after capture is armed.')
    d=sub.add_parser('diagnose');d.add_argument('--wow',type=Path,default=DEFAULT_WOW)
    u=sub.add_parser('update');u.add_argument('--catalog',type=Path);u.add_argument('--store',type=Path,default=default_store())
    r=sub.add_parser('record');r.add_argument('output',type=Path);r.add_argument('--previous',type=Path,required=True)
    r.add_argument('--wow',type=Path,default=DEFAULT_WOW);r.add_argument('--seconds',type=int,default=600)
    d=sub.add_parser('decode',help='Decode a saved capture.')
    for name in ('source','destination','session','flows'):d.add_argument(name,type=Path)
    d.add_argument('--flow-index',type=int,default=0)
    a=p.parse_args(argv)
    try:
        if a.command=='version':result={'application':'HXARK Sniffer','version':APP_VERSION,'channel':'beta'}
        elif a.command=='interfaces-check':
            from iara.sniffer.automatic import capture_adapters
            result={'capture_addresses':len(capture_adapters()),'capture_started':False}
        elif a.command=='ui-check':
            import tkinter
            from iara.sniffer.desktop import start
            try:result=start(smoke_test=True)
            except tkinter.TclError:raise ValueError('ui_unavailable') from None
        elif a.command=='diagnose':result=inspect_build(a.wow)
        elif a.command=='capture-check':
            from scripts.sniffer_start_loopback_probe import run
            result=run(a.output)
        elif a.command=='auto-check':
            from scripts.sniffer_auto_probe import run
            result=run(a.output,initial_auth=a.initial_auth,changed_address=a.changed_address)
        elif a.command=='update':result=apply(read_bounded(a.catalog) if a.catalog else fetch(CATALOG_URL),a.store,PUBLIC_KEY)
        elif a.command=='record':result=record(a.output,a.previous,a.wow,a.seconds)
        elif a.command=='decode':result=decode(a.source,a.destination,a.session,a.flows,a.flow_index)
        else:
            from iara.sniffer.desktop import start
            start();return 0
        emit(result,a.result)
        return 1 if a.command=='record' and result.get('complete') is not True else 0
    except (ValueError,OSError,KeyError,TypeError) as exc:
        safe={'unsupported_build','client_fingerprint_mismatch','catalog_expired','catalog_rollback',
              'invalid_catalog_signature','engine_update_required','update_in_progress'}
        code=str(exc) if type(exc) is ValueError and str(exc) in safe else 'operation_unavailable'
        emit({'ok':False,'code':code},None);return 1


def emit(result,path):
    raw=json.dumps(result,indent=2)
    if path is not None:
        with path.open('x',encoding='utf-8') as f:f.write(raw)
    if sys.stdout is not None:print(raw)


if __name__=='__main__':raise SystemExit(main())
