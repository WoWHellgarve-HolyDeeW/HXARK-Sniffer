"""Capture inventoried endpoints with a protected session snapshot.

CLI diagnostic: arm before connecting, then log out before the duration expires.
The desktop application manages this lifecycle automatically.
"""
import argparse
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.sniffer_capture_start import prepare_owner,run_capture
from scripts.sniffer_session_snapshot import save
from scripts.sniffer_decode_session import decode

RETRYABLE={'session_root_unavailable','session_not_initialized','session_changed_during_read'}


def record(output,previous,wow,seconds=300,*,stop_requested=None):
    from iara.sniffer.updates import safe_store,default_store,update_lock
    # The same inter-process lock protects catalog installation and active capture.
    with update_lock(safe_store(default_store())):
        return _record(output,previous,wow,seconds,stop_requested=stop_requested)


def _record(output,previous,wow,seconds=300,*,stop_requested=None):
    interface,local,servers,owner=prepare_owner(wow,previous)
    build=json.loads(previous.read_text())['build']
    protected=output/'private-session.dpapi'
    state={'session_saved':False,'session_error':None}
    next_attempt=0.0
    def progress(receipt):
        nonlocal next_attempt
        if state['session_saved'] or not receipt['owned_connections']:return
        if time.monotonic()<next_attempt:return
        next_attempt=time.monotonic()+5
        try:
            save(wow,protected)
        except ValueError as exc:
            if str(exc) in RETRYABLE:
                state['session_error']=str(exc)
                return
            raise
        state.update(session_saved=True,session_error=None)
        print('{"session_saved":true,"protected_with":"Windows_DPAPI_current_user"}',flush=True)
    capture=run_capture(output,interface=interface,local=local,servers=servers,owner=owner,
                        seconds=seconds,on_progress=progress,stop_requested=stop_requested,
                        on_ready=lambda:print(json.dumps({'armed':True,'build':build}),flush=True))
    progress(capture)
    result={'build':build,'capture_completed':capture['capture_completed'],**state,
            'uploaded':False,'captures':[],'complete':False}
    if not state['session_saved']:
        result['code']='session_not_captured'
    else:
        flows=output/'private-flows.json'
        for index,flow in enumerate(json.loads(flows.read_text())):
            name=f'world-{index+1:02d}.pkt'
            try:
                receipt=decode(output/flow['file'],output/name,protected,flows,index)
                result['captures'].append({'file':name,'ok':True,'receipt':receipt})
            except (ValueError,OSError,TypeError,KeyError,IndexError):
                result['captures'].append({'file':name,'ok':False,'code':'authenticated_decode_incomplete'})
        result['complete']=bool(result['captures']) and all(v['ok'] for v in result['captures'])
    with (output/'decode-receipt.json').open('x') as f:json.dump(result,f,indent=2)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('output',type=Path);p.add_argument('--previous',required=True,type=Path)
    p.add_argument('--seconds',type=int,default=300)
    p.add_argument('--wow',type=Path,default=Path(r'C:\Program Files (x86)\World of Warcraft\_retail_\Wow.exe'))
    a=p.parse_args()
    try:
        result=record(a.output,a.previous,a.wow,a.seconds)
        print(json.dumps(result,indent=2))
        raise SystemExit(0 if result['complete'] else 1)
    except (ValueError,OSError,TypeError,KeyError,IndexError):
        print('{"ok":false,"code":"local_recording_incomplete"}')
        raise SystemExit(1)
