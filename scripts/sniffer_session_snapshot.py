"""Save a session snapshot protected with current-user DPAPI."""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from iara.sniffer.windows_session import snapshot
from iara.sniffer.local_secrets import protect


def save(wow,destination):
    value=snapshot(wow)
    sealed=protect(json.dumps(value).encode())
    with destination.open('xb') as f:f.write(sealed)
    return {'build':value['build'],'verified_key_slots':len(value['keys']),
            'protected_with':'Windows_DPAPI_current_user','uploaded':False,
            'traffic_authenticated':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('destination',type=Path)
    p.add_argument('--wow',type=Path,default=Path(r'C:\Program Files (x86)\World of Warcraft\_retail_\Wow.exe'))
    a=p.parse_args()
    try:print(json.dumps(save(a.wow,a.destination)))
    except (ValueError,OSError,TypeError,KeyError):
        print('{"ok":false,"code":"session_snapshot_unavailable"}');raise SystemExit(1)
