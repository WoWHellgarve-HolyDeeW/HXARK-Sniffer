"""Capture established WoW connections.

This diagnostic cannot recover a handshake missed before capture started.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from iara.sniffer.profiles import select_profile
from iara.sniffer.capture_status import capture_summary


def inventory(wow):
    from iara.sniffer.windows_inventory import inventory as native_inventory
    return native_inventory(wow)


def filters(info):
    """Build a filter from the current process-owned four-tuples."""
    grouped={}
    rows=info.get('connections')
    if type(rows) is not list or not 1<=len(rows)<=32:raise ValueError('no_bounded_game_connections')
    for row in rows:
        interface=row['interface']
        if type(interface) is not str or not re.fullmatch(r'\\Device\\NPF_\{[0-9a-fA-F-]{36}\}',interface):
            raise ValueError('invalid_capture_interface')
        c,s=row['client'],row['server']
        for endpoint in (c,s):
            if type(endpoint) is not list or len(endpoint)!=2 or type(endpoint[1]) is not int or not 1<=endpoint[1]<=65535:
                raise ValueError('invalid_endpoint')
        client=str(ipaddress.IPv4Address(c[0]));server=str(ipaddress.IPv4Address(s[0]))
        if server in ('0.0.0.0','255.255.255.255'):raise ValueError('invalid_remote')
        pair=f'((src host {client} and src port {c[1]} and dst host {server} and dst port {s[1]}) or (src host {server} and src port {s[1]} and dst host {client} and dst port {c[1]}))'
        grouped.setdefault(interface,[]).append(pair)
    if len(grouped)!=1:raise ValueError('multiple_interfaces_require_selection')
    interface,values=next(iter(grouped.items()))
    return interface,'tcp and ('+' or '.join(values)+')'


def capture(wow,output,dumpcap,seconds):
    if type(seconds) is not int or not 5<=seconds<=120:raise ValueError('invalid_duration')
    info=inventory(wow)
    select_profile(info['build'],experimental=True,image_sha256=info['sha256'])
    interface,rule=filters(info)
    output.mkdir(parents=True,exist_ok=False)
    (output/'private-connections.json').write_text(json.dumps(info,indent=2),encoding='utf-8')
    destination=output/'wow-passive.pcap'
    argv=[str(dumpcap),'-i',interface,'-p','-P','-s','262144','-f',rule,
          '-a',f'duration:{seconds}','-a','filesize:65536','-c','100000','-w',str(destination),'-q']
    receipt={'capture_completed':False,'decoded':False,'build':info['build'],
             'scope':'current_exact_wow_non_loopback_tcp_connections','duration_limit_seconds':seconds,
             'excluded_loopback_connections':info.get('excluded_loopback_connections',0),
             'byte_limit':67108864,'contents_uploaded':False,'process_memory_read':False,
             'limitation':'Existing connections may lack their initial handshake; new connections are not included.'}
    receipt_path=output/'receipt.json'
    receipt_path.write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    try:
        with (output/'private-dumpcap.log').open('xb') as log:
            process=subprocess.Popen(argv,stdout=log,stderr=log,creationflags=0x08000000)
            try:
                code=process.wait(timeout=seconds+15)
                receipt['capture_exit_code']=code
                receipt['capture_process_completed']=code==0
                if code==0:
                    with destination.open('rb') as source:
                        diagnostic=capture_summary(source,info['connections'])
                    (output/'diagnostic.json').write_text(json.dumps(diagnostic,indent=2),encoding='utf-8')
                    receipt['capture_completed']=True
                    receipt['captured_packets']=diagnostic['packets']
                    receipt['connections_observed']=diagnostic['connections_observed']
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=3)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
    finally:
        receipt_path.write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    return receipt


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('output',type=Path)
    p.add_argument('--wow',type=Path,default=Path(r'C:\Program Files (x86)\World of Warcraft\_retail_\Wow.exe'))
    p.add_argument('--dumpcap',type=Path,default=Path(r'C:\Program Files\Wireshark\dumpcap.exe'))
    p.add_argument('--seconds',type=int,default=20);a=p.parse_args()
    try:
        result=capture(a.wow,a.output,a.dumpcap,a.seconds)
        print(json.dumps(result))
        if not result['capture_completed']:raise SystemExit(1)
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        safe={'windows_required','wow_process_not_unique_or_not_running','unsupported_build',
              'client_fingerprint_mismatch','tcp_inventory_unavailable','tcp_inventory_unstable',
              'adapter_inventory_unavailable','game_adapter_unavailable','game_process_changed',
              'no_bounded_game_connections','multiple_interfaces_require_selection',
              'unexpected_connection','truncated_pcap','truncated_or_invalid_record'}
        code=str(exc) if type(exc) is ValueError and str(exc) in safe else 'capture_unavailable'
        print(json.dumps({'ok':False,'code':code,'decoded':False}));raise SystemExit(1)
