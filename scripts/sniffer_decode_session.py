"""Decode 70575 PCAP using a DPAPI-protected session snapshot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from iara.sniffer.local_secrets import unprotect
from iara.sniffer.handshake import inspect_handshake
from iara.sniffer.profiles import select_profile
from iara.sniffer.replay import replay
from iara.capture_inspector import inspect_file


def _bounded_read(path,limit):
    with path.open('rb') as f:
        data=f.read(limit+1)
    if len(data)>limit:raise ValueError('input_limit')
    return data


def _identity(stat):
    return stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns


def decode(source,destination,protected,flows,flow_index,*,process_exited=False,max_bytes=32*1024*1024,max_packets=50000):
    if type(max_bytes) is not int or not 1024<=max_bytes<=1024**3:raise ValueError('input_limit')
    if type(max_packets) is not int or not 1<=max_packets<=10000000:raise ValueError('input_limit')
    secret=json.loads(unprotect(_bounded_read(protected,65536)))
    profile=select_profile(secret['build'],experimental=True,image_sha256=secret['image_sha256'])
    if profile.layout is None:raise ValueError('unsupported_session_profile')
    connections=json.loads(_bounded_read(flows,65536))
    if type(connections) is not list or type(flow_index) is not int or not 0<=flow_index<len(connections)<=32:
        raise ValueError('invalid_flow_selection')
    flow=connections[flow_index]
    if source.name!=flow['file']:raise ValueError('capture_file_mismatch')
    session=bytes.fromhex(secret['session'])
    independent=None
    with source.open('rb') as f:
        before=_identity(os.fstat(f.fileno()))
        if not 24<=before[2]<=max_bytes:raise ValueError('input_limit')
        pcap_hash=hashlib.file_digest(f,'sha256').hexdigest()
        f.seek(0)
        key,boundaries=inspect_handshake(f,client=flow['client'],server=flow['server'],session=session)
        f.seek(0)
        def validate(partial,records):
            nonlocal independent
            if before!=_identity(os.fstat(f.fileno())) or before!=_identity(source.stat()):
                raise ValueError('capture_changed_during_decode')
            independent=inspect_file(partial)
            if (independent.get('complete') is not True or independent.get('build')!=profile.build or
                    independent.get('records')!=records or independent.get('directions',{}).get('unknown')!=0):
                raise ValueError('independent_container_check_failed')
        result=replay(f,destination,profile=profile,client=flow['client'],server=flow['server'],
                      keys={'client':key,'server':key},encrypted_from=boundaries,validate_output=validate,
                      max_packets=max_packets,max_bytes=max_bytes,process_exited=process_exited)
    with destination.open('rb') as f:pkt_hash=hashlib.file_digest(f,'sha256').hexdigest()
    result.update({'independent_container_check':independent,'handshake_validated':True,
                   'key_source':'Windows_DPAPI_session','contains_private_game_data':True,
                   'pcap_sha256':pcap_hash,'pkt_sha256':pkt_hash})
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','destination','protected','flows'):p.add_argument(name,type=Path)
    p.add_argument('--flow-index',type=int,default=0);a=p.parse_args()
    try:print(json.dumps(decode(a.source,a.destination,a.protected,a.flows,a.flow_index),indent=2))
    except (ValueError,OSError,TypeError,KeyError,IndexError):
        print('{"ok":false,"code":"authenticated_decode_incomplete"}');raise SystemExit(1)
