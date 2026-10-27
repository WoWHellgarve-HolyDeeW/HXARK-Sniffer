"""Arm capture before login and persist process-owned TCP flows.

Pending packets are held in a bounded buffer until Windows confirms ownership.
"""
import argparse
from dataclasses import replace
import json
from pathlib import Path
import queue
import re
import struct
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from iara.sniffer.capture_gate import CaptureGate
from iara.sniffer.pcap import _read, decode_tcp
from iara.sniffer.windows_inventory import find_process, tcp_rows, adapter_addresses, fixed_version
from iara.sniffer.profiles import select_profile


def run_capture(output, *, interface, local, servers, owner, seconds=300,
                dumpcap=None, on_ready=None, on_progress=None, stop_requested=None,
                server_port=None, interface_scope=False, max_bytes=32*1024*1024, max_packets=50000):
    """owner() returns confirmed tuples, or [] while waiting for the process.

    Callback errors abort capture instead of being treated as an empty table.
    """
    if type(seconds) is not int or not 3 <= seconds <= 43200:
        raise ValueError('invalid_duration')
    if type(max_bytes) is not int or not 1024 <= max_bytes <= 1024**3:
        raise ValueError('invalid_capture_limit')
    if type(max_packets) is not int or not 1 <= max_packets <= 10000000:
        raise ValueError('invalid_packet_limit')
    if not re.fullmatch(r'\\Device\\NPF_(?:\{[0-9a-fA-F-]{36}\}|Loopback)', interface):
        raise ValueError('invalid_interface')
    gate = CaptureGate(None if interface_scope else local, servers, server_port=server_port,
                       interface_scope=interface_scope)
    if dumpcap is None:
        from iara.sniffer.prerequisites import find_dumpcap
        dumpcap = find_dumpcap()
    predicates = [f'(host {a} and port {p})' for a, p in sorted(gate.servers)]
    rule = ('ip and tcp' if interface_scope else f'tcp and host {gate.local}') + ' and (' + (f'port {server_port}' if server_port else ' or '.join(predicates)) + ')'
    output.mkdir(parents=True, exist_ok=False)
    receipt = {'build': None, 'capture_completed': False, 'decoded': False,
               'scope': 'world_port_then_exact_pid_owner' if server_port else 'previous_world_endpoints_then_exact_pid_owner',
               'candidate_persistence': False, 'duration_limit_seconds': seconds,
               'capture_byte_limit': max_bytes, 'quarantine_byte_limit': gate.max_bytes,
               'session_keys_saved': False, 'uploaded': False}
    if interface_scope:
        receipt.update(scope='interface_world_port_then_exact_pid_owner',
                       matching_owner_scope='observed_candidate_four_tuple')
    receipt_path = output/'receipt.json'
    receipt_path.write_text(json.dumps(receipt, indent=2))
    stop = threading.Event()
    events = queue.Queue(maxsize=128)
    files, metadata = {}, {}
    process = None
    worker = None
    header = None
    packets = 0
    total = 24
    requested_stop=False
    owner_polls = owner_observations = matching_owner_observations = 0
    def checkpoint():
        for f in files.values():
            f.flush()
        receipt.update({'candidate_packets': packets, 'input_bytes': total,
                        'owner_polls': owner_polls,
                        'owner_observations': owner_observations,
                        'matching_owner_observations': matching_owner_observations,
                        'owned_connections': len(files),
                        'persisted_packets': sum(v['packets'] for v in metadata.values()),
                        'discarded_packets': gate.discarded,
                        'unconfirmed_packets': sum(len(f.pending) for f in gate.flows.values() if f),
                        'transport_complete': None, 'transport_validated': False})
        for target,data in ((output/'private-flows.json',list(metadata.values())),(receipt_path,receipt)):
            temporary=target.with_suffix(target.suffix+'.tmp')
            temporary.write_text(json.dumps(data,indent=2))
            temporary.replace(target)
    def enqueue(value):
        while not stop.is_set():
            try:
                events.put(value, timeout=.1)
                return
            except queue.Full:
                continue
    def reader():
        try:
            head = _read(process.stdout, 24)
            formats = {b'\xd4\xc3\xb2\xa1':('<',1000000), b'\xa1\xb2\xc3\xd4':('>',1000000),
                       b'\x4d\x3c\xb2\xa1':('<',1000000000), b'\xa1\xb2\x3c\x4d':('>',1000000000)}
            if head[:4] not in formats:
                raise ValueError('unsupported_capture_format')
            endian, precision = formats[head[:4]]
            major, minor, _, _, snap, link = struct.unpack(endian+'HHiiII', head[4:])
            if (major, minor) != (2,4) or not 1 <= snap <= 262144 or link not in (0,1,101):
                raise ValueError('invalid_pcap_header')
            enqueue(('header', head))
            count, size = 0, 24
            while not stop.is_set():
                raw = _read(process.stdout, 16, eof=True)
                if not raw:
                    enqueue(('eof', None))
                    return
                sec, fraction, cap, orig = struct.unpack(endian+'IIII', raw)
                if fraction >= precision or cap != orig or not 1 <= cap <= snap:
                    raise ValueError('truncated_or_invalid_record')
                count += 1
                size += 16+cap
                if count > max_packets or size > max_bytes:
                    raise ValueError('capture_limit')
                frame = _read(process.stdout, cap)
                packet = replace(decode_tcp(frame, link, endian), timestamp_ns=sec*10**9+fraction*(10**9//precision))
                enqueue(('packet', (packet, raw+frame)))
        except Exception as exc:
            safe = {'capture_limit','truncated_pcap','truncated_or_invalid_record',
                    'unsupported_capture_format','invalid_pcap_header',
                    'truncated_ipv4','fragmented_ipv4','truncated_tcp',
                    'invalid_ipv4','unsupported_network_protocol','unsupported_link_type',
                    'truncated_ethernet','truncated_vlan','not_tcp'}
            enqueue(('error', str(exc) if type(exc) is ValueError and str(exc) in safe else 'capture_reader_failed'))
    def persist(records):
        for key, raw in records:
            if key not in files:
                name = f'world-{len(files)+1:02d}.pcap'
                files[key] = (output/name).open('xb')
                files[key].write(header)
                metadata[key] = {'file': name, 'client': list(key[0]), 'server': list(key[1]), 'packets': 0}
            files[key].write(raw)
            metadata[key]['packets'] += 1
    try:
        argv = [str(dumpcap), '-i', interface, '-p', '-F', 'pcap', '-s', '262144', '-f', rule,
                '-a', f'duration:{seconds}', '-a', f'filesize:{max_bytes//1024}', '-c', str(max_packets), '-w', '-', '-q']
        with (output/'private-capture.log').open('xb') as log:
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=log, creationflags=0x08000000)
            worker = threading.Thread(target=reader, daemon=True)
            worker.start()
            started = time.monotonic()
            deadline = started+seconds+15
            next_owner = started
            next_progress = started+1
            while True:
                now = time.monotonic()
                if stop_requested is not None and stop_requested.is_set() and not requested_stop:
                    requested_stop=True
                    receipt['stop_requested']=True
                    receipt['user_stopped']=True  # Legacy receipt; the supervisor records the actual reason.
                    if process.poll() is None:process.terminate()
                if now > deadline:
                    raise ValueError('capture_timeout')
                if header is None and now-started > 10:
                    raise ValueError('capture_not_ready')
                if now >= next_owner:
                    owned = owner()
                    owner_polls += 1
                    owner_observations += len(owned)
                    matching_owner_observations += sum(
                        gate.flows.get(key) is not None if interface_scope else key[0][0] == gate.local
                        for key in owned)
                    persist(gate.confirm(owned, now))
                    next_owner = now+.05
                if now >= next_progress:
                    checkpoint()
                    if on_progress:on_progress(dict(receipt))
                    next_progress=time.monotonic()+1
                try:
                    kind, value = events.get(timeout=.05)
                except queue.Empty:
                    continue
                if kind == 'header':
                    header = value
                    receipt['armed'] = True
                    receipt_path.write_text(json.dumps(receipt, indent=2))
                    if on_ready:
                        on_ready()
                elif kind == 'packet':
                    packets += 1
                    packet, raw = value
                    total += len(raw)
                    persist(gate.feed(packet, raw, time.monotonic()))
                elif kind == 'error':
                    raise ValueError(value)
                elif kind == 'eof':
                    if process.wait(timeout=5) != 0 and not requested_stop:
                        raise ValueError('capture_process_failed')
                    # Npcap adapter detach can make dumpcap exit with status 0.
                    # Read the detach diagnostic without exposing raw log text.
                    with (output/'private-capture.log').open('rb') as diagnostic:
                        if b'is no longer attached' in diagnostic.read(65536):
                            raise ValueError('capture_adapter_detached')
                    persist(gate.confirm(owner(),time.monotonic()))
                    receipt['capture_completed'] = True
                    break
    except BaseException as exc:
        receipt['error_type'] = type(exc).__name__
        # Return fixed codes rather than raw exception messages.
        if type(exc) is ValueError and str(exc) in {
            'capture_limit','capture_timeout','capture_not_ready','capture_process_failed','capture_adapter_detached',
            'capture_reader_failed','capture_flow_limit','capture_quarantine_full',
            'capture_tuple_reused','packet_outside_prefilter','truncated_pcap',
            'truncated_or_invalid_record','unsupported_capture_format','invalid_pcap_header',
            'truncated_ipv4','fragmented_ipv4','truncated_tcp','invalid_ipv4',
            'unsupported_network_protocol','unsupported_link_type','truncated_ethernet',
            'truncated_vlan','not_tcp'}:
            receipt['error_code'] = str(exc)
        raise
    finally:
        stop.set()
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            if worker:
                worker.join(3)
            if process.stdout:
                process.stdout.close()
        try:
            checkpoint()
        finally:
            try:
                for f in files.values():f.close()
            finally:
                gate.close()
                if hasattr(owner, 'close'):owner.close()
    return receipt


def prepare_owner(wow, previous):
    import hashlib
    import ctypes as C
    from iara.sniffer.windows_inventory import _apis, U32, PTR
    info = json.loads(previous.read_text())
    digest = hashlib.sha256(wow.read_bytes()).hexdigest()
    build, _ = fixed_version(wow)
    select_profile(build, experimental=True, image_sha256=digest)
    if info.get('sha256') != digest or info.get('build') != build:
        raise ValueError('previous_inventory_mismatch')
    rows = [r for r in info['connections'] if r['server'][1] == 3724]
    if not rows or len({r['interface'] for r in rows}) != 1 or len({r['client'][0] for r in rows}) != 1:
        raise ValueError('known_world_scope_unavailable')
    interface, local = rows[0]['interface'], rows[0]['client'][0]
    if adapter_addresses().get(local) != interface:
        raise ValueError('adapter_changed')
    pid = None
    handle = None
    next_discovery = 0
    k = _apis()
    k.GetExitCodeProcess.argtypes = [PTR, C.POINTER(U32)]
    k.GetExitCodeProcess.restype = C.c_int
    def owner():
        nonlocal pid, handle, next_discovery
        if pid is None:
            now = time.monotonic()
            if now < next_discovery:
                return []
            next_discovery = now+1
            try:
                pid = find_process(wow)
            except ValueError as exc:
                if str(exc) == 'wow_process_not_unique_or_not_running':
                    return []
                raise
            handle = k.OpenProcess(0x1000, False, pid)
            if not handle:
                raise ValueError('process_identity_unavailable')
            from iara.sniffer.windows_inventory import process_path
            import os
            if os.path.normcase(process_path(k, handle)) != os.path.normcase(str(wow.resolve())):
                raise ValueError('game_process_changed')
        code = U32()
        if not k.GetExitCodeProcess(handle, C.byref(code)) or code.value != 259:
            raise ValueError('game_process_exited')
        return [(tuple(r['client']),tuple(r['server'])) for r in tcp_rows(pid)]
    def close():
        nonlocal handle
        if handle:
            k.CloseHandle(handle)
            handle = None
    owner.close = close
    return interface, local, sorted({tuple(r['server']) for r in rows}), owner


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('output', type=Path)
    p.add_argument('--previous', required=True, type=Path)
    p.add_argument('--seconds', type=int, default=300)
    p.add_argument('--wow', type=Path, default=Path(r'C:\Program Files (x86)\World of Warcraft\_retail_\Wow.exe'))
    a = p.parse_args()
    try:
        interface, local, servers, owner = prepare_owner(a.wow, a.previous)
        result = run_capture(a.output, interface=interface, local=local, servers=servers, owner=owner,
                             seconds=a.seconds, on_ready=lambda: print('{"armed":true,"keys_verified":false}', flush=True))
        print(json.dumps(result))
    except (ValueError, OSError, KeyError, subprocess.SubprocessError):
        print('{"ok":false,"code":"initial_capture_unavailable"}')
        raise SystemExit(1)
