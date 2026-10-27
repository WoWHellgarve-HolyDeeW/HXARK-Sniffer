"""Capture lifecycle: arm interfaces, track the WoW process, drain and decode.

Only process-owned IPv4 connections are persisted. A held process handle
distinguishes process exit from PID reuse.
"""
import ctypes as C
from datetime import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time
import uuid

from .windows_inventory import _apis, U32, PTR, find_process, process_path, tcp_rows, adapter_addresses
from .windows_session import snapshot
from .local_secrets import protect
from .maintenance import inspect_build

MAX_SECONDS = 12 * 60 * 60
MAX_BYTES = 1024**3
MAX_PACKETS = 1000000
MAX_ADAPTERS = 8


class ProcessOwner:
    def __init__(self, wow):
        self.wow = Path(wow).resolve(strict=True)
        self.k = _apis()
        self.k.GetExitCodeProcess.argtypes = [PTR, C.POINTER(U32)]
        self.k.GetExitCodeProcess.restype = C.c_int
        self.pid = self.handle = None
        self.exited = False
        self.rows = ()
        self.next_discovery = 0

    def poll(self):
        if self.exited:
            return
        if self.handle is None:
            if time.monotonic() < self.next_discovery:
                return
            self.next_discovery = time.monotonic() + .25
            try:
                pid = find_process(self.wow)
            except ValueError as exc:
                if str(exc) == 'wow_process_not_unique_or_not_running':
                    return
                raise
            handle = self.k.OpenProcess(0x1000, False, pid)
            if not handle:
                return  # It may have closed between discovery and OpenProcess.
            try:
                if os.path.normcase(process_path(self.k, handle)) != os.path.normcase(str(self.wow)):
                    raise ValueError('process_identity_changed')
            except BaseException:
                self.k.CloseHandle(handle)
                raise
            self.pid, self.handle = pid, handle
        code = U32()
        if not self.k.GetExitCodeProcess(self.handle, C.byref(code)):
            raise ValueError('process_identity_unavailable')
        if code.value != 259:
            self.exited = True
            self.rows = ()
            return
        rows = tcp_rows(self.pid, connecting=True)
        # Discard rows if the process exited during the table read.
        if not self.k.GetExitCodeProcess(self.handle, C.byref(code)):
            raise ValueError('process_identity_unavailable')
        if code.value != 259:
            self.exited = True
            self.rows = ()
        else:
            self.rows = tuple((tuple(r['client']), tuple(r['server'])) for r in rows if r['server'][1] == 3724)

    def close(self):
        if self.handle is not None:
            self.k.CloseHandle(self.handle)
            self.handle = None


def capture_adapters(dumpcap=None):
    """Use the intersection of OS IPv4 addresses and Npcap devices."""
    if dumpcap is None:
        from .prerequisites import find_dumpcap
        dumpcap = find_dumpcap()
    try:
        result = subprocess.run([str(dumpcap), '-D'], capture_output=True,
                                timeout=10, creationflags=0x08000000, check=True)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        raise ValueError('capture_adapter_query_failed') from None
    # GUIDs are ASCII; interface names may use a different code page.
    devices = {x.decode('ascii').lower() for x in re.findall(rb'\\Device\\NPF_\{[0-9a-fA-F-]{36}\}', result.stdout)}
    found = sorted((local, interface) for local, interface in adapter_addresses().items()
                   if interface.lower() in devices and not ipaddress.IPv4Address(local).is_loopback)
    if not found:
        raise ValueError('capture_adapter_unavailable')
    if len({interface.lower() for _, interface in found}) > MAX_ADAPTERS:
        raise ValueError('too_many_capture_adapters')
    return found


class SessionArchive:
    def __init__(self, wow, output, verified):
        self.wow, self.output, self.verified = wow, output, verified
        self.paths, self.digests = [], set()
        self.last_error = None

    def sample(self, pid):
        try:
            value = snapshot(self.wow, expected_pid=pid, verified_image=self.verified)
        except ValueError as exc:
            if str(exc) in {'session_root_unavailable', 'session_not_initialized',
                            'session_changed_during_read', 'session_memory_unavailable',
                            'wow_process_not_unique_or_not_running'}:
                self.last_error = 'session_not_ready'
                return
            raise
        raw = json.dumps(value, sort_keys=True).encode()
        digest = hashlib.sha256(raw).digest()
        if digest in self.digests:
            return
        if len(self.paths) >= 32:
            raise ValueError('session_archive_limit')
        destination = self.output / f'private-session-{len(self.paths)+1:02d}.dpapi'
        with destination.open('xb') as f:
            f.write(protect(raw))
        self.paths.append(destination)
        self.digests.add(digest)
        self.last_error = None


def export_captures(output, adapter_outputs, secrets, *, process_exited, dumps=None):
    """Try session snapshots and export validated PKT candidates."""
    from scripts.sniffer_decode_session import decode
    results = []
    candidates = output / 'private-candidates'
    candidates.mkdir()
    for source_dir in adapter_outputs:
        flows_path = source_dir / 'private-flows.json'
        if not flows_path.exists():
            continue
        flows = json.loads(flows_path.read_text())
        if not isinstance(flows, list) or len(flows) > 32:
            raise ValueError('invalid_flow_selection')
        for index, flow in enumerate(flows):
            if not re.fullmatch(r'world-\d{2}\.pcap', flow.get('file', '')):
                raise ValueError('invalid_capture_file')
            number = len(results)+1
            record = {'file': f'world-{number:03d}.pkt', 'ok': False, 'code': 'authenticated_decode_incomplete'}
            for attempt, secret in enumerate(secrets):
                temporary = candidates / f'{number:03d}-{attempt:02d}.pkt'
                try:
                    receipt = decode(source_dir / flow['file'], temporary, secret, flows_path, index,
                                     process_exited=process_exited, max_bytes=MAX_BYTES, max_packets=MAX_PACKETS)
                except (ValueError, OSError, TypeError, KeyError, IndexError) as exc:
                    if type(exc) is ValueError and str(exc) in {
                        'unsupported_authentication_layout','unsupported_challenge_layout',
                        'handshake_incomplete','encryption_enable_not_confirmed',
                        'encryption_ack_not_confirmed','message_limit','decoded_batch_limit',
                        'authentication_failed','missing_tcp_handshake','connection_reset'}:
                        record['code'] = str(exc)
                    continue
                # Keep private inputs outside the user-facing dumps library.
                try:
                    if dumps is not None:
                        from .capture_library import publish_capture
                        published = publish_capture(temporary, dumps, output.name, number,
                                                    receipt['pkt_sha256'], remove_source=True)
                        record = dict(published, ok=True, receipt=receipt)
                    else:
                        # Legacy CLI layout retained for existing diagnostic tools.
                        os.link(temporary, output / record['file'])
                        temporary.unlink()
                        record = {'file': record['file'], 'ok': True, 'receipt': receipt}
                except (OSError, ValueError):
                    record['code'] = 'capture_publish_failed'
                    # Keep the candidate for recovery; another key cannot fix a filesystem error.
                break
            results.append(record)
    return results


def run_session(wow, captures, stop, notify=lambda value: None, *,
                owner_factory=ProcessOwner, adapters_factory=capture_adapters,
                archive_factory=SessionArchive, capture=None, export=export_captures,
                inspect=inspect_build, exit_grace=1.0, seconds=MAX_SECONDS, dumps=None):
    from scripts.sniffer_capture_start import run_capture
    from .updates import update_lock, safe_store, default_store
    capture = capture or run_capture
    wow = Path(wow).resolve(strict=True)
    stat = wow.stat()
    observation = inspect(wow)
    if not observation['capture_allowed']:
        raise ValueError('unsupported_build')
    if (wow.stat().st_size, wow.stat().st_mtime_ns) != (stat.st_size, stat.st_mtime_ns):
        raise ValueError('client_changed_during_capture')
    verified = {'stat': (stat.st_size, stat.st_mtime_ns), 'build': observation['build'],
                'sha256': observation['image_sha256']}
    # Use one collector per interface, including interfaces with multiple IPs.
    adapters = list({interface.lower(): (local, interface)
                     for local, interface in adapters_factory()}.values())
    if not 1 <= len(adapters) <= MAX_ADAPTERS:
        raise ValueError('capture_adapter_unavailable')
    captures = Path(captures)
    captures.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(captures).free < MAX_BYTES + 256*1024**2:
        raise ValueError('insufficient_capture_disk')
    output = captures / (datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    halt = threading.Event()
    workers, folders, ready, errors, receipts = [], [], set(), [], {}
    progress = {}
    owned_connections = set()
    mutex = threading.Lock()
    reason = 'user_stopped'
    def emit(state, **values):
        notify({'state': state, **values})
    def worker(index, local, interface, folder):
        def armed():
            with mutex:
                ready.add(index)
        def report(value):
            with mutex:
                progress[index] = value
        try:
            receipts[index] = capture(folder, interface=interface, local=local, servers=None,
                server_port=3724, interface_scope=True, owner=lambda: list(owner.rows), seconds=seconds,
                on_ready=armed, on_progress=report, stop_requested=halt, max_bytes=MAX_BYTES//len(adapters),
                max_packets=MAX_PACKETS//len(adapters))
        except Exception as exc:
            safe = {'capture_limit', 'capture_flow_limit', 'capture_quarantine_full', 'capture_not_ready',
                    'capture_tuple_reused', 'capture_process_failed', 'truncated_ipv4', 'truncated_tcp',
                    'fragmented_ipv4','truncated_pcap','capture_reader_failed','capture_adapter_detached'}
            with mutex:
                errors.append({'adapter': index, 'code': str(exc) if str(exc) in safe else 'adapter_capture_failed'})
            # Preserve bounded technical counters on a failed collector too.
            try:
                failed_receipt = json.loads((folder/'receipt.json').read_text())
                receipts[index] = {key: value for key, value in failed_receipt.items()
                                   if key in {'candidate_packets','persisted_packets','owner_observations',
                                              'matching_owner_observations'} and type(value) is int and value >= 0}
            except (OSError, ValueError, AttributeError):
                pass
    with update_lock(safe_store(default_store())):
        owner = owner_factory(wow)
        try:
            archive = archive_factory(wow, output, verified)
            for index, (local, interface) in enumerate(adapters):
                folder = output / f'private-adapter-{index+1:02d}'
                folders.append(folder)
                t = threading.Thread(target=worker, args=(index, local, interface, folder), daemon=True)
                workers.append(t)
                t.start()
            started = time.monotonic()
            exited_at = None
            next_snapshot = 0
            last_state = None
            while not stop.is_set():
                owner.poll()
                owned_connections.update(owner.rows)
                if len(owned_connections) > MAX_ADAPTERS * 32:
                    raise ValueError('owned_connection_limit')
                now = time.monotonic()
                with mutex:
                    armed_count = len(ready)
                    failed = bool(errors)
                    captured = sum(v.get('persisted_packets', 0) for v in progress.values())
                if owner.exited:
                    if exited_at is None:
                        exited_at = now
                        emit('saving')
                    if now-exited_at >= exit_grace:
                        reason = 'process_exited'
                        break
                elif owner.pid is not None and owner.rows and now >= next_snapshot:
                    try:
                        archive.sample(owner.pid)
                    except (ValueError, OSError):
                        owner.poll()
                        if not owner.exited:raise
                    next_snapshot = now+1
                state = ('recording' if captured else 'awaiting_traffic') if owner.pid is not None else 'waiting'
                if armed_count != len(adapters):
                    state = 'arming'
                if not owner.exited and state != last_state:
                    emit(state, adapters=armed_count)
                    last_state = state
                if failed:
                    reason = 'adapter_error'
                    break
                if not all(t.is_alive() for t in workers):
                    reason = 'capture_limit'
                    break
                if now-started >= seconds:
                    reason = 'duration_limit'
                    break
                if now-started > 12 and armed_count != len(adapters):
                    raise ValueError('capture_not_ready')
                if shutil.disk_usage(output).free < 256*1024**2:
                    raise ValueError('insufficient_capture_disk')
                stop.wait(.05)
        except Exception as exc:
            reason = 'supervisor_error'
            safe = {'client_changed_during_capture', 'process_identity_changed', 'session_archive_limit',
                    'readonly_process_access_denied', 'capture_not_ready', 'insufficient_capture_disk',
                    'owned_connection_limit'}
            errors.append({'code': str(exc) if str(exc) in safe else 'automatic_capture_failed'})
        finally:
            halt.set()
            for thread in workers:
                thread.join(20)
            owner.close()
        if any(t.is_alive() for t in workers):
            raise ValueError('capture_shutdown_incomplete')
        emit('saving')
        secrets = archive.paths if 'archive' in locals() else []
        try:
            options = {'dumps': dumps} if dumps is not None else {}
            results = export(output, folders, secrets, process_exited=reason == 'process_exited', **options)
        except Exception:
            errors.append({'code':'export_failed'})
            results = []
        totals = {key: sum(value.get(key, 0) for value in receipts.values()) for key in (
            'candidate_packets','persisted_packets','owner_observations','matching_owner_observations')}
        captured_connections = set()
        for folder in folders:
            try:
                flows = json.loads((folder/'private-flows.json').read_text())
                if not isinstance(flows, list) or len(flows) > 32:
                    raise ValueError('invalid_flow_selection')
                captured_connections.update((tuple(f['client']), tuple(f['server']))
                                            for f in flows if f.get('packets', 0) > 0)
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                # Treat missing or invalid collector records as incomplete capture.
                continue
        missing_connections = len(owned_connections - captured_connections)
        if missing_connections:
            errors.append({'code': 'owned_game_flow_not_captured', 'count': missing_connections})
        if reason == 'process_exited' and not results and not errors:
            if not totals['candidate_packets']:
                code = 'no_game_packets'
            elif not totals['persisted_packets']:
                code = 'no_owned_game_flow'
            else:
                code = 'no_exportable_game_flow'
            errors.append({'code': code})
        retry_before_game = (owner.pid is None and not secrets and not results and
            ((bool(errors) and all(e['code'] == 'capture_adapter_detached' for e in errors))
             or (not errors and reason in ('duration_limit', 'capture_limit'))))
        result = {'build': observation['build'], 'reason': reason, 'captures': results,
                  'complete': bool(results) and all(r['ok'] for r in results) and not errors,
                  'errors': errors, 'adapter_count': len(adapters), 'uploaded': False,
                  'session_snapshots': len(secrets), 'capture_counts': totals,
                  'observed_owned_connections': len(owned_connections),
                  'uncaptured_owned_connections': missing_connections,
                  'retry_before_game': retry_before_game}
        with (output / 'result.json').open('x') as f:
            json.dump(result, f, indent=2)
        emit('network_wait' if retry_before_game else 'saved' if result['complete'] else 'incomplete',
             files=sum(r['ok'] for r in results), reason=reason)
        return result
