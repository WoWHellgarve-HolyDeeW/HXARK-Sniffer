import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
from dataclasses import replace
from iara.sniffer.capture_gate import CaptureGate
from iara.sniffer.automatic import run_session, capture_adapters, SessionArchive, export_captures, ProcessOwner
from tests.test_sniffer_capture_gate import C, S, SYN, PAIR
from tests.test_sniffer_replay import fixture, pcap, datagram, PROFILE, CLIENT, SERVER, KEY
from iara.sniffer.replay import replay
from tests import test_sniffer_decode_session as decode_tests


class AutomaticTests(unittest.TestCase):
    def test_discovery_errors_are_identified_before_any_capture(self):
        import subprocess
        for exc in (subprocess.TimeoutExpired('dumpcap',10),subprocess.CalledProcessError(1,'dumpcap')):
            with patch('iara.sniffer.automatic.subprocess.run',side_effect=exc),self.assertRaisesRegex(ValueError,'capture_adapter_query_failed'):
                capture_adapters('dumpcap')

    def test_discover_server_requires_exact_owner_and_ignores_other_interface(self):
        gate=CaptureGate(C[0],None,server_port=3724)
        new=replace(SYN,destination='203.0.113.99')
        gate.feed(new,b'syn',0)
        self.assertEqual(gate.confirm([PAIR],1),[])
        self.assertEqual(gate.confirm([((C[0],C[1]),('203.0.113.99',3724))],2)[0][1],b'syn')
        with self.assertRaisesRegex(ValueError,'outside_prefilter'):
            gate.feed(replace(SYN,source='192.0.2.99'),b'x',3)

    def test_dynamic_scope_cannot_be_mixed_or_unbounded(self):
        for args in ((None,None),([S],3724),(None,True),(None,0)):
            with self.assertRaises(ValueError):CaptureGate(C[0],args[0],server_port=args[1])

    def test_adapter_selection_intersects_npcap_and_os(self):
        a=r'\Device\NPF_{00000000-0000-0000-0000-000000000001}'
        b=r'\Device\NPF_{00000000-0000-0000-0000-000000000002}'
        with patch('iara.sniffer.automatic.subprocess.run',return_value=Mock(stdout=('1. '+a+'\n2. '+b).encode())),patch(
                'iara.sniffer.automatic.adapter_addresses',return_value={'192.0.2.1':a,'192.0.2.2':b,'192.0.2.3':'missing'}):
            self.assertEqual(capture_adapters(),[('192.0.2.1',a),('192.0.2.2',b)])

    def test_adapter_display_name_encoding_never_breaks_guid_selection(self):
        a=r'\Device\NPF_{00000000-0000-0000-0000-000000000001}'
        raw=b'1. '+a.encode('ascii')+b' (Wi-Fi \x81\xff\xc3\xa1)\r\n'
        with patch('iara.sniffer.automatic.subprocess.run',return_value=Mock(stdout=raw)) as command,patch(
                'iara.sniffer.automatic.adapter_addresses',return_value={'192.0.2.1':a}):
            self.assertEqual(capture_adapters(),[('192.0.2.1',a)])
            self.assertNotIn('text',command.call_args.kwargs)

    def test_address_aliases_do_not_consume_interface_slots(self):
        a=r'\Device\NPF_{00000000-0000-0000-0000-000000000001}'
        with patch('iara.sniffer.automatic.subprocess.run',return_value=Mock(stdout=a.encode())),patch(
                'iara.sniffer.automatic.adapter_addresses',return_value={f'192.0.2.{i}':a for i in range(1,12)}):
            self.assertEqual(len(capture_adapters()),11)

    def test_interface_count_remains_bounded(self):
        pairs={f'192.0.2.{i}':rf'\Device\NPF_{{00000000-0000-0000-0000-{i:012d}}}' for i in range(1,10)}
        with patch('iara.sniffer.automatic.subprocess.run',return_value=Mock(stdout='\n'.join(pairs.values()).encode())),patch(
                'iara.sniffer.automatic.adapter_addresses',return_value=pairs):
            with self.assertRaisesRegex(ValueError,'too_many_capture_adapters'):capture_adapters()

    def exercise(self,root,*,failure=False,cancel=False,unsupported=False,export_error=False,empty=False,detach=False,missing=False,same_interface=False):
        wow=root/'Wow.exe';wow.write_bytes(b'synthetic')
        stop=threading.Event();events=[];armed=threading.Event();calls=[]
        class Owner:
            pid=None;exited=False;rows=();ticks=0
            def poll(self):
                if detach:return
                if not armed.is_set():return
                self.ticks+=1;self.pid=42;self.rows=(PAIR,)
                if cancel:stop.set()
                if self.ticks>=4:self.exited=True;self.rows=()
            def close(self):self.closed=True
        owner=Owner();archive=Mock(paths=[])
        def capture(folder,**kw):
            folder.mkdir();kw['on_ready']();armed.set();calls.append(kw)
            if detach:
                (folder/'receipt.json').write_text(json.dumps({'candidate_packets':0,'persisted_packets':0}))
                raise ValueError('capture_adapter_detached')
            if failure:raise ValueError('capture_process_failed')
            kw['on_progress']({'persisted_packets':0 if empty else 6})
            kw['stop_requested'].wait(3)
            flows=[] if empty or missing else [{'client':list(PAIR[0]),'server':list(PAIR[1]),'packets':6}]
            (folder/'private-flows.json').write_text(json.dumps(flows))
            return {'capture_completed':True}
        exported=Mock(return_value=[] if empty or detach else [{'ok':True,'file':'world-001.pkt'}])
        if export_error:exported.side_effect=OSError('disk full')
        with patch('iara.sniffer.updates.default_store',return_value=root/'store'),patch(
                'iara.sniffer.automatic.shutil.disk_usage',return_value=Mock(free=10*1024**3)):
            result=run_session(wow,root/'captures',stop,events.append,
                owner_factory=lambda _:owner,archive_factory=lambda *a:archive,
                adapters_factory=lambda:[('192.0.2.1','a'),('192.0.2.2','A' if same_interface else 'b')],capture=capture,
                export=exported,inspect=lambda _:{'capture_allowed':not unsupported,'build':70575,'image_sha256':'a'*64},
                exit_grace=0,seconds=3)
        return result,events,calls,owner,archive,exported

    def test_two_adapters_ready_then_exit_exports_once_without_clicks(self):
        with tempfile.TemporaryDirectory() as d:
            r,events,calls,owner,archive,exported=self.exercise(Path(d))
            self.assertEqual(r['reason'],'process_exited');self.assertTrue(r['complete'])
            self.assertEqual(len(calls),2);self.assertTrue(owner.closed)
            self.assertTrue(all(c['server_port']==3724 and c['servers'] is None for c in calls))
            self.assertTrue(all(c['interface_scope'] is True for c in calls))
            self.assertEqual(sum(c['max_bytes'] for c in calls),1024**3)
            archive.sample.assert_called();exported.assert_called_once()
            self.assertTrue(exported.call_args.kwargs['process_exited'])
            self.assertIn('saved',[e['state'] for e in events])

    def test_adapter_failure_never_claims_full_success(self):
        with tempfile.TemporaryDirectory() as d:
            r,*_=self.exercise(Path(d),failure=True)
            self.assertFalse(r['complete']);self.assertEqual(r['reason'],'adapter_error')

    def test_zero_packets_cannot_claim_recording_or_success(self):
        with tempfile.TemporaryDirectory() as d:
            r,events,*_=self.exercise(Path(d),empty=True)
            self.assertFalse(r['complete'])
            self.assertIn({'code':'owned_game_flow_not_captured','count':1},r['errors'])
            self.assertNotIn('recording',[e['state'] for e in events])
            self.assertIn('awaiting_traffic',[e['state'] for e in events])
            self.assertFalse(r['retry_before_game'])

    def test_multiple_addresses_on_one_interface_do_not_duplicate_capture(self):
        with tempfile.TemporaryDirectory() as d:
            r,_,calls,*_=self.exercise(Path(d),same_interface=True)
            self.assertTrue(r['complete']);self.assertEqual(r['adapter_count'],1)
            self.assertEqual(len(calls),1);self.assertEqual(calls[0]['max_bytes'],1024**3)

    def test_missing_owned_connection_cannot_hide_behind_successful_pkt(self):
        with tempfile.TemporaryDirectory() as d:
            r,*_=self.exercise(Path(d),missing=True)
            self.assertTrue(r['captures'][0]['ok']);self.assertFalse(r['complete'])
            self.assertEqual(r['observed_owned_connections'],1)
            self.assertEqual(r['uncaptured_owned_connections'],1)
            self.assertIn({'code':'owned_game_flow_not_captured','count':1},r['errors'])

    def test_detach_before_game_can_rearm_without_claiming_capture(self):
        with tempfile.TemporaryDirectory() as d:
            r,*_=self.exercise(Path(d),detach=True)
            self.assertTrue(r['retry_before_game']);self.assertFalse(r['complete'])
            self.assertEqual(r['reason'],'adapter_error')
            self.assertTrue(all(e['code']=='capture_adapter_detached' for e in r['errors']))

    def test_window_close_stops_collectors_without_claiming_game_exit(self):
        with tempfile.TemporaryDirectory() as d:
            r,_,calls,owner,_,exported=self.exercise(Path(d),cancel=True)
            self.assertEqual(r['reason'],'user_stopped')
            self.assertFalse(exported.call_args.kwargs['process_exited'])
            self.assertTrue(owner.closed);self.assertTrue(all(c['stop_requested'].is_set() for c in calls))

    def test_unknown_build_never_starts_collector(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'unsupported_build'):self.exercise(Path(d),unsupported=True)
            self.assertFalse((Path(d)/'captures').exists())

    def test_export_failure_closes_owner_and_cannot_claim_success(self):
        with tempfile.TemporaryDirectory() as d:
            result,_,_,owner,_,_=self.exercise(Path(d),export_error=True)
            self.assertFalse(result['complete']);self.assertTrue(owner.closed)
            self.assertIn({'code':'export_failed'},result['errors'])

    def test_session_snapshots_deduplicate_and_keep_changes_private(self):
        with tempfile.TemporaryDirectory() as d:
            archive=SessionArchive('fake',Path(d),{})
            with patch('iara.sniffer.automatic.snapshot',side_effect=[{'session':'one'},{'session':'one'},{'session':'two'}]),patch(
                    'iara.sniffer.automatic.protect',return_value=b'encrypted'):
                for _ in range(3):archive.sample(42)
            self.assertEqual(len(archive.paths),2)
            self.assertTrue(all(p.read_bytes()==b'encrypted' for p in archive.paths))

    def test_exit_can_finish_valid_frames_without_fin_but_does_not_claim_full_transport(self):
        for packets in (fixture()[:-2],fixture()):
            with tempfile.TemporaryDirectory() as d:
                r=replay(io.BytesIO(pcap(packets)),Path(d)/'out.pkt',profile=PROFILE,client=CLIENT,server=SERVER,
                         keys={'client':KEY,'server':KEY},encrypted_from={'client':1,'server':1},process_exited=True)
                self.assertEqual(r['records'],5)
                self.assertEqual(r['transport_complete'],packets==fixture())

    def test_exit_does_not_hide_missing_bytes_or_wrong_keys(self):
        for raw,key in ((pcap(fixture()[:3]+fixture()[5:]),KEY),(pcap(fixture()),b'x'*32)):
            with tempfile.TemporaryDirectory() as d:
                out=Path(d)/'out.pkt'
                with self.assertRaises(ValueError):
                    replay(io.BytesIO(raw),out,profile=PROFILE,client=CLIENT,server=SERVER,
                           keys={'client':key,'server':KEY},encrypted_from={'client':1,'server':1},process_exited=True)
                self.assertFalse(out.exists())

    def test_reset_at_exit_exports_only_valid_frames_and_reports_transport_limit(self):
        raw=pcap(fixture()[:-2]+[datagram('client',999,flags=4)])
        with tempfile.TemporaryDirectory() as d:
            r=replay(io.BytesIO(raw),Path(d)/'out.pkt',profile=PROFILE,client=CLIENT,server=SERVER,
                     keys={'client':KEY,'server':KEY},encrypted_from={'client':1,'server':1},process_exited=True)
            self.assertEqual(r['records'],5);self.assertFalse(r['transport_complete'])

    def test_incomplete_frame_at_exit_does_not_finalize(self):
        packets=fixture()[:-2]+[datagram('client',999999,b'fragment')]
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'out.pkt'
            with self.assertRaises(ValueError):
                replay(io.BytesIO(pcap(packets)),out,profile=PROFILE,client=CLIENT,server=SERVER,
                       keys={'client':KEY,'server':KEY},encrypted_from={'client':1,'server':1},process_exited=True)
            self.assertFalse(out.exists())

    def test_connecting_tcp_rows_can_confirm_owner_before_handshake_finishes(self):
        import struct
        from iara.sniffer.windows_tables import parse_tcp_table
        row=struct.pack('<I',3)+bytes([192,0,2,1])+struct.pack('!H',50000)+bytes(2)
        row+=bytes([203,0,113,8])+struct.pack('!H',3724)+bytes(2)+struct.pack('<I',42)
        raw=struct.pack('<I',1)+row
        self.assertEqual(parse_tcp_table(raw,42),[])
        self.assertEqual(len(parse_tcp_table(raw,42,connecting=True)),1)
        self.assertEqual(parse_tcp_table(raw,43,connecting=True),[])

    def test_export_uses_later_valid_snapshot_after_wrong_key(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);adapter=root/'adapter';adapter.mkdir()
            args,secret=decode_tests.SessionDecodeTests().fixture(adapter)
            args[3].rename(adapter/'private-flows.json')
            bad=json.loads(secret);bad['session']='01'*40
            with patch('scripts.sniffer_decode_session.unprotect',side_effect=[json.dumps(bad).encode(),secret]):
                results=export_captures(root,[adapter],[args[2],args[2]],process_exited=True)
            self.assertTrue(results[0]['ok']);self.assertTrue((root/'world-001.pkt').exists())
            self.assertEqual(results[0]['receipt']['records'],6)

    def test_automatic_export_initial_login_with_verified_private_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);adapter=root/'adapter';adapter.mkdir()
            args,secret=decode_tests.SessionDecodeTests().fixture(adapter,initial_auth=True)
            args[3].rename(adapter/'private-flows.json')
            with patch('scripts.sniffer_decode_session.unprotect',return_value=secret):
                results=export_captures(root,[adapter],[args[2]],process_exited=True)
            self.assertTrue(results[0]['ok']);self.assertTrue((root/'world-001.pkt').exists())
            self.assertEqual(results[0]['receipt']['authenticated_frames'],2)

    def test_automatic_export_publishes_only_pkt_in_library(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);session=root/'20261026-120000-1234abcd';session.mkdir()
            adapter=session/'adapter';adapter.mkdir()
            args,secret=decode_tests.SessionDecodeTests().fixture(adapter,initial_auth=True)
            args[3].rename(adapter/'private-flows.json')
            with patch('scripts.sniffer_decode_session.unprotect',return_value=secret):
                results=export_captures(session,[adapter],[args[2]],process_exited=True,dumps=root/'dumps')
            self.assertTrue(results[0]['ok']);self.assertEqual(results[0]['storage'],'dumps')
            self.assertTrue((root/'dumps'/results[0]['file']).is_file())
            self.assertFalse(list(session.glob('*.pkt')))
            self.assertFalse(list((session/'private-candidates').glob('*.pkt')))
            self.assertEqual([p.suffix for p in (root/'dumps').iterdir()],['.pkt'])

    def test_publish_failure_keeps_authenticated_candidate_for_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);session=root/'20261026-120000-1234abcd';session.mkdir()
            adapter=session/'adapter';adapter.mkdir()
            args,secret=decode_tests.SessionDecodeTests().fixture(adapter,initial_auth=True)
            args[3].rename(adapter/'private-flows.json')
            with patch('scripts.sniffer_decode_session.unprotect',return_value=secret) as keys,patch(
                    'iara.sniffer.capture_library.publish_capture',side_effect=OSError('disk full')):
                results=export_captures(session,[adapter],[args[2],args[2]],process_exited=True,dumps=root/'dumps')
            self.assertFalse(results[0]['ok']);self.assertEqual(results[0]['code'],'capture_publish_failed')
            self.assertTrue(list((session/'private-candidates').glob('*.pkt')))
            keys.assert_called_once()

    def test_native_process_exit_is_normal_and_handle_is_closed(self):
        import os,subprocess,sys
        if os.name!='nt':self.skipTest('Windows native lifecycle')
        executable=Path(sys.executable).with_name('pythonw.exe')
        if not executable.exists():self.skipTest('pythonw unavailable')
        child=subprocess.Popen([str(executable),'-c','import time; time.sleep(.8)'],creationflags=0x08000000)
        owner=ProcessOwner(executable)
        try:
            with patch('iara.sniffer.automatic.find_process',return_value=child.pid):
                owner.poll();self.assertEqual(owner.pid,child.pid)
                child.wait(timeout=3);owner.poll()
                self.assertTrue(owner.exited);self.assertEqual(owner.rows,())
        finally:
            owner.close()
            if child.poll() is None:child.terminate();child.wait()
        self.assertIsNone(owner.handle)
