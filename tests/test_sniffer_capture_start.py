import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch
from scripts.sniffer_capture_start import run_capture
from tests.test_sniffer_replay import pcap,fixture,CLIENT,SERVER


class FakeCapture:
    def __init__(self,data):self.stdout=io.BytesIO(data);self.done=False;self.terminated=False
    def poll(self):return 0 if self.done else None
    def wait(self,timeout=None):self.done=True;return 0
    def terminate(self):self.terminated=True;self.done=True
    def kill(self):self.terminate()


class CaptureStartTests(unittest.TestCase):
    def test_user_stop_drains_owned_packets_without_proving_transport_complete(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'capture';event=threading.Event()
            process=FakeCapture(pcap(fixture()));owner=Mock(return_value=[(CLIENT,SERVER)])
            process.wait=lambda timeout=None:1 if process.terminated else 0
            with patch('scripts.sniffer_capture_start.subprocess.Popen',return_value=process):
                receipt=run_capture(root,interface=r'\Device\NPF_Loopback',local=CLIENT[0],servers=[SERVER],
                                    owner=owner,seconds=3,on_ready=event.set,stop_requested=event)
            self.assertTrue(process.terminated);self.assertTrue(receipt['user_stopped'])
            self.assertTrue(receipt['capture_completed']);self.assertFalse(receipt['transport_validated'])
            self.assertEqual((root/'world-01.pcap').read_bytes(),pcap(fixture()))
            owner.close.assert_called_once()

    def run_case(self,root,data,owner,on_ready=None):
        process=FakeCapture(data)
        with patch('scripts.sniffer_capture_start.subprocess.Popen',return_value=process):
            result=run_capture(root,interface=r'\Device\NPF_Loopback',local=CLIENT[0],servers=[SERVER],
                               owner=owner,seconds=3,on_ready=on_ready)
        self.assertTrue(process.stdout.closed)
        return result,process

    def test_confirmed_initial_syn_survives_quarantine_and_final_flush(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'capture';owner=Mock(return_value=[(CLIENT,SERVER)])
            raw=pcap(fixture());r,p=self.run_case(root,raw,owner)
            self.assertTrue(r['capture_completed']);self.assertEqual(r['owned_connections'],1)
            self.assertIsNone(r['transport_complete']);self.assertFalse(r['transport_validated'])
            self.assertEqual((root/'world-01.pcap').read_bytes(),raw)
            self.assertEqual(json.loads((root/'receipt.json').read_text()),r)
            self.assertFalse((root/'receipt.json.tmp').exists());owner.close.assert_called_once()

    def test_unowned_payload_never_persisted(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'capture';r,p=self.run_case(root,pcap(fixture()),Mock(return_value=[]))
            self.assertEqual(r['persisted_packets'],0);self.assertGreater(r['unconfirmed_packets'],0)
            self.assertEqual(list(root.glob('*.pcap')),[])

    def test_nanosecond_capture_header_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            data=bytearray(pcap(fixture()));data[:4]=b'\x4d\x3c\xb2\xa1'
            r,p=self.run_case(Path(d)/'capture',bytes(data),Mock(return_value=[(CLIENT,SERVER)]))
            self.assertTrue(r['capture_completed']);self.assertGreater(r['persisted_packets'],0)

    def test_truncation_records_failure_and_closes_owner(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'capture';owner=Mock(return_value=[])
            with self.assertRaises(ValueError):self.run_case(root,pcap(fixture())[:-1],owner)
            r=json.loads((root/'receipt.json').read_text())
            self.assertFalse(r['capture_completed']);owner.close.assert_called_once()

    def test_callback_interrupt_stops_only_capture_and_preserves_failure_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'capture';owner=Mock(return_value=[]);process=FakeCapture(pcap([]))
            def interrupt():raise KeyboardInterrupt()
            with patch('scripts.sniffer_capture_start.subprocess.Popen',return_value=process):
                with self.assertRaises(KeyboardInterrupt):
                    run_capture(root,interface=r'\Device\NPF_Loopback',local=CLIENT[0],servers=[SERVER],
                                owner=owner,seconds=3,on_ready=interrupt)
            self.assertTrue(process.terminated);self.assertTrue(process.stdout.closed)
            owner.close.assert_called_once();self.assertFalse(json.loads((root/'receipt.json').read_text())['capture_completed'])

    def test_parser_error_is_fixed_code_without_payload(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'capture'
            with patch('scripts.sniffer_capture_start.decode_tcp',side_effect=ValueError('truncated_ipv4')):
                with self.assertRaisesRegex(ValueError,'truncated_ipv4'):
                    self.run_case(root,pcap(fixture()),Mock(return_value=[]))
            r=json.loads((root/'receipt.json').read_text())
            self.assertEqual(r['error_code'],'truncated_ipv4')

    def test_detached_adapter_exit_zero_is_not_completed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'capture'
            def detach():
                with (root/'private-capture.log').open('ab') as f:
                    f.write(b'dumpcap: The network adapter is no longer attached; the capture has stopped.\n')
            with self.assertRaisesRegex(ValueError,'capture_adapter_detached'):
                self.run_case(root,pcap([]),Mock(return_value=[]),on_ready=detach)
            r=json.loads((root/'receipt.json').read_text())
            self.assertFalse(r['capture_completed']);self.assertEqual(r['error_code'],'capture_adapter_detached')

    def test_ownership_diagnostics_have_counts_not_endpoints(self):
        with tempfile.TemporaryDirectory() as d:
            r,_=self.run_case(Path(d)/'capture',pcap(fixture()),Mock(return_value=[(CLIENT,SERVER)]))
            self.assertGreater(r['owner_polls'],0)
            self.assertEqual(r['owner_observations'],r['matching_owner_observations'])
            self.assertNotIn(CLIENT[0],json.dumps(r));self.assertNotIn(SERVER[0],json.dumps(r))

    def test_interface_filter_is_not_bound_to_stale_dhcp_address(self):
        for owned in ([],[(CLIENT,SERVER)]):
            with tempfile.TemporaryDirectory() as d:
                root=Path(d)/'capture';raw=pcap(fixture())
                with patch('scripts.sniffer_capture_start.subprocess.Popen',return_value=FakeCapture(raw)) as command:
                    r=run_capture(root,interface=r'\Device\NPF_Loopback',local='192.0.2.254',servers=None,
                                  server_port=3724,interface_scope=True,owner=lambda:owned,seconds=3)
                argv=command.call_args.args[0]
                self.assertEqual(argv[argv.index('-f')+1],'ip and tcp and (port 3724)')
                self.assertIn('-p',argv)
                self.assertEqual(r['scope'],'interface_world_port_then_exact_pid_owner')
                if owned:self.assertEqual((root/'world-01.pcap').read_bytes(),raw)
                else:self.assertEqual(list(root.glob('*.pcap')),[])
                self.assertNotIn(CLIENT[0],json.dumps(r))
