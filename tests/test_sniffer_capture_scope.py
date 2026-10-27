from copy import deepcopy
import json
from pathlib import Path
import subprocess
import struct
import tempfile
import unittest
from unittest.mock import patch,MagicMock
from scripts.sniffer_capture_wow import filters,capture
from iara.sniffer.profiles import PROFILES

INFO={'build':70575,'sha256':PROFILES[70575].image_sha256,'connections':[
    {'client':['192.0.2.10',50000],'server':['203.0.113.7',3724],
     'interface':r'\Device\NPF_{12345678-1234-1234-1234-123456789abc}'}]}


class CaptureScopeTests(unittest.TestCase):
    def test_exact_bidirectional_tuple(self):
        _,rule=filters(INFO)
        self.assertEqual(rule,'tcp and (((src host 192.0.2.10 and src port 50000 and dst host 203.0.113.7 and dst port 3724) or (src host 203.0.113.7 and src port 3724 and dst host 192.0.2.10 and dst port 50000)))')

    def test_no_broadening_on_missing_interface_or_connections(self):
        for rows in ([],None,INFO['connections']*33):
            with self.assertRaises(ValueError):filters({'connections':rows})
        v=deepcopy(INFO);v['connections'][0]['interface']='any'
        with self.assertRaises(ValueError):filters(v)

    def test_no_argument_injection_or_mixed_adapters(self):
        for bad in ('203.0.113.7 or tcp','::1','0.0.0.0'):
            v=deepcopy(INFO);v['connections'][0]['server'][0]=bad
            with self.assertRaises(ValueError):filters(v)
        v=deepcopy(INFO);v['connections'].append(deepcopy(v['connections'][0]))
        v['connections'][1]['interface']=v['connections'][1]['interface'].replace('12345678','87654321')
        with self.assertRaisesRegex(ValueError,'multiple_interfaces'):filters(v)

    def test_unknown_client_does_not_start_capture(self):
        v=deepcopy(INFO);v['sha256']='other'
        with tempfile.TemporaryDirectory() as d,patch('scripts.sniffer_capture_wow.inventory',return_value=v),patch('scripts.sniffer_capture_wow.subprocess.Popen') as proc:
            with self.assertRaises(ValueError):capture(Path('Wow.exe'),Path(d)/'new',Path('dumpcap.exe'),20)
            proc.assert_not_called()

    def test_interrupt_stops_own_process_and_preserves_failure_receipt(self):
        process=MagicMock();process.wait.side_effect=[subprocess.TimeoutExpired('capture',35),0];process.poll.return_value=None
        with tempfile.TemporaryDirectory() as d,patch('scripts.sniffer_capture_wow.inventory',return_value=INFO),patch('scripts.sniffer_capture_wow.subprocess.Popen',return_value=process):
            out=Path(d)/'capture'
            with self.assertRaises(subprocess.TimeoutExpired):capture(Path('Wow.exe'),out,Path('dumpcap.exe'),20)
            process.terminate.assert_called_once()
            self.assertFalse(json.loads((out/'receipt.json').read_text())['capture_completed'])

    def test_capture_is_never_decode_proof(self):
        process=MagicMock();process.wait.return_value=0;process.poll.return_value=0
        with tempfile.TemporaryDirectory() as d,patch('scripts.sniffer_capture_wow.inventory',return_value=INFO),patch('scripts.sniffer_capture_wow.subprocess.Popen',return_value=process) as popen:
            def captured(*args,**kwargs):
                (Path(d)/'capture'/'wow-passive.pcap').write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
                return process
            popen.side_effect=captured
            r=capture(Path('Wow.exe'),Path(d)/'capture',Path('dumpcap.exe'),20)
            self.assertTrue(r['capture_completed']);self.assertFalse(r['decoded'])
            argv=popen.call_args.args[0];self.assertIn('-p',argv);self.assertIn('filesize:65536',argv)
            self.assertIn('tcp and',argv[argv.index('-f')+1])

    def test_process_success_without_capture_is_not_success(self):
        process=MagicMock();process.wait.return_value=0;process.poll.return_value=0
        with tempfile.TemporaryDirectory() as d,patch('scripts.sniffer_capture_wow.inventory',return_value=INFO),patch('scripts.sniffer_capture_wow.subprocess.Popen',return_value=process):
            out=Path(d)/'capture'
            with self.assertRaises(FileNotFoundError):capture(Path('Wow.exe'),out,Path('dumpcap.exe'),20)
            r=json.loads((out/'receipt.json').read_text())
            self.assertTrue(r['capture_process_completed']);self.assertFalse(r['capture_completed'])

    def test_capture_process_failure_has_explicit_receipt(self):
        process=MagicMock();process.wait.return_value=2;process.poll.return_value=2
        with tempfile.TemporaryDirectory() as d,patch('scripts.sniffer_capture_wow.inventory',return_value=INFO),patch('scripts.sniffer_capture_wow.subprocess.Popen',return_value=process):
            r=capture(Path('Wow.exe'),Path(d)/'capture',Path('dumpcap.exe'),20)
            self.assertFalse(r['capture_completed']);self.assertFalse(r['capture_process_completed'])
            self.assertEqual(r['capture_exit_code'],2)
