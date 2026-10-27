import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts.sniffer_decode_session import decode
from iara.sniffer.windows_session import IMAGE_SHA256
from tests.test_sniffer_handshake import capture,SESSION,CLIENT,SERVER


class SessionDecodeTests(unittest.TestCase):
    def fixture(self,root,*,initial_auth=False):
        source=root/'world-01.pcap';source.write_bytes(capture(initial_auth=initial_auth))
        protected=root/'private.dpapi';protected.write_bytes(b'fictional encrypted fixture')
        flows=root/'flows.json';flows.write_text(json.dumps([{'file':source.name,'client':CLIENT,'server':SERVER}]))
        secret=json.dumps({'build':70575,'image_sha256':IMAGE_SHA256,'session':SESSION.hex()}).encode()
        return (source,root/'out.pkt',protected,flows,0),secret

    def test_complete_private_input_to_independently_validated_output(self):
        with tempfile.TemporaryDirectory() as d:
            args,secret=self.fixture(Path(d))
            with patch('scripts.sniffer_decode_session.unprotect',return_value=secret):r=decode(*args)
            self.assertEqual(r['records'],6);self.assertEqual(r['authenticated_frames'],2)
            self.assertTrue(r['transport_complete']);self.assertTrue(r['handshake_validated'])
            self.assertTrue(r['independent_container_check']['complete'])
            self.assertNotIn(SESSION.hex(),json.dumps(r))

    def test_initial_login_private_input_to_validated_output(self):
        with tempfile.TemporaryDirectory() as d:
            args,secret=self.fixture(Path(d),initial_auth=True)
            with patch('scripts.sniffer_decode_session.unprotect',return_value=secret):r=decode(*args)
            self.assertEqual(r['records'],6);self.assertEqual(r['authenticated_frames'],2)
            self.assertTrue(r['transport_complete']);self.assertTrue(r['handshake_validated'])
            self.assertTrue(r['independent_container_check']['complete'])
            self.assertNotIn(SESSION.hex(),json.dumps(r))
            self.assertNotIn('fictional realm ticket',json.dumps(r))

    def test_independent_validation_failure_does_not_publish(self):
        with tempfile.TemporaryDirectory() as d:
            args,secret=self.fixture(Path(d))
            with patch('scripts.sniffer_decode_session.unprotect',return_value=secret),patch(
                    'scripts.sniffer_decode_session.inspect_file',return_value={'complete':False}):
                with self.assertRaisesRegex(ValueError,'independent_container_check_failed'):decode(*args)
            self.assertFalse(args[1].exists());self.assertTrue(Path(str(args[1])+'.partial').exists())

    def test_changed_capture_does_not_publish(self):
        from scripts.sniffer_decode_session import inspect_handshake
        with tempfile.TemporaryDirectory() as d:
            args,secret=self.fixture(Path(d))
            def changed(*a,**kw):
                result=inspect_handshake(*a,**kw)
                # A growing live capture must not be advertised as finalized.
                with args[0].open('ab') as f:f.write(b'')
                import os
                stat=args[0].stat();os.utime(args[0],ns=(stat.st_atime_ns,stat.st_mtime_ns+1000000000))
                return result
            with patch('scripts.sniffer_decode_session.unprotect',return_value=secret),patch(
                    'scripts.sniffer_decode_session.inspect_handshake',side_effect=changed):
                with self.assertRaisesRegex(ValueError,'capture_changed_during_decode'):decode(*args)
            self.assertFalse(args[1].exists())

    def test_malformed_selection_and_wrong_fingerprint(self):
        with tempfile.TemporaryDirectory() as d:
            args,secret=self.fixture(Path(d))
            with patch('scripts.sniffer_decode_session.unprotect',return_value=secret):
                for index in (True,-1,1):
                    with self.assertRaisesRegex(ValueError,'invalid_flow_selection'):decode(*args[:-1],index)
            value=json.loads(secret);value['image_sha256']='wrong'
            with patch('scripts.sniffer_decode_session.unprotect',return_value=json.dumps(value).encode()):
                with self.assertRaisesRegex(ValueError,'fingerprint_mismatch'):decode(*args)
            self.assertFalse(args[1].exists())

    def test_incomplete_connection_and_existing_output(self):
        with tempfile.TemporaryDirectory() as d:
            args,secret=self.fixture(Path(d))
            # Remove the final FIN packet (16 byte PCAP record + 40 byte IP/TCP).
            args[0].write_bytes(args[0].read_bytes()[:-56])
            with patch('scripts.sniffer_decode_session.unprotect',return_value=secret):
                with self.assertRaisesRegex(ValueError,'connection_not_fully_captured'):decode(*args)
            self.assertFalse(args[1].exists())
            args[1].write_bytes(b'preserve')
            with patch('scripts.sniffer_decode_session.unprotect',return_value=secret):
                with self.assertRaises(FileExistsError):decode(*args)
            self.assertEqual(args[1].read_bytes(),b'preserve')
