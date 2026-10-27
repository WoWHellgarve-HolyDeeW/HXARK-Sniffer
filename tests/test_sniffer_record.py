from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
from scripts.sniffer_record import record


class RecordTests(unittest.TestCase):
    def call(self,root,save_error=None,decode_error=None):
        previous=root.parent/'previous.json';previous.write_text('{"build":70575}')
        def capture(output,**kw):
            output.mkdir()
            (output/'private-flows.json').write_text(json.dumps([{'file':'world-01.pcap'}]))
            kw['on_ready']()
            for n in range(2):kw['on_progress']({'owned_connections':1})
            return {'capture_completed':True,'owned_connections':1}
        def save(wow,path):
            if save_error:raise save_error
            path.write_bytes(b'sealed synthetic')
        with patch('scripts.sniffer_record.prepare_owner',return_value=('i','l',[],Mock())),patch(
                'iara.sniffer.updates.default_store',return_value=root.parent/'isolated-store'),patch(
                'scripts.sniffer_record.run_capture',side_effect=capture),patch(
                'scripts.sniffer_record.save',side_effect=save) as saver,patch(
                'scripts.sniffer_record.decode',return_value={'records':6},side_effect=decode_error),redirect_stdout(io.StringIO()):
            result=record(root,previous,root/'wow.exe',3)
        return result,saver

    def test_session_saved_once_and_success_receipted(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'record';r,s=self.call(root)
            self.assertTrue(r['complete']);s.assert_called_once()
            self.assertEqual(json.loads((root/'decode-receipt.json').read_text()),r)

    def test_not_initialized_never_claims_decode_success(self):
        with tempfile.TemporaryDirectory() as d:
            r,s=self.call(Path(d)/'record',ValueError('session_not_initialized'))
            self.assertFalse(r['complete']);self.assertEqual(r['code'],'session_not_captured')

    def test_corrupt_traffic_keeps_capture_but_does_not_claim_pkt(self):
        with tempfile.TemporaryDirectory() as d:
            r,s=self.call(Path(d)/'record',decode_error=ValueError('authentication_failed'))
            self.assertFalse(r['complete']);self.assertFalse(r['captures'][0]['ok'])

    def test_fingerprint_failure_is_not_retried(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'session_profile_mismatch'):
                self.call(Path(d)/'record',ValueError('session_profile_mismatch'))
