from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts.sniffer_decode_pcap import main
from tests.test_sniffer_replay import fixture,pcap,CLIENT,SERVER,KEY


class DecodeCLITests(unittest.TestCase):
    def run_cli(self,root,manifest,experimental=True):
        (root/'test.pcap').write_bytes(pcap(fixture()))
        (root/'private.json').write_text(json.dumps(manifest))
        args=['sniffer_decode_pcap',str(root/'test.pcap'),str(root/'private.json'),str(root/'out.pkt')]
        if experimental:args+=['--experimental']
        out=io.StringIO()
        with patch('sys.argv',args),redirect_stdout(out):code=main()
        text=out.getvalue()
        self.assertNotIn(KEY.hex(),text)
        return code,json.loads(text)

    def manifest(self):
        return {'build':70575,'client':CLIENT,'server':SERVER,'encrypted_from':{'client':1,'server':1},
                'keys':{'client':KEY.hex(),'server':KEY.hex()}}

    def test_profile_evidence_does_not_claim_this_input_is_live(self):
        with tempfile.TemporaryDirectory() as d:
            code,r=self.run_cli(Path(d),self.manifest())
            self.assertEqual(code,0);self.assertTrue(r['build_compatibility_verified'])
            self.assertFalse(r['live_capture_verified'])

    def test_unverified_build_requires_explicit_selection(self):
        with tempfile.TemporaryDirectory() as d:
            manifest=self.manifest();manifest['build']=69875
            code,r=self.run_cli(Path(d),manifest,False)
            self.assertEqual(code,1);self.assertEqual(r['code'],'build_requires_validation')

    def test_fixed_error_without_key_or_network_details(self):
        with tempfile.TemporaryDirectory() as d:
            v=self.manifest();v['keys']['client']=(b'x'*32).hex()
            code,r=self.run_cli(Path(d),v)
            self.assertEqual(code,1);self.assertEqual(r['code'],'authentication_failed')
            self.assertFalse((Path(d)/'out.pkt').exists())
