import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from iara.sniffer.maintenance import triage,prepare_job
from iara.sniffer.profiles import PROFILES
from iara.sniffer.catalog import verify
from scripts.sniffer_publish_catalog import release
from scripts.sniffer_staff import main
from tests.test_sniffer_updates import catalog,NOW


class MaintenanceTests(unittest.TestCase):


    def test_job_is_technical_only_and_does_not_promote_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            with patch('iara.sniffer.maintenance.active_profiles',return_value={}):observation=triage(99999,'a'*64)
            job=prepare_job(observation,Path(d)/'job')
            self.assertFalse(job['network_capture_uploaded'])
            self.assertFalse(job['observation']['capture_allowed'])
            self.assertTrue(job['release_gate']['live_authenticated_capture'])
            self.assertEqual(set(Path(d,'job').iterdir()),{Path(d,'job/job.json')})
            for field,value in [('capture_allowed',True),('next_action','publish'),('schema','untrusted'),('private_data_included',True)]:
                bad={**observation,field:value}
                with self.assertRaises(ValueError):prepare_job(bad,Path(d)/field)

    def test_signer_requires_matching_reviewed_live_evidence(self):
        profile=catalog()['profiles'][0];key=Ed25519PrivateKey.generate()
        receipt=dict(build=70575,authenticated_frames=209,records=357,live_capture_verified=True,
            transport_complete=True,container_complete=True,build_compatibility_verified=True,
            handshake_validated=True,session_uploaded=False,scope='one_complete_continued_session_connection',
            independent_container_check={'complete':True,'records':357,'build':70575})
        raw=json.dumps(receipt).encode();profile['proof']['receipt_sha256']=hashlib.sha256(raw).hexdigest()
        signed=release(profile,raw,key,revision=1,issued_at=NOW)
        self.assertEqual(verify(signed,key.public_key().public_bytes_raw(),now=NOW)['revision'],1)
        other=copy.deepcopy(profile);other['build']=99999;other['version']='12.1.5.99999'
        other_receipt={**receipt,'build':99999,'independent_container_check':{'complete':True,'records':357,'build':99999}}
        other_raw=json.dumps(other_receipt).encode();other['proof']['receipt_sha256']=hashlib.sha256(other_raw).hexdigest()
        updated=release(other,other_raw,key,revision=2,issued_at=NOW,previous_raw=signed)
        self.assertEqual([p['build'] for p in verify(updated,key.public_key().public_bytes_raw(),now=NOW)['profiles']],[70575,99999])
        with self.assertRaisesRegex(ValueError,'revision'):
            release(profile,raw,key,revision=1,issued_at=NOW,previous_raw=signed)
        with self.assertRaisesRegex(ValueError,'evidence'):release(profile,raw+b' ',key,revision=1,issued_at=NOW)
        for field in ('live_capture_verified','transport_complete','container_complete','handshake_validated'):
            bad={**receipt,field:False};raw=json.dumps(bad).encode();profile['proof']['receipt_sha256']=hashlib.sha256(raw).hexdigest()
            with self.assertRaisesRegex(ValueError,'evidence'):release(profile,raw,key,revision=1,issued_at=NOW)
        receipt['independent_container_check']['complete']=False
        raw=json.dumps(receipt).encode();profile['proof']['receipt_sha256']=hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError,'independent'):release(profile,raw,key,revision=1,issued_at=NOW)

    def test_windowed_cli_receipt_and_incomplete_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            result=Path(d)/'version.json'
            with patch('sys.stdout',None):self.assertEqual(main(['--result',str(result),'version']),0)
            self.assertEqual(json.loads(result.read_text())['channel'],'beta')
            with patch('sys.stdout',None):self.assertEqual(main(['--result',str(result),'version']),1)
            with patch('scripts.sniffer_staff.record',return_value={'complete':False}),patch('sys.stdout',None):
                self.assertEqual(main(['record',str(Path(d)/'capture'),'--previous',str(Path(d)/'info.json')]),1)
