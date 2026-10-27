import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from iara.sniffer.catalog import canonical,sign,verify,SCHEMA
from iara.sniffer.updates import apply,installed,update_lock,safe_store,fetch
from iara.sniffer.profiles import active_profiles,select_profile
from iara.sniffer.windows_session import read_session
from tests import test_sniffer_windows_session as memory_tests

NOW=1792800000


def catalog(build=70575,revision=1):
    return {'schema':SCHEMA,'channel':'staff','revision':revision,'engine_abi':1,
            'issued_at':NOW,'expires_at':NOW+86400,'profiles':[{
                'build':build,'version':f'12.1.5.{build}','image_sha256':'a'*64,'protocol':'continued-v1',
                'root_rva':0x4a50750,'vtable_rva':0x40f8d00,'session_offset':0x48,
                'slots_offset':0x231,'slot_stride':0x148,'slot_count':4,
                'compressed_opcode':0x4c000e,'bundle_opcode':0x4c000d,
                'proof':{'receipt_sha256':'b'*64,'authenticated_frames':209,'pkt_records':357,'reviewed':True}}]}


class CatalogTests(unittest.TestCase):
    def setUp(self):self.key=Ed25519PrivateKey.generate();self.pub=self.key.public_key().public_bytes_raw()
    def seal(self,v):return canonical({'signed':v,'signature':self.key.sign(canonical(v)).hex()})
    def test_signature_and_tamper(self):
        raw=sign(catalog(),self.key);self.assertEqual(verify(raw,self.pub,now=NOW)['revision'],1)
        with self.assertRaisesRegex(ValueError,'signature'):verify(raw.replace(b'70575',b'70576'),self.pub,now=NOW)
        with self.assertRaises(ValueError):verify(raw,bytes(32),now=NOW)
    def test_duplicate_fields_are_rejected(self):
        raw=sign(catalog(),self.key).replace(b'"revision":1',b'"revision":1,"revision":1')
        with self.assertRaisesRegex(ValueError,'duplicate'):verify(raw,self.pub,now=NOW)
    def test_expiry_future_and_lifetime(self):
        raw=sign(catalog(),self.key)
        with self.assertRaisesRegex(ValueError,'expired'):verify(raw,self.pub,now=NOW+86400)
        with self.assertRaisesRegex(ValueError,'future'):verify(raw,self.pub,now=NOW-301)
        v=catalog();v['expires_at']=NOW+91*86400
        with self.assertRaisesRegex(ValueError,'lifetime'):verify(self.seal(v),self.pub,now=NOW)
    def test_strict_data_only_bounds_and_proof(self):
        for field,value in [('root_rva',0),('vtable_rva',2**32),('slot_count',999),('slot_stride',True),
                            ('protocol','execute-python'),('image_sha256','wrong'),('version','12.1.5.999')]:
            v=catalog();v['profiles'][0][field]=value
            with self.assertRaises(ValueError):verify(self.seal(v),self.pub,now=NOW)
        for field,value in [('reviewed',False),('authenticated_frames',0),('pkt_records',True)]:
            v=catalog();v['profiles'][0]['proof'][field]=value
            with self.assertRaises(ValueError):verify(self.seal(v),self.pub,now=NOW)
        v=catalog();v['profiles'][0]['command']='payload'
        with self.assertRaises(ValueError):verify(self.seal(v),self.pub,now=NOW)
    def test_channel_abi_and_duplicate_build(self):
        for field,value in [('engine_abi',2),('channel','public'),('revision',True)]:
            v=catalog();v[field]=value
            with self.assertRaises(ValueError):verify(self.seal(v),self.pub,now=NOW)
        v=catalog();v['profiles']*=2
        with self.assertRaisesRegex(ValueError,'duplicate_profile'):verify(self.seal(v),self.pub,now=NOW)
    def test_install_rollback_conflict_and_atomic_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);raw=sign(catalog(revision=2),self.key)
            self.assertTrue(apply(raw,root,self.pub,now=NOW)['updated'])
            self.assertFalse(apply(raw,root,self.pub,now=NOW)['updated'])
            with self.assertRaisesRegex(ValueError,'rollback'):apply(sign(catalog(),self.key),root,self.pub,now=NOW)
            v=catalog(revision=2);v['profiles'][0]['root_rva']+=8
            with self.assertRaisesRegex(ValueError,'conflict'):apply(sign(v,self.key),root,self.pub,now=NOW)
            with patch('iara.sniffer.updates.os.replace',side_effect=OSError('synthetic disk error')):
                with self.assertRaises(OSError):apply(sign(catalog(revision=3),self.key),root,self.pub,now=NOW)
            self.assertEqual((root/'installed.json').read_bytes(),raw);self.assertFalse(list(root.glob('*.tmp')))
    def test_installed_profiles_work_offline_after_catalog_expiry(self):
        with tempfile.TemporaryDirectory() as d:
            apply(sign(catalog(),self.key),Path(d),self.pub,now=NOW)
            with patch('iara.sniffer.updates.time.time',return_value=NOW+86401):
                self.assertEqual(len(installed(d,self.pub)),1)
    def test_capture_lock_blocks_installation(self):
        with tempfile.TemporaryDirectory() as d:
            root=safe_store(d)
            with update_lock(root):
                with self.assertRaisesRegex(ValueError,'update_in_progress'):apply(sign(catalog(),self.key),root,self.pub,now=NOW)
            self.assertFalse((root/'installed.json').exists())
    def test_unknown_build_not_implicitly_promoted_and_profile_data_reused(self):
        with tempfile.TemporaryDirectory() as d:
            with patch('iara.sniffer.updates.default_store',return_value=Path(d)),patch('iara.sniffer.trust.PUBLIC_KEY',self.pub):
                with self.assertRaisesRegex(ValueError,'unsupported_build'):select_profile(99999)
                apply(sign(catalog(build=99999),self.key),Path(d),self.pub,now=NOW)
                profile=select_profile(99999,image_sha256='a'*64)
                b,r,values=memory_tests.SessionMemoryTests().fixture()
                self.assertEqual(len(read_session(lambda a,n:values[(a,n)],b,profile.layout)['keys']),1)
                with self.assertRaisesRegex(ValueError,'fingerprint_mismatch'):select_profile(99999,image_sha256='c'*64)
    def test_network_url_boundaries(self):
        for url in ['http://example.com/catalog','https://user:pass@example.com/a','https://example.com:444/a',
                    'file:///a','https://example.com/a?secret=1','https://example.com/a#x']:
            with self.assertRaisesRegex(ValueError,'invalid_update_url'):fetch(url)
