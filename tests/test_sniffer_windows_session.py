import json
import os
import struct
import unittest
from iara.sniffer.windows_session import read_session,ROOT_RVA,VTABLE_RVA
from iara.sniffer.session_keys import derive_encryption
from iara.sniffer.local_secrets import protect,unprotect


class SessionMemoryTests(unittest.TestCase):
    def fixture(self):
        base=0x140000000;root=0x200000000;session=b's'*40;c=b'c'*32;s=b't'*32
        values={(base+ROOT_RVA,8):struct.pack('<Q',root),(root,8):struct.pack('<Q',base+VTABLE_RVA),
                (root+0x48,40):session}
        for n in range(4):values[(root+n*0x148+0x231,96)]=bytes(96)
        values[(root+0x231,96)]=c+s+derive_encryption(session,c,s)
        return base,root,values
    def test_only_evidenced_fields_read(self):
        base,root,v=self.fixture();calls=[]
        def read(a,n):calls.append((a,n));return v[(a,n)]
        result=read_session(read,base)
        self.assertEqual(len(result['keys']),1);self.assertEqual(result['keys'][0]['slot'],0)
        self.assertEqual(len(calls),14);self.assertTrue(all(n<=96 for a,n in calls))
        self.assertNotIn('material',result)
    def test_null_root_and_wrong_type(self):
        for field,value in [('root',bytes(8)),('vtable',bytes(8))]:
            b,r,v=self.fixture();v[(b+ROOT_RVA,8) if field=='root' else (r,8)]=value
            with self.assertRaises(ValueError):read_session(lambda a,n:v[(a,n)],b)
    def test_key_mismatch(self):
        b,r,v=self.fixture();x=v[(r+0x231,96)];v[(r+0x231,96)]=x[:-1]+bytes([x[-1]^1])
        with self.assertRaisesRegex(ValueError,'key_mismatch'):read_session(lambda a,n:v[(a,n)],b)
    def test_read_race(self):
        b,r,v=self.fixture();seen={}
        def read(a,n):
            seen[a]=seen.get(a,0)+1
            return bytes(n) if a==r+0x48 and seen[a]>1 else v[(a,n)]
        with self.assertRaisesRegex(ValueError,'changed_during_read'):read_session(read,b)
    def test_partial_read_refused(self):
        b,r,v=self.fixture()
        with self.assertRaisesRegex(ValueError,'memory_unavailable'):read_session(lambda a,n:v[(a,n)][:-1],b)
    def test_uninitialized(self):
        b,r,v=self.fixture();v[(r+0x231,96)]=bytes(96)
        with self.assertRaisesRegex(ValueError,'not_initialized'):read_session(lambda a,n:v[(a,n)],b)
    @unittest.skipUnless(os.name=='nt','Windows DPAPI')
    def test_dpapi_roundtrip_and_tamper(self):
        plain=b'fictional secret; no game data';sealed=protect(plain)
        self.assertNotIn(plain,sealed);self.assertEqual(unprotect(sealed),plain)
        broken=bytearray(sealed);broken[-1]^=1
        with self.assertRaises(ValueError):unprotect(bytes(broken))
