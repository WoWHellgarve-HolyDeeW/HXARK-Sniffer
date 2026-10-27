import io
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest

from iara.capture_inspector import scan, inspect_file
from tests.pkt_fixture import fixture


class CaptureInspectorTests(unittest.TestCase):
    def test_empty_and_directions(self):
        self.assertEqual(scan(io.BytesIO(fixture()))['records'],0)
        data=fixture(records=[(0x47534d53,b'a',b'e'),(0x47534d43,b'b',b''),(999,b'c',b'')])
        r=scan(io.BytesIO(data))
        self.assertEqual(r['directions'],dict(server=1,client=1,unknown=1))
        self.assertEqual(r['payload_bytes'],3);self.assertTrue(r['complete'])

    def test_limits_are_explicit(self):
        data=fixture(records=[(1,b'a',b''),(1,b'b',b'')])
        r=scan(io.BytesIO(data),1)
        self.assertFalse(r['complete']);self.assertEqual(r['next_offset'],91)

    def test_short_reads_and_no_private_data_read(self):
        class Watched(io.BytesIO):
            def read(self,n=-1):
                self.assertions(n)
                return super().read(min(n,1))
            def assertions(self,n):
                if not 1<=n<=8:raise AssertionError('unbounded')
                p=self.tell()
                if not any(lo<=p and p+n<=hi for lo,hi in [(0,10),(62,66),(67,71),(79,87)]):
                    raise AssertionError('private bytes requested')
        data=fixture(records=[(0x47534d53,b'private payload',b'private extra')],extra=b'x')
        self.assertTrue(scan(Watched(data))['complete'])

    def test_record_truncations_rejected(self):
        data=fixture(records=[(1,b'abcdef',b'e')])
        for end in range(67,len(data)):
            with self.subTest(end=end),self.assertRaisesRegex(ValueError,'malformed_file'):
                scan(io.BytesIO(data[:end]))

    def test_invalid_lengths_rejected(self):
        for offset,n in [(62,-1),(78,-1),(82,-1),(82,0),(82,3),(78,2**31-1),(82,2**31-1)]:
            data=bytearray(fixture(records=[(1,b'abc',b'')]))
            struct.pack_into('<i',data,offset,n)
            with self.subTest(offset=offset,n=n),self.assertRaises(ValueError):scan(io.BytesIO(data))

    def test_invalid_limit(self):
        for n in (0,-1,False,True,1.0,'4',1000001):
            with self.subTest(n=n),self.assertRaisesRegex(ValueError,'invalid_limit'):scan(io.BytesIO(fixture()),n)

    def test_bad_seek_does_not_hang(self):
        class Bad(io.BytesIO):
            def seek(self,offset,whence=0):return 999
        with self.assertRaises(ValueError):scan(Bad(fixture()))

    def test_random_valid_containers(self):
        rng=random.Random(231026)
        for i in range(200):
            records=[(rng.choice([1,0x47534d43,0x47534d53]),rng.randbytes(rng.randrange(100)),rng.randbytes(rng.randrange(12))) for _ in range(rng.randrange(20))]
            data=fixture(build=i,records=records,extra=rng.randbytes(rng.randrange(30)))
            r=scan(io.BytesIO(data));self.assertTrue(r['complete']);self.assertEqual(r['build'],i)
            self.assertEqual(r['records'],len(records));self.assertEqual(r['payload_bytes'],sum(len(p) for d,p,e in records))

    def test_regular_file_receipt_and_cli_partial(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'sample.pkt';p.write_bytes(fixture(records=[(1,b'a',b''),(1,b'b',b'')]))
            self.assertEqual(inspect_file(p)['coverage'],'structure_only')
            r=subprocess.run([sys.executable,'-m','iara.capture_inspector',str(p),'--max-records','1'],capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,3);self.assertFalse(json.loads(r.stdout)['complete'])



if __name__=='__main__':unittest.main()
