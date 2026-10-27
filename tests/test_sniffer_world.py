"""World-packet framing and decompression regressions."""
import random
import struct
import unittest
import zlib
from iara.sniffer.world import WorldFramer, BodyDecoder

C=0x4c000e; B=0x4c000d; SEED=0x9827d8f1
def body(op,p=b''):return struct.pack('<I',op)+p
def frame(v):return struct.pack('<I',len(v))+bytes(12)+v
def greet(d):return ('WORLD OF WARCRAFT CONNECTION - '+('CLIENT TO SERVER' if d=='client' else 'SERVER TO CLIENT')+' - V2\n').encode()
def comp(z,v):
    c=z.compress(v)+z.flush(zlib.Z_SYNC_FLUSH)
    return body(C,struct.pack('<III',len(v),zlib.adler32(v,SEED),zlib.adler32(c,SEED))+c)
def bundle(values):return body(B,b''.join(struct.pack('<H',len(v)-4)+v for v in values))

class WorldTests(unittest.TestCase):
    def test_random_splits(self):
        rng=random.Random(70575)
        values=[body(i,rng.randbytes(i)) for i in range(4,104)]
        for direction in ('client','server'):
            wire=greet(direction)+b''.join(map(frame,values))
            for _ in range(20):
                f=WorldFramer(direction,max_body=128);out=[];pos=0
                while pos<len(wire):
                    count=rng.randint(1,250);out+=f.feed(wire[pos:pos+count]);pos+=count
                    self.assertLessEqual(f.buffered_bytes,144)
                self.assertEqual(out,[(bytes(12),v) for v in values]);f.finish()

    def test_every_truncation(self):
        wire=greet('client')+frame(body(8,b'abc'))
        for end in range(len(wire)):
            if end==len(greet('client')):continue
            f=WorldFramer('client');f.feed(wire[:end])
            with self.assertRaises(ValueError):f.finish()
            with self.assertRaises(ValueError):f.feed(b'')

    def test_length_bounds(self):
        for n in (0,1,3,101,2**32-1):
            f=WorldFramer('server',max_body=100)
            with self.assertRaises(ValueError):f.feed(greet('server')+struct.pack('<I',n))
            with self.assertRaises(ValueError):f.feed(b'')

    def test_greeting_and_closed(self):
        f=WorldFramer('server')
        with self.assertRaises(ValueError):f.feed(greet('client'))
        f=WorldFramer('client');f.feed(greet('client'));f.finish()
        with self.assertRaises(ValueError):f.finish()
        with self.assertRaises(ValueError):f.feed(b'')

    def test_type_and_chunk_limits(self):
        class Bytes(bytes):pass
        for data in (None,bytearray(),Bytes(),bytes(149)):
            f=WorldFramer('client',max_body=4)
            with self.assertRaises(ValueError):f.feed(data)
        for n in (True,3,16777217,'4'):
            with self.assertRaises(ValueError):WorldFramer('client',n)

    def test_compression_dictionary(self):
        rng=random.Random(70575);data=rng.randbytes(15000)
        z=zlib.compressobj(wbits=-15);d=BodyDecoder(C,B)
        one=comp(z,body(100,data));two=comp(z,body(200,data))
        self.assertLess(len(two),200)
        self.assertEqual(d.decode(one),[(100,data)])
        self.assertEqual(d.decode(two),[(200,data)])
        with self.assertRaises(ValueError):BodyDecoder(C,B).decode(two)

    def test_checksum_and_sizes(self):
        v=comp(zlib.compressobj(wbits=-15),body(12,b'x'*1000))
        for offset in (4,8,12,18):
            changed=bytearray(v);changed[offset]^=1;d=BodyDecoder(C,B)
            with self.assertRaises(ValueError):d.decode(bytes(changed))
            with self.assertRaises(ValueError):d.decode(body(1))

    def test_inflate_bomb(self):
        v=comp(zlib.compressobj(wbits=-15),body(12,bytes(100000)))
        with self.assertRaises(ValueError):BodyDecoder(C,B,max_output=4096).decode(v)

    def test_unfinished_flush_and_finished_stream(self):
        v=body(10,b'abc'*100);z=zlib.compressobj(wbits=-15)
        c=z.compress(v)+z.flush(zlib.Z_FINISH)+b'\0\0\xff\xff'
        wire=body(C,struct.pack('<III',len(v),zlib.adler32(v,SEED),zlib.adler32(c,SEED))+c)
        with self.assertRaises(ValueError):BodyDecoder(C,B).decode(wire)
        wire=comp(zlib.compressobj(wbits=-15),v)[:-1]
        with self.assertRaises(ValueError):BodyDecoder(C,B).decode(wire)

    def test_nested_and_empty_bundles(self):
        d=BodyDecoder(C,B)
        self.assertEqual(d.decode(bundle([body(1,b'a'),bundle([body(2,b'b')]),bundle([])])),[(1,b'a'),(2,b'b')])
        z=zlib.compressobj(wbits=-15)
        self.assertEqual(d.decode(comp(z,bundle([body(3,b'c'),body(4)]))),[(3,b'c'),(4,b'')])

    def test_bundle_truncation(self):
        v=bundle([body(7,b'abcdef')])
        for end in range(5,len(v)):
            with self.assertRaises(ValueError):BodyDecoder(C,B).decode(v[:end])

    def test_depth_count_and_total_bytes(self):
        v=body(1)
        for _ in range(10):v=bundle([v])
        with self.assertRaises(ValueError):BodyDecoder(C,B,max_depth=4).decode(v)
        with self.assertRaises(ValueError):BodyDecoder(C,B,max_messages=2).decode(bundle([body(1)]*3))
        with self.assertRaises(ValueError):BodyDecoder(C,B,max_output=100).decode(bundle([body(1,b'x'*50)]))

    def test_options_and_payload_types(self):
        for args in [(True,B),(C,C),(-1,B),(2**32,B)]:
            with self.assertRaises(ValueError):BodyDecoder(*args)
        for kw in ({'max_output':True},{'max_messages':0},{'max_messages':16385},{'max_depth':17}):
            with self.assertRaises(ValueError):BodyDecoder(C,B,**kw)
        for v in (None,bytearray(b'abcd'),b'abc'):
            with self.assertRaises(ValueError):BodyDecoder(C,B).decode(v)
