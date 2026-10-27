import io
from pathlib import Path
import struct
import tempfile
import unittest
import zlib
from iara.sniffer.replay import replay
from iara.sniffer.decoder import DirectionDecoder
from iara.sniffer.profiles import select_profile
from tests.test_sniffer_crypto import encrypted
from tests.test_sniffer_world import body,bundle,comp,greet,C,B

KEY=bytes(range(32));CLIENT=('127.0.0.1',12345);SERVER=('127.0.0.1',3724)
PROFILE=select_profile(70575,experimental=True)


def datagram(direction,sequence,payload=b'',flags=0x18):
    a,b=(CLIENT,SERVER) if direction=='client' else (SERVER,CLIENT)
    tcp=struct.pack('!HHIIBBHHH',a[1],b[1],sequence,0,0x50,flags,65535,0,0)+payload
    return struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),1,0x4000,64,6,0,
                       b'\x7f\0\0\1',b'\x7f\0\0\1')+tcp


def pcap(packets):
    return struct.pack('<IHHiiII',0xa1b2c3d4,2,4,0,0,262144,101)+b''.join(
        struct.pack('<IIII',1792796400,index*1000,len(p),len(p))+p for index,p in enumerate(packets))


def fixture():
    packets=[datagram('client',100,flags=2),datagram('server',200,flags=0x12)]
    z=zlib.compressobj(wbits=-15)
    values={'client':[body(7,b'plain'),body(8,b'private synthetic')],
            'server':[body(9,b'plain'),comp(z,bundle([body(10,b'abc'*100),body(11)]))]}
    sequences={'client':101,'server':201}
    for d in ('client','server'):
        wire=greet(d)
        for n,v in enumerate(values[d]):
            tag,data=(bytes(12),v) if n==0 else encrypted(KEY,n,d,v)
            wire+=struct.pack('<I',len(data))+tag+data
        # Deliberately capture the tail before the beginning, then retransmit.
        start=sequences[d]
        packets += [datagram(d,start+20,wire[20:]),datagram(d,start,wire[:20]),datagram(d,start,wire[:20])]
        sequences[d]+=len(wire)
    packets += [datagram(d,sequences[d],flags=0x11) for d in ('client','server')]
    return packets


class ReplayTests(unittest.TestCase):
    def test_authenticated_login_bundle_uses_explicit_batch_allowance(self):
        for count,valid in ((8865,True),(16385,False)):
            decoder=DirectionDecoder(PROFILE,'server',encrypted_from=0,key=KEY)
            plain=comp(zlib.compressobj(wbits=-15),bundle([body(42,b'fixture')]*count))
            tag,wire=encrypted(KEY,0,'server',plain)
            data=greet('server')+struct.pack('<I',len(wire))+tag+wire
            if valid:
                messages=decoder.feed(data);decoder.finish()
                self.assertEqual(messages,[(42,b'fixture')]*count)
            else:
                with self.assertRaisesRegex(ValueError,'message_limit'):decoder.feed(data)
                self.assertTrue(decoder.failed)

    def call(self,raw,out,**kw):
        args=dict(profile=PROFILE,client=CLIENT,server=SERVER,keys={'client':KEY,'server':KEY},
                  encrypted_from={'client':1,'server':1})
        args.update(kw)
        return replay(io.BytesIO(raw),out,**args)

    def test_full_authenticated_compressed_reordered_capture(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'capture.pkt';r=self.call(pcap(fixture()),out)
            self.assertEqual(r['records'],5);self.assertEqual(r['world_frames'],4)
            self.assertTrue(r['build_compatibility_verified']);self.assertFalse(r['live_capture_verified'])
            self.assertTrue(r['transport_complete']);self.assertEqual(r['authenticated_frames'],2)
            self.assertFalse(Path(str(out)+'.partial').exists())
            # Independent binary container reading; verify exact decoded payloads.
            data=out.read_bytes();self.assertEqual(struct.unpack_from('<I',data,6)[0],70575)
            offset=66;messages=[]
            while offset<len(data):
                magic,conn,ticks,extra,length,op=struct.unpack_from('<IiIiiI',data,offset)
                messages.append((op,data[offset+24:offset+20+length]));offset+=20+length
            self.assertEqual(messages,[(7,b'plain'),(8,b'private synthetic'),(9,b'plain'),(10,b'abc'*100),(11,b'')])
            self.assertEqual(offset,len(data))

    def test_lso_v2_buffer_preserves_authenticated_payload(self):
        packets=[datagram('client',100,flags=2),datagram('server',200,flags=0x12)]
        for direction,start in (('client',101),('server',201)):
            plain=body(7,b'plain');payload=body(8,bytes(range(256))*8)
            tag,ciphertext=encrypted(KEY,1,direction,payload)
            wire=greet(direction)+struct.pack('<I',len(plain))+bytes(12)+plain
            wire+=struct.pack('<I',len(ciphertext))+tag+ciphertext
            raw=bytearray(datagram(direction,start,wire));raw[2:4]=bytes(2)
            packets.extend([bytes(raw),datagram(direction,start+len(wire),flags=0x11)])
        ethernet=[bytes(12)+b'\x08\x00'+p for p in packets]
        raw=bytearray(pcap(ethernet));raw[20:24]=struct.pack('<I',1)
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'offload.pkt';r=self.call(bytes(raw),out)
            self.assertEqual(r['records'],4);self.assertEqual(r['authenticated_frames'],2)
            self.assertTrue(r['transport_complete'])
            self.assertEqual(out.read_bytes().count(bytes(range(256))*8),2)

    def test_missing_syn_fin_or_gap_does_not_finalize(self):
        all_packets=fixture()
        for packets in (all_packets[1:],all_packets[:-1],all_packets[:3]+all_packets[5:]):
            with tempfile.TemporaryDirectory() as d:
                out=Path(d)/'out.pkt'
                with self.assertRaises(ValueError):self.call(pcap(packets),out)
                self.assertFalse(out.exists());self.assertTrue(Path(str(out)+'.partial').exists())

    def test_wrong_key_or_boundary_never_commits(self):
        for kw in ({'keys':{'client':b'x'*32,'server':KEY}},
                   {'encrypted_from':{'client':0,'server':1}},
                   {'encrypted_from':{'client':2,'server':1}}):
            with tempfile.TemporaryDirectory() as d:
                out=Path(d)/'out.pkt'
                with self.assertRaises(ValueError):self.call(pcap(fixture()),out,**kw)
                self.assertFalse(out.exists())

    def test_reset_and_conflicting_syn(self):
        for extra in (datagram('client',100,flags=4),datagram('client',999,flags=2)):
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):self.call(pcap(fixture()+[extra]),Path(d)/'out.pkt')

    def test_empty_unrelated_and_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'out.pkt'
            with self.assertRaisesRegex(ValueError,'selected_connection_not_found'):self.call(pcap([]),out)
            out.write_bytes(b'preserve')
            with self.assertRaises(FileExistsError):self.call(pcap(fixture()),out)
            self.assertEqual(out.read_bytes(),b'preserve')

    def test_profiles_never_assume_future_build(self):
        for build in (70576,True,69875):
            with self.assertRaises(ValueError):select_profile(build)
        with self.assertRaises(ValueError):select_profile(70575,experimental=True,image_sha256='wrong')
        self.assertTrue(PROFILE.key_locator_verified)
        self.assertEqual(select_profile(70575),PROFILE)

    def test_no_key_and_corruption_close_decoder(self):
        d=DirectionDecoder(PROFILE,'client',encrypted_from=0)
        with self.assertRaisesRegex(ValueError,'session_key_required'):d.feed(greet('client')+struct.pack('<I',4)+bytes(12)+body(1))
        with self.assertRaisesRegex(ValueError,'decoder_unavailable'):d.feed(b'')

    def test_timestamp_precision_and_invalid_fraction(self):
        from iara.sniffer.pcap import iter_tcp
        data=bytearray(pcap([datagram('client',100)]));data[28:32]=struct.pack('<I',123456)
        self.assertEqual(next(iter_tcp(io.BytesIO(data))).timestamp_ns,1792796400000000000+123456000)
        data[:4]=b'\x4d\x3c\xb2\xa1'
        self.assertEqual(next(iter_tcp(io.BytesIO(data))).timestamp_ns,1792796400000000000+123456)
        data[28:32]=struct.pack('<I',1000000000)
        with self.assertRaisesRegex(ValueError,'invalid_timestamp'):list(iter_tcp(io.BytesIO(data)))

    def test_pkt_preserves_absolute_milliseconds_across_second_boundary(self):
        # The PKT header has whole seconds; record ticks must retain the first
        # PCAP packet's fractional second rather than shift the entire flow.
        for shift_us in (123456, 999999):
            with self.subTest(shift_us=shift_us), tempfile.TemporaryDirectory() as d:
                raw=bytearray(pcap(fixture()));offset=24
                while offset<len(raw):
                    sec,usec,size,_=struct.unpack_from('<IIII',raw,offset)
                    sec,rem=divmod(sec*1000000+usec+shift_us,1000000)
                    struct.pack_into('<II',raw,offset,sec,rem);offset+=16+size
                out=Path(d)/'timed.pkt';self.call(bytes(raw),out)
                data=out.read_bytes();sec,tick0=struct.unpack_from('<II',data,54)
                observed=[];offset=66
                while offset<len(data):
                    _,_,tick,extra,length=struct.unpack_from('<IiIii',data,offset)
                    observed.append(sec*1000+((tick-tick0)&0xffffffff))
                    offset+=20+extra+length
                expected=[1792796400000+(shift_us+i*1000)//1000 for i in (3,3,6,6,6)]
                self.assertEqual(observed,expected)

    def test_multiple_frames_cannot_multiply_memory_without_bound(self):
        for limits in ({'max_batch_bytes':10},{'max_batch_messages':1}):
            d=DirectionDecoder(PROFILE,'client',encrypted_from=100,**limits)
            packet=struct.pack('<I',8)+bytes(12)+body(1,b'abcd')
            with self.assertRaisesRegex(ValueError,'decoded_batch_limit'):d.feed(greet('client')+packet*2)
            with self.assertRaises(ValueError):d.feed(b'')
