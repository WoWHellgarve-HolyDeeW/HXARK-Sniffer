import io
import struct
import tempfile
from pathlib import Path
import unittest
from iara.sniffer.handshake import validate_initial_frames,inspect_handshake,MAX_REALM_TICKET
from iara.sniffer.session_keys import derive_encryption
from iara.sniffer.replay import replay
from iara.sniffer.profiles import select_profile
from tests.test_sniffer_replay import datagram,pcap,CLIENT,SERVER
from tests.test_sniffer_crypto import encrypted
from tests.test_sniffer_world import greet

SESSION=bytes(range(40));CC=b'c'*32;SC=b's'*32


def frames(*,initial_auth=False,ticket=b'fictional realm ticket',ipv6=False):
    c=struct.pack('<I',0x440003)+bytes(8)+CC+bytes(40)
    if initial_auth:
        c=(struct.pack('<IQIII',0x440001,0,1,2,3)+CC+bytes(24)+
           bytes([0x80 if ipv6 else 0])+struct.pack('<I',len(ticket))+ticket)
    s=struct.pack('<I',0x4c0000)+bytes(32)+SC+b'\0'
    enable=struct.pack('<I',0x4c0004)+bytes(68)+b'\x80'
    return [(bytes(12),c),(bytes(12),struct.pack('<I',0x440005))],[(bytes(12),s),(bytes(12),enable)]


def capture(*,initial_auth=False,authenticated=True,fragment=False):
    c,s=frames(initial_auth=initial_auth);key=derive_encryption(SESSION,CC,SC)
    packets=[datagram('client',100,flags=2),datagram('server',200,flags=0x12)]
    for d,start,initial in [('client',101,c),('server',201,s)]:
        messages=initial+([encrypted(key,2,d,struct.pack('<I',42)+b'fictional')] if authenticated else [])
        wire=greet(d)+b''.join(struct.pack('<I',len(body))+tag+body for tag,body in messages)
        if fragment:
            # Out-of-order tail, split header/ticket and exact retransmission.
            packets += [datagram(d,start+100,wire[100:]),datagram(d,start,wire[:30]),
                        datagram(d,start+30,wire[30:100]),datagram(d,start+30,wire[30:100])]
        else:packets.append(datagram(d,start,wire))
        packets.append(datagram(d,start+len(wire),flags=0x11))
    return pcap(packets)


class HandshakeTests(unittest.TestCase):
    def test_initial_login_variable_ticket_and_flag(self):
        for length in (0,1,849,MAX_REALM_TICKET):
            for ipv6 in (False,True):
                c,s=frames(initial_auth=True,ticket=b'x'*length,ipv6=ipv6)
                self.assertEqual(validate_initial_frames(c,s,SESSION),derive_encryption(SESSION,CC,SC))

    def test_initial_login_rejects_invalid_lengths_padding_and_opcode(self):
        c,s=frames(initial_auth=True);body=c[0][1]
        bad=[body[:n] for n in (4,23,55,79,80,84,len(body)-1)]
        bad += [body+b'x',body[:80]+b'\x01'+body[81:],body[:80]+b'\x81'+body[81:],
                body[:81]+struct.pack('<I',0xffffffff)+body[85:],
                struct.pack('<I',0x440003)+body[4:],
                struct.pack('<I',0x440002)+body[4:],
                frames(initial_auth=True,ticket=b'x'*(MAX_REALM_TICKET+1))[0][0][1]]
        for changed in bad:
            with self.subTest(length=len(changed)):
                c[0]=(bytes(12),changed)
                with self.assertRaisesRegex(ValueError,'unsupported_authentication_layout'):
                    validate_initial_frames(c,s,SESSION)

    def test_initial_login_still_requires_explicit_enable_ack_and_plain_handshake(self):
        for direction,index in [('client',0),('client',1),('server',0),('server',1)]:
            c,s=frames(initial_auth=True);v=c if direction=='client' else s
            tag,body=v[index];v[index]=(b'x'*12,body)
            with self.assertRaisesRegex(ValueError,'unexpected_handshake'):validate_initial_frames(c,s,SESSION)
        for index in (0,1):
            c,s=frames(initial_auth=True);s[index]=(bytes(12),s[index][1][:-1])
            with self.assertRaises(ValueError):validate_initial_frames(c,s,SESSION)
        c,s=frames(initial_auth=True);c[1]=(bytes(12),struct.pack('<I',0x440006))
        with self.assertRaisesRegex(ValueError,'ack_not_confirmed'):validate_initial_frames(c,s,SESSION)

    def test_initial_login_complete_wire_and_wrong_session(self):
        raw=capture(initial_auth=True)
        for session,valid in ((SESSION,True),(b'x'*40,False)):
            key,b=inspect_handshake(io.BytesIO(raw),client=CLIENT,server=SERVER,session=session)
            self.assertEqual(b,{'client':2,'server':2})
            with tempfile.TemporaryDirectory() as d:
                target=Path(d)/'initial.pkt'
                kw=dict(profile=select_profile(70575,experimental=True),client=CLIENT,server=SERVER,
                        keys={'client':key,'server':key},encrypted_from=b)
                if valid:
                    r=replay(io.BytesIO(raw),target,**kw)
                    self.assertEqual(r['records'],6);self.assertEqual(r['authenticated_frames'],2)
                    self.assertTrue(r['transport_complete'])
                else:
                    with self.assertRaisesRegex(ValueError,'authentication_failed'):replay(io.BytesIO(raw),target,**kw)
                    self.assertFalse(target.exists())

    def test_initial_login_split_and_reordered_retransmission(self):
        raw=capture(initial_auth=True,fragment=True)
        key,b=inspect_handshake(io.BytesIO(raw),client=CLIENT,server=SERVER,session=SESSION)
        with tempfile.TemporaryDirectory() as d:
            r=replay(io.BytesIO(raw),Path(d)/'split.pkt',profile=select_profile(70575),
                     client=CLIENT,server=SERVER,keys={'client':key,'server':key},encrypted_from=b)
            self.assertEqual(r['records'],6);self.assertEqual(r['authenticated_frames'],2)

    def test_plain_handshake_cannot_publish_unverified_key_even_with_fin(self):
        for initial_auth in (False,True):
            raw=capture(initial_auth=initial_auth,authenticated=False)
            key,b=inspect_handshake(io.BytesIO(raw),client=CLIENT,server=SERVER,session=b'x'*40)
            for exited in (False,True):
                with tempfile.TemporaryDirectory() as d:
                    target=Path(d)/'plain.pkt'
                    with self.assertRaisesRegex(ValueError,'no_authenticated_frames'):
                        replay(io.BytesIO(raw),target,profile=select_profile(70575),client=CLIENT,server=SERVER,
                               keys={'client':key,'server':key},encrypted_from=b,process_exited=exited)
                    self.assertFalse(target.exists())

    def test_explicit_control_and_challenges(self):
        c,s=frames();self.assertEqual(validate_initial_frames(c,s,SESSION),derive_encryption(SESSION,CC,SC))
    def test_unknown_auth_or_enable_rejected(self):
        for direction,index in [('client',0),('client',1),('server',0),('server',1)]:
            c,s=frames();v=c if direction=='client' else s;tag,body=v[index]
            for changed in [body[:-1],bytes([body[0]^1])+body[1:]]:
                v[index]=(tag,changed)
                with self.assertRaises(ValueError):validate_initial_frames(c,s,SESSION)
    def test_enable_must_be_enabled(self):
        c,s=frames();s[1]=(bytes(12),s[1][1][:-1]+b'\0')
        with self.assertRaisesRegex(ValueError,'enable_not_confirmed'):validate_initial_frames(c,s,SESSION)
    def test_no_guess_from_nonzero_tag(self):
        c,s=frames();c[0]=(b'x'*12,c[0][1])
        with self.assertRaisesRegex(ValueError,'unexpected_handshake'):validate_initial_frames(c,s,SESSION)
    def test_complete_wire_to_pkt(self):
        raw=capture();key,boundaries=inspect_handshake(io.BytesIO(raw),client=CLIENT,server=SERVER,session=SESSION)
        self.assertEqual(boundaries,{'client':2,'server':2})
        with tempfile.TemporaryDirectory() as d:
            result=replay(io.BytesIO(raw),Path(d)/'test.pkt',profile=select_profile(70575,experimental=True),
                          client=CLIENT,server=SERVER,keys={'client':key,'server':key},encrypted_from=boundaries)
            self.assertEqual(result['records'],6)
    def test_wrong_session_rejected_by_gcm(self):
        raw=capture();key,b=inspect_handshake(io.BytesIO(raw),client=CLIENT,server=SERVER,session=b'x'*40)
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'test.pkt'
            with self.assertRaisesRegex(ValueError,'authentication_failed'):
                replay(io.BytesIO(raw),target,profile=select_profile(70575,experimental=True),client=CLIENT,
                       server=SERVER,keys={'client':key,'server':key},encrypted_from=b)
            self.assertFalse(target.exists())
    def test_missing_handshake(self):
        with self.assertRaisesRegex(ValueError,'handshake_incomplete'):
            inspect_handshake(io.BytesIO(pcap([])),client=CLIENT,server=SERVER,session=SESSION)
