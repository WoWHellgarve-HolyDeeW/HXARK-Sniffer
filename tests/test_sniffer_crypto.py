import struct
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from iara.sniffer.crypto import PacketDecryptor


def encrypted(key, counter, direction, body):
    nonce=struct.pack('<Q',counter)+(b'CLNT' if direction=='client' else b'SRVR')
    e=Cipher(algorithms.AES(key),modes.GCM(nonce)).encryptor()
    value=e.update(body)+e.finalize()
    return e.tag[:12],value


class CryptoTests(unittest.TestCase):
    def test_transition_preserves_counter(self):
        key=bytes(range(32));d=PacketDecryptor('client')
        self.assertEqual(d.decode(bytes(12),b'hello'),b'hello')
        d.activate(key)
        self.assertEqual(d.decode(*encrypted(key,1,'client',b'world')),b'world')
        self.assertEqual(d.counter,2)

    def test_both_directions_and_large_counter(self):
        for direction in ('client','server'):
            d=PacketDecryptor(direction,counter=2**40);d.activate(bytes(32))
            self.assertEqual(d.decode(*encrypted(bytes(32),2**40,direction,b'\0'*32)),bytes(32))

    def test_tamper_fail_closed(self):
        key=bytes(range(32));tag,body=encrypted(key,0,'server',b'payload')
        for t,b in [(bytes([tag[0]^1])+tag[1:],body),(tag,bytes([body[0]^1])+body[1:])]:
            d=PacketDecryptor('server');d.activate(key)
            with self.assertRaisesRegex(ValueError,'authentication_failed'):d.decode(t,b)
            self.assertEqual(d.counter,0)
            with self.assertRaisesRegex(ValueError,'crypto_unavailable'):d.decode(tag,body)

    def test_wrong_key_direction_or_counter(self):
        tag,body=encrypted(bytes(32),0,'client',b'testing')
        for direction,counter,key in [('server',0,bytes(32)),('client',1,bytes(32)),('client',0,b'x'*32)]:
            d=PacketDecryptor(direction,counter=counter);d.activate(key)
            with self.assertRaisesRegex(ValueError,'authentication_failed'):d.decode(tag,body)

    def test_no_zero_tag_fallback(self):
        d=PacketDecryptor('client');d.activate(bytes(32))
        with self.assertRaisesRegex(ValueError,'authentication_failed'):d.decode(bytes(12),b'not plaintext')

    def test_no_key_and_close(self):
        d=PacketDecryptor('client')
        with self.assertRaisesRegex(ValueError,'encryption_key_required'):d.decode(b'x'*12,b'hello')
        d=PacketDecryptor('client');d.close()
        with self.assertRaises(ValueError):d.activate(bytes(32))

    def test_bounds_and_types(self):
        for n in (True,-1,2**64,0.5):
            with self.assertRaises(ValueError):PacketDecryptor('client',counter=n)
        for key in (b'x',bytearray(32),None):
            with self.assertRaises(ValueError):PacketDecryptor('server').activate(key)
        for tag,body in [(bytes(11),b'hello'),(bytes(12),bytes(3)),(bytes(12),bytearray(4))]:
            with self.assertRaises(ValueError):PacketDecryptor('server').decode(tag,body)

    def test_no_counter_wrap(self):
        d=PacketDecryptor('server',counter=2**64-1);d.decode(bytes(12),b'abcd')
        with self.assertRaisesRegex(ValueError,'counter_exhausted'):d.decode(bytes(12),b'abcd')

    def test_no_rekey_silently(self):
        d=PacketDecryptor('client');d.activate(bytes(32))
        with self.assertRaises(ValueError):d.activate(bytes(32))
