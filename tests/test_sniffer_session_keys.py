import hashlib
import hmac
import unittest
from iara.sniffer.session_keys import derive_session, derive_encryption


class SessionTests(unittest.TestCase):
    def test_independent_vector(self):
        # Protocol constants found in the 70575 image, not session-specific keys.
        m, c, s = bytes(range(64)), bytes(range(32)), bytes(range(32,64))
        seed = bytes.fromhex('e81e8b5927621eaa861518eac0bf668c6dbf8393bcaa80525b1edc23a012b750')
        d = hmac.digest(hashlib.sha512(m).digest(), s+c+seed, 'sha512')
        parts = [hashlib.sha512(d[:32]).digest(), bytes(64), hashlib.sha512(d[32:]).digest()]
        expected = hashlib.sha512(b''.join(parts)).digest()[:40]
        self.assertEqual(derive_session(m,c,s), expected)
        seed2 = bytes.fromhex('71c9ed5aa70e4dff4c36a65a3e468a4a5da148c830474adef60d6cbe6fe45573')
        self.assertEqual(derive_encryption(expected,c,s), hmac.digest(expected,c+s+seed2,'sha512')[:32])

    def test_challenge_order_and_every_input_matters(self):
        m,c,s = bytes(range(64)), b'c'*32, b's'*32
        original = derive_session(m,c,s)
        self.assertNotEqual(original,derive_session(m,s,c))
        for i in range(64):
            v=bytearray(m);v[i]^=1
            self.assertNotEqual(original,derive_session(bytes(v),c,s))
        self.assertNotEqual(derive_encryption(original,c,s),derive_encryption(original,s,c))

    def test_each_parameter_validated_without_echo(self):
        for fn,n in [(derive_session,64),(derive_encryption,40)]:
            for index,length in enumerate([n,32,32]):
                for bad in [None,True,42,'private-value',bytearray(length),memoryview(bytes(length)),bytes(length-1),bytes(length+1)]:
                    values=[bytes(n),bytes(32),bytes(32)];values[index]=bad
                    with self.assertRaises(ValueError) as e:fn(*values)
                    self.assertEqual(str(e.exception),'INVALID_INPUT')

    def test_no_cross_session_state(self):
        args=(b'x'*64,b'y'*32,b'z'*32);a=derive_session(*args)
        derive_session(bytes(64),bytes(32),bytes(32))
        self.assertEqual(derive_session(*args),a)
        self.assertEqual(args,(b'x'*64,b'y'*32,b'z'*32))

    def test_derived_key_authenticates_both_directions(self):
        from iara.sniffer.crypto import PacketDecryptor
        from tests.test_sniffer_crypto import encrypted
        session=derive_session(bytes(64),b'c'*32,b's'*32)
        key=derive_encryption(session,b'c'*32,b's'*32)
        for direction in ('client','server'):
            decoder=PacketDecryptor(direction,counter=3);decoder.activate(key)
            self.assertEqual(decoder.decode(*encrypted(key,3,direction,b'fictional-world')),b'fictional-world')
