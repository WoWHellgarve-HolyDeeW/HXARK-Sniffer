"""AES-256-GCM world frames: 12-byte tags and per-direction counters.

Nonce: little-endian u64 counter followed by CLNT or SRVR.
The caller supplies the encryption boundary; tag contents do not identify it.
"""


class PacketDecryptor:
    def __init__(self, direction, *, counter=0):
        if direction not in ('client', 'server'):
            raise ValueError('invalid_direction')
        if type(counter) is not int or not 0 <= counter < 2**64:
            raise ValueError('invalid_counter')
        self.direction = direction
        self.counter = counter
        self._key = None
        self.failed = False

    def _fail(self, code):
        self.failed = True
        self._key = None
        raise ValueError(code)

    def activate(self, key):
        if self.failed or self._key is not None:
            self._fail('crypto_unavailable')
        if type(key) is not bytes or len(key) != 32:
            self._fail('invalid_key')
        self._key = key

    def decode(self, tag, body):
        if self.failed:
            self._fail('crypto_unavailable')
        if (type(tag) is not bytes or len(tag) != 12 or type(body) is not bytes
                or not 4 <= len(body) <= 16*1024*1024):
            self._fail('invalid_crypto_frame')
        if self.counter >= 2**64:
            self._fail('counter_exhausted')
        if self._key is None:
            if tag != bytes(12):
                self._fail('encryption_key_required')
            result = body
        else:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.exceptions import InvalidTag
            nonce = self.counter.to_bytes(8, 'little') + (b'CLNT' if self.direction == 'client' else b'SRVR')
            decryptor = Cipher(algorithms.AES(self._key), modes.GCM(nonce, tag, min_tag_length=12)).decryptor()
            try:
                # Do not release unauthenticated plaintext from update().
                pending = decryptor.update(body)
                result = pending + decryptor.finalize()
            except InvalidTag:
                self._fail('authentication_failed')
        self.counter += 1
        return result

    def close(self):
        # Drop this reference; Python does not guarantee zeroization of copies.
        self._key = None
        self.failed = True
