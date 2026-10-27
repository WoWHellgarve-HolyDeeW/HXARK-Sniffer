"""Decode one direction from a supplied encryption boundary.

The boundary counts complete world frames after the greeting, starting at zero.
"""
from .crypto import PacketDecryptor
from .world import WorldFramer, BodyDecoder
from .profiles import BuildProfile


class DirectionDecoder:
    def __init__(self, profile, direction, *, encrypted_from, key=None,
                 max_body=1048576, max_expanded=4194304,
                 max_batch_bytes=16777216, max_batch_messages=16384):
        if not isinstance(profile, BuildProfile):
            raise ValueError('invalid_profile')
        if type(encrypted_from) is not int or not 0 <= encrypted_from < 2**64:
            raise ValueError('encryption_boundary_required')
        if key is not None and (type(key) is not bytes or len(key)!=32):
            raise ValueError('invalid_key')
        if (type(max_batch_bytes) is not int or not 4<=max_batch_bytes<=16777216
                or type(max_batch_messages) is not int or not 1<=max_batch_messages<=16384):
            raise ValueError('invalid_batch_limit')
        self.framer=WorldFramer(direction,max_body)
        self.crypto=PacketDecryptor(direction)
        # Login bundles can exceed 1024 messages; use the same frame and batch limit.
        self.body=BodyDecoder(profile.compressed_opcode,profile.bundle_opcode,max_expanded,
                              max_messages=max_batch_messages)
        self._key=key
        self.encrypted_from=encrypted_from
        self.max_batch_bytes=max_batch_bytes;self.max_batch_messages=max_batch_messages
        self.frames=0;self.messages=0;self.failed=False;self.closed=False

    def feed(self, data):
        if self.failed or self.closed:
            raise ValueError('decoder_unavailable')
        try:
            messages=[];expanded_bytes=0
            for tag,wire_body in self.framer.feed(data):
                if self.frames==self.encrypted_from:
                    if self._key is None:raise ValueError('session_key_required')
                    self.crypto.activate(self._key)
                    self._key=None
                plain=self.crypto.decode(tag,wire_body)
                decoded=self.body.decode(plain)
                expanded_bytes+=sum(4+len(payload) for _,payload in decoded)
                if (expanded_bytes>self.max_batch_bytes or
                        len(messages)+len(decoded)>self.max_batch_messages):
                    raise ValueError('decoded_batch_limit')
                messages.extend(decoded)
                self.frames+=1
            self.messages+=len(messages)
            return messages
        except BaseException:
            self.failed=True;self.close();raise

    def finish(self):
        if self.failed or self.closed:raise ValueError('decoder_unavailable')
        try:self.framer.finish()
        except BaseException:self.failed=True;raise
        finally:self.close()

    def close(self):
        self._key=None;self.crypto.close();self.closed=True
