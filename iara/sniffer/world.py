"""World-packet framing, compression and bundles using build-supplied opcodes."""

import struct
import zlib


_ADLER_SEED = 0x9827D8F1


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


class WorldFramer:
    def __init__(self, direction, max_body=1048576):
        if type(direction) is not str or direction not in ('client', 'server'):
            raise ValueError('direction')
        if not _integer(max_body, 4, 16777216):
            raise ValueError('max_body')
        self._greeting = (
            b'WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER - V2\n'
            if direction == 'client' else
            b'WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT - V2\n'
        )
        self._max_body = max_body
        self._buffer = bytearray()
        self._greeted = False
        self._length = None
        self._closed = False
        self._poisoned = False

    @property
    def buffered_bytes(self):
        return len(self._buffer)

    def _fail(self, code):
        self._poisoned = True
        self._buffer.clear()
        raise ValueError(code)

    def _active(self):
        if self._poisoned or self._closed:
            self._fail('inactive')

    def feed(self, data):
        self._active()
        if type(data) is not bytes:
            self._fail('input_type')
        if len(data) > 2 * (self._max_body + 70):
            self._fail('chunk_limit')
        result = []
        view = memoryview(data)
        position = 0
        while position < len(data):
            if not self._greeted:
                target = len(self._greeting)
            elif self._length is None:
                target = 4
            else:
                target = self._length + 16
            amount = min(target - len(self._buffer), len(data) - position)
            self._buffer.extend(view[position:position + amount])
            position += amount
            if not self._greeted:
                if self._buffer != self._greeting[:len(self._buffer)]:
                    self._fail('greeting')
                if len(self._buffer) == target:
                    self._greeted = True
                    self._buffer.clear()
            elif self._length is None:
                if len(self._buffer) == 4:
                    length = struct.unpack_from('<I', self._buffer)[0]
                    if not 4 <= length <= self._max_body:
                        self._fail('body_length')
                    self._length = length
            elif len(self._buffer) == target:
                result.append((bytes(self._buffer[4:16]), bytes(self._buffer[16:])))
                self._buffer.clear()
                self._length = None
        return result

    def finish(self):
        self._active()
        if not self._greeted or self._buffer:
            self._fail('incomplete')
        self._closed = True


class BodyDecoder:
    def __init__(self, compressed_opcode, bundle_opcode, max_output=1048576,
                 max_messages=1024, max_depth=8):
        if (not _integer(compressed_opcode, 0, 0xffffffff)
                or not _integer(bundle_opcode, 0, 0xffffffff)
                or compressed_opcode == bundle_opcode):
            raise ValueError('opcodes')
        if not _integer(max_output, 4, 16777216):
            raise ValueError('max_output')
        if not _integer(max_messages, 1, 16384):
            raise ValueError('max_messages')
        if not _integer(max_depth, 1, 16):
            raise ValueError('max_depth')
        self._compressed = compressed_opcode
        self._bundle = bundle_opcode
        self._max_output = max_output
        self._max_messages = max_messages
        self._max_depth = max_depth
        self._inflater = zlib.decompressobj(-15)
        self._poisoned = False

    def decode(self, body):
        if self._poisoned:
            raise ValueError('poisoned')
        try:
            if type(body) is not bytes:
                raise ValueError('input_type')
            if not 4 <= len(body) <= self._max_output:
                raise ValueError('body_length')
            # All per-call accounting is discarded after this decode.
            budget = [0]
            result = []
            self._expand(body, 0, budget, result)
            return result
        except ValueError:
            # A partially used inflater must never be reused after failure.
            self._poisoned = True
            raise
        except zlib.error:
            self._poisoned = True
            raise ValueError('inflate_error') from None
        except Exception:
            self._poisoned = True
            raise

    def _expand(self, body, depth, budget, result):
        if depth > self._max_depth:
            raise ValueError('depth_limit')
        if len(body) < 4:
            raise ValueError('body_length')
        budget[0] += len(body)
        if budget[0] > self._max_output:
            raise ValueError('output_limit')
        opcode = struct.unpack_from('<I', body)[0]
        if opcode == self._compressed:
            if len(body) < 20:
                raise ValueError('compressed_header')
            expected, decoded_adler, compressed_adler = struct.unpack_from('<III', body, 4)
            if not 4 <= expected <= self._max_output - budget[0]:
                raise ValueError('decoded_size')
            wire = body[16:]
            if not wire.endswith(b'\x00\x00\xff\xff'):
                raise ValueError('flush_marker')
            if zlib.adler32(wire, _ADLER_SEED) & 0xffffffff != compressed_adler:
                raise ValueError('compressed_checksum')
            decoded = self._inflater.decompress(wire, expected + 1)
            if (len(decoded) != expected or self._inflater.eof
                    or self._inflater.unused_data or self._inflater.unconsumed_tail):
                raise ValueError('inflate_state')
            if zlib.adler32(decoded, _ADLER_SEED) & 0xffffffff != decoded_adler:
                raise ValueError('decoded_checksum')
            self._expand(decoded, depth + 1, budget, result)
        elif opcode == self._bundle:
            offset = 4
            while offset < len(body):
                if len(body) - offset < 6:
                    raise ValueError('bundle_header')
                size = struct.unpack_from('<H', body, offset)[0]
                end = offset + 6 + size
                if end > len(body):
                    raise ValueError('bundle_length')
                if budget[0] + size + 4 > self._max_output:
                    raise ValueError('output_limit')
                self._expand(body[offset + 2:end], depth + 1, budget, result)
                offset = end
        else:
            if len(result) >= self._max_messages:
                raise ValueError('message_limit')
            result.append((opcode, body[4:]))
