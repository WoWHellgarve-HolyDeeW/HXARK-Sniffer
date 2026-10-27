"""Synthetic PKT fixtures."""
import struct


def fixture(build=69814, records=(), extra=b'', key=b'PRIVATE_KEY_DO_NOT_READ'):
    header = bytearray(66)
    header[:3] = b'PKT'
    struct.pack_into('<HBI', header, 3, 0x301, 0x15, build)
    header[14:54] = key.ljust(40, b'X')[:40]
    struct.pack_into('<i', header, 62, len(extra))
    data = bytes(header) + extra
    for direction, payload, extra_record in records:
        data += struct.pack('<IiiII', direction, 1, 7, len(extra_record), len(payload)+4)
        data += extra_record + b'OPCD' + payload
    return data
