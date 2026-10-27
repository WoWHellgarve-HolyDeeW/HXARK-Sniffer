"""PKT 3.1 serializer for decoded messages.

Incomplete output keeps its .partial suffix. Existing files are not overwritten.
"""
import os
from pathlib import Path
import struct

MAX_PAYLOAD = 16*1024*1024


def uint(value, bits):
    if type(value) is not int or not 0 <= value < 2**bits:
        raise ValueError('invalid_integer')
    return value


def header(build, start_unix, start_ticks, locale='enUS'):
    if type(locale) is not str or len(locale) != 4 or not locale.isascii() or not locale.isalpha():
        raise ValueError('invalid_locale')
    # 0 is deliberately not Ymir's registered sniffer identifier. No session key.
    return (b'PKT'+struct.pack('<HBI',0x301,0,uint(build,32))+locale.encode('ascii')+
            bytes(40)+struct.pack('<IIi',uint(start_unix,32),uint(start_ticks,32),0))


def record(direction, connection, ticks, opcode, payload):
    if direction not in ('server','client'):
        raise ValueError('invalid_direction')
    if type(connection) is not int or not -(2**31) <= connection < 2**31:
        raise ValueError('invalid_connection')
    if type(payload) is not bytes or len(payload)>MAX_PAYLOAD:
        raise ValueError('invalid_payload')
    magic=0x47534d53 if direction=='server' else 0x47534d43
    return struct.pack('<IiIiiI',magic,connection,uint(ticks,32),0,len(payload)+4,uint(opcode,32))+payload


class PKTWriter:
    def __init__(self, destination, *, build, start_unix, start_ticks, locale='enUS', max_bytes=1024**3):
        first=header(build,start_unix,start_ticks,locale)
        if type(max_bytes) is not int or not len(first)<=max_bytes<=8*1024**3:
            raise ValueError('invalid_file_limit')
        self.destination=Path(destination).absolute()
        self.partial=self.destination.with_name(self.destination.name+'.partial')
        if self.destination.exists() or self.destination.is_symlink():
            raise FileExistsError(self.destination)
        self.stream=self.partial.open('xb',buffering=0)
        self.max_bytes=max_bytes;self.bytes=0;self.records=0;self.failed=False;self.committed=False
        try:self._write(first)
        except BaseException:self.stream.close();raise

    def _write(self, data):
        try:
            view=memoryview(data)
            while view:
                count=self.stream.write(view)
                if not count:raise OSError('short_write')
                self.bytes+=count;view=view[count:]
        except BaseException:
            self.failed=True
            raise

    def append(self, direction, connection, ticks, opcode, payload):
        if self.stream.closed or self.failed:raise ValueError('writer_unavailable')
        data=record(direction,connection,ticks,opcode,payload)
        if self.bytes+len(data)>self.max_bytes:raise ValueError('capture_size_limit')
        self._write(data);self.records+=1

    def commit(self):
        if self.failed or self.stream.closed:raise ValueError('writer_unavailable')
        try:
            self.stream.flush();os.fsync(self.stream.fileno());self.stream.close()
            # Hard link creation is atomic and refuses an existing destination,
            # unlike rename on POSIX. Both names are in the same directory.
            os.link(self.partial,self.destination)
            self.committed=True
            self.partial.unlink()
        except BaseException:
            self.failed=True;self.stream.close();raise
        return {'records':self.records,'bytes':self.bytes,'container_complete':True,
                'live_capture_verified':False}

    def close(self):
        self.stream.close()

    def __enter__(self):return self
    def __exit__(self,*exc):self.close()
