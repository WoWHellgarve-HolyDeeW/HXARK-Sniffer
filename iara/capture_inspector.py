"""PKT 3.1 structure checks without reading payloads or session keys."""


def scan(stream, max_records=1000000):
    """Count records from container headers.

    The stream remains at next_offset on success. A record limit stops inspection
    before the next record, so unexamined trailing data is not validated.
    """
    if (not isinstance(max_records, int) or isinstance(max_records, bool)
            or not 1 <= max_records <= 1000000):
        raise ValueError('invalid_limit')

    def position():
        try:
            offset = stream.tell()
        except (OSError, ValueError, TypeError, OverflowError, AttributeError):
            raise ValueError('malformed_file') from None
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValueError('malformed_file')
        return offset

    def seek(offset, whence=0):
        try:
            result = stream.seek(offset, whence)
        except (OSError, ValueError, TypeError, OverflowError, AttributeError):
            raise ValueError('malformed_file') from None
        actual = position()
        if ((whence == 0 and actual != offset)
                or (result is not None and result != actual)):
            raise ValueError('malformed_file')
        return actual

    def read_exact(length):
        # Header reads are at most eight bytes; streams may return fewer per call.
        data = bytearray()
        while len(data) < length:
            remaining = length - len(data)
            before = position()
            try:
                chunk = stream.read(remaining)
            except (OSError, ValueError, TypeError, OverflowError, AttributeError):
                raise ValueError('malformed_file') from None
            if (not isinstance(chunk, (bytes, bytearray))
                    or not 0 < len(chunk) <= remaining
                    or position() != before + len(chunk)):
                raise ValueError('malformed_file')
            data.extend(chunk)
        return data

    origin = position()
    if origin != 0:
        raise ValueError('malformed_file')
    size = seek(0, 2)
    seek(origin)

    if read_exact(3) != b'PKT':
        raise ValueError('unsupported_format')
    version = int.from_bytes(read_exact(2), 'little')
    if version != 0x301:
        raise ValueError('unsupported_format')
    if size < 66:
        raise ValueError('malformed_file')
    seek(6)  # Skip the sniffer ID. Later seeks also skip session data and timestamps.
    build = int.from_bytes(read_exact(4), 'little')
    seek(62)
    additional = int.from_bytes(read_exact(4), 'little', signed=True)
    if additional < 0 or additional > size - 66:
        raise ValueError('malformed_file')
    offset = 66 + additional
    seek(offset)

    directions = {'server': 0, 'client': 0, 'unknown': 0}
    records = 0
    payload_bytes = 0
    while offset < size and records < max_records:
        if size - offset < 20:
            raise ValueError('malformed_file')
        direction = int.from_bytes(read_exact(4), 'little')
        seek(offset + 12)  # Do not read connection identifiers or timestamps.
        lengths = read_exact(8)
        extra = int.from_bytes(lengths[:4], 'little', signed=True)
        data_length = int.from_bytes(lengths[4:], 'little', signed=True)
        if extra < 0 or data_length < 4:
            raise ValueError('malformed_file')
        end = offset + 20 + extra + data_length
        if end > size:
            raise ValueError('malformed_file')
        seek(end)  # Skip all extra data, opcode and payload.
        name = ('server' if direction == 0x47534d53 else
                'client' if direction == 0x47534d43 else 'unknown')
        directions[name] += 1
        payload_bytes += data_length - 4
        records += 1
        offset = end

    return {'version': version, 'build': build, 'records': records,
            'directions': directions, 'payload_bytes': payload_bytes,
            'next_offset': offset, 'complete': offset == size}


def inspect_file(path, max_records=1000000):
    """Inspect a regular PKT file and reject size/mtime changes during the scan.

    Use a closed capture: changes that preserve size and mtime are not detected.
    """
    import os
    import stat
    from pathlib import Path
    selected=Path(path)
    info=selected.stat()
    if not stat.S_ISREG(info.st_mode):raise ValueError('not_regular_file')
    # Unbuffered reads avoid prefetching adjacent private payload/key bytes.
    with selected.open('rb',buffering=0) as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):raise ValueError('not_regular_file')
        result=scan(stream,max_records)
        after=os.fstat(stream.fileno())
        if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
            raise ValueError('file_changed_during_scan')
    return dict(result,bytes=before.st_size,coverage='structure_only',private_content_exported=False)


def main():
    import argparse
    import json
    from pathlib import Path
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',type=Path)
    p.add_argument('--max-records',type=int,default=1000000)
    a=p.parse_args()
    try:result=inspect_file(a.file,a.max_records)
    except (OSError,ValueError) as exc:
        print(json.dumps({'ok':False,'error':str(exc) if isinstance(exc,ValueError) else 'file_unavailable'}))
        raise SystemExit(2)
    print(json.dumps(dict(ok=True,**result),indent=2))
    if not result['complete']:raise SystemExit(3)


if __name__=='__main__':main()
