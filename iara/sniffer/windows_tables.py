"""Parse Windows inventory buffers."""

import struct


def parse_tcp_table(data, pid, *, connecting=False):
    """Parse established IPv4 TCP rows owned by exactly the requested PID."""
    if type(data) is not bytes:
        raise ValueError("E_DATA_TYPE")
    if not 4 <= len(data) <= 16 * 1024 * 1024:
        raise ValueError("E_DATA_LENGTH")
    if type(pid) is not int or not 1 <= pid <= 0xffffffff:
        raise ValueError("E_PID")

    count = struct.unpack_from("<I", data, 0)[0]
    if count > 65536:
        raise ValueError("E_ROW_COUNT")
    if len(data) < 4 + 24 * count:
        raise ValueError("E_TRUNCATED")

    result = []
    seen = set()
    for offset in range(4, 4 + 24 * count, 24):
        state = struct.unpack_from("<I", data, offset)[0]
        owner = struct.unpack_from("<I", data, offset + 20)[0]
        if owner != pid or state not in ((3,4,5) if connecting else (5,)):
            continue

        local = data[offset + 4:offset + 8]
        remote = data[offset + 12:offset + 16]
        local_port = int.from_bytes(data[offset + 8:offset + 10], "big")
        remote_port = int.from_bytes(data[offset + 16:offset + 18], "big")
        if local_port == 0 or remote_port == 0:
            raise ValueError("E_PORT")
        for address in (local, remote):
            if (address == b"\x00\x00\x00\x00"
                    or address == b"\xff\xff\xff\xff"
                    or 224 <= address[0] <= 239):
                raise ValueError("E_ADDRESS")

        client_ip = ".".join(str(part) for part in local)
        server_ip = ".".join(str(part) for part in remote)
        key = (client_ip, local_port, server_ip, remote_port)
        if key not in seen:
            seen.add(key)
            result.append({"client": [client_ip, local_port],
                           "server": [server_ip, remote_port]})
    return result


def build_from_fixed_version(ms, ls):
    """Extract the inventory build number without inferring compatibility."""
    if (type(ms) is not int or type(ls) is not int
            or not 0 <= ms <= 0xffffffff or not 0 <= ls <= 0xffffffff):
        raise ValueError("E_VERSION")
    major = ms >> 16
    build_part = ls >> 16
    private_part = ls & 65535
    return private_part + 10 * build_part if major >= 100 else private_part
