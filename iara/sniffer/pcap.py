"""Bounded PCAP/IPv4/TCP reader.

Rejects truncation and IP fragmentation. Checksums are not validated because
offloaded captures may leave them incomplete. IPv6 and PCAPNG are unsupported.
"""
from dataclasses import dataclass, replace
import ipaddress
import struct


@dataclass(frozen=True)
class TCPSegment:
    source: str
    destination: str
    source_port: int
    destination_port: int
    sequence: int
    flags: int
    payload: bytes
    timestamp_ns: int = 0


def decode_tcp(packet, link_type, endian='<'):
    if type(packet) is not bytes:
        raise ValueError('invalid_packet')
    if link_type == 0:  # DLT_NULL, host byte order, AF_INET.
        if len(packet) < 4 or struct.unpack(endian+'I', packet[:4])[0] != 2:
            raise ValueError('unsupported_network_protocol')
        ip = packet[4:]
    elif link_type == 1:  # Ethernet, at most two VLAN headers.
        if len(packet) < 14:
            raise ValueError('truncated_ethernet')
        offset = 14
        protocol = int.from_bytes(packet[12:14], 'big')
        for _ in range(2):
            if protocol not in (0x8100, 0x88a8):
                break
            if len(packet) < offset+4:
                raise ValueError('truncated_vlan')
            protocol = int.from_bytes(packet[offset+2:offset+4], 'big')
            offset += 4
        if protocol != 0x800:
            raise ValueError('unsupported_network_protocol')
        ip = packet[offset:]
    elif link_type == 101:  # DLT_RAW.
        ip = packet
    else:
        raise ValueError('unsupported_link_type')
    if len(ip) < 20 or ip[0] >> 4 != 4:
        raise ValueError('invalid_ipv4')
    ihl = (ip[0] & 15)*4
    length = int.from_bytes(ip[2:4], 'big')
    # Windows LSOv2 leaves Total Length at zero before NIC segmentation.
    # Npcap supplies the complete buffer (checked against original length by
    # the PCAP reader). No bytes may be inferred for nonzero/truncated lengths.
    # Restrict this capture representation to Ethernet and a full-sized frame;
    # short zero-length packets cannot be distinguished from Ethernet padding.
    if length == 0 and link_type == 1 and 1500 < len(ip) <= 262130:
        length = len(ip)
    if ihl < 20 or length < ihl+20 or length > len(ip):
        raise ValueError('truncated_ipv4')
    if int.from_bytes(ip[6:8], 'big') & 0x3fff:
        raise ValueError('fragmented_ipv4')
    if ip[9] != 6:
        raise ValueError('not_tcp')
    tcp = ip[ihl:length]
    header = (tcp[12] >> 4)*4
    if header < 20 or header > len(tcp):
        raise ValueError('truncated_tcp')
    source_port, destination_port, sequence = struct.unpack('!HHI', tcp[:8])
    return TCPSegment(str(ipaddress.IPv4Address(ip[12:16])),
                      str(ipaddress.IPv4Address(ip[16:20])),
                      source_port, destination_port, sequence, tcp[13], tcp[header:])


def _read(stream, size, eof=False):
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size-len(data))
        if type(chunk) is not bytes or len(chunk) > size-len(data):
            raise ValueError('invalid_stream')
        if not chunk:
            if not data and eof:
                return b''
            raise ValueError('truncated_pcap')
        data.extend(chunk)
    return bytes(data)


def iter_tcp(stream, *, max_packets=10000, max_bytes=64*1024*1024):
    """Yield TCP segments; caller must exhaust the iterator to validate the tail."""
    if type(max_packets) is not int or not 1 <= max_packets <= 1000000:
        raise ValueError('invalid_packet_limit')
    if type(max_bytes) is not int or not 24 <= max_bytes <= 1024**3:
        raise ValueError('invalid_byte_limit')
    first = _read(stream, 24)
    formats = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
               b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
    endian = formats.get(first[:4])
    if endian is None:
        raise ValueError('unsupported_capture_format')
    nano = first[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    major, minor, _, _, snaplen, link_type = struct.unpack(endian+'HHiiII', first[4:])
    if (major, minor) != (2, 4) or not 1 <= snaplen <= 262144:
        raise ValueError('invalid_pcap_header')
    if link_type not in (0, 1, 101):
        raise ValueError('unsupported_link_type')
    count = 0
    total = 24
    while True:
        raw = _read(stream, 16, eof=True)
        if not raw:
            return
        if count >= max_packets:
            raise ValueError('packet_limit')
        seconds, fraction, captured, original = struct.unpack(endian+'IIII', raw)
        if fraction >= (1000000000 if nano else 1000000):
            raise ValueError('invalid_timestamp')
        if captured != original or not 1 <= captured <= snaplen:
            raise ValueError('truncated_or_invalid_record')
        total += 16+captured
        if total > max_bytes:
            raise ValueError('byte_limit')
        count += 1
        yield replace(decode_tcp(_read(stream, captured), link_type, endian),
                      timestamp_ns=seconds*1000000000+fraction*(1 if nano else 1000))
