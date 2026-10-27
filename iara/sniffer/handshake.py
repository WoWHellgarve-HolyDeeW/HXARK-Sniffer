"""Retail 70575 initial and continued-session handshakes.

Protocol messages set the encryption boundary. Unknown layouts are rejected.
Realm tickets remain opaque and are not used for key derivation.
"""
import struct
from .pcap import iter_tcp
from .tcp import TCPStream
from .world import WorldFramer
from .session_keys import derive_encryption


MAX_REALM_TICKET = 16 * 1024


def client_challenge(body):
    """Read a structurally validated challenge; GCM validates the key later.

    Realm login: opcode, DoS u64, three u32 realm fields, 32-byte challenge,
    24-byte digest, IPv6 bit/padding, u32 ticket length, opaque ticket.
    Continued login: opcode, DoS u64, challenge, digest and 16-byte routing data.
    The layouts are described in TrinityCore AuthenticationPackets at
    0153a76226cd83fe086bae64074723590d7df4ce and authenticated on local 70575
    captures. No source implementation is incorporated here.
    """
    if type(body) is not bytes or len(body) < 4:
        raise ValueError('unsupported_authentication_layout')
    opcode = struct.unpack_from('<I', body)[0]
    if opcode == 0x440003 and len(body) == 84:
        return body[12:44]
    if opcode == 0x440001 and 85 <= len(body) <= 85 + MAX_REALM_TICKET:
        ticket_size = struct.unpack_from('<I', body, 81)[0]
        if body[80] in (0, 0x80) and ticket_size == len(body) - 85:
            return body[24:56]
    raise ValueError('unsupported_authentication_layout')


def validate_initial_frames(client, server, session):
    if len(client)!=2 or len(server)!=2:
        raise ValueError('handshake_incomplete')
    for tag,body in list(client)+list(server):
        if tag!=bytes(12) or type(body) is not bytes or len(body)<4:
            raise ValueError('unexpected_handshake_frame')
    c,a=client[0][1],client[1][1]
    s,e=server[0][1],server[1][1]
    challenge = client_challenge(c)
    if len(s)!=69 or struct.unpack_from('<I',s)[0]!=0x4c0000:
        raise ValueError('unsupported_challenge_layout')
    if len(e)!=73 or struct.unpack_from('<I',e)[0]!=0x4c0004 or e[-1]!=0x80:
        raise ValueError('encryption_enable_not_confirmed')
    if a!=struct.pack('<I',0x440005):
        raise ValueError('encryption_ack_not_confirmed')
    return derive_encryption(session,challenge,s[36:68])


def inspect_handshake(source, *, client, server, session):
    client,server=tuple(client),tuple(server)
    streams={};starts={};frames={d:[] for d in ('client','server')}
    framers={d:WorldFramer(d) for d in frames}
    for packet in iter_tcp(source,max_packets=50000,max_bytes=32*1024*1024):
        pair=((packet.source,packet.source_port),(packet.destination,packet.destination_port))
        if pair==(client,server):direction='client'
        elif pair==(server,client):direction='server'
        else:continue
        if packet.flags&4:raise ValueError('connection_reset')
        if packet.flags&2:
            start=(packet.sequence+1)%2**32
            if direction in starts and starts[direction]!=start:raise ValueError('connection_reused')
            if direction not in starts:
                starts[direction]=start;streams[direction]=TCPStream(start)
        if direction not in streams:raise ValueError('missing_tcp_handshake')
        if len(frames[direction])<2 and packet.payload:
            data=streams[direction].feed((packet.sequence+bool(packet.flags&2))%2**32,packet.payload)
            frames[direction].extend(framers[direction].feed(data)[:2-len(frames[direction])])
        if all(len(x)==2 for x in frames.values()):
            key=validate_initial_frames(frames['client'],frames['server'],session)
            return key, {'client':2,'server':2}
    raise ValueError('handshake_incomplete')
