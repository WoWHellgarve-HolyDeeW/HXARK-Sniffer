"""Decode a selected TCP connection from PCAP to PKT.

Requires SYN/FIN, encryption boundaries and local keys. Missing data aborts
decoding and leaves the output unfinalized.
"""
from .pcap import iter_tcp
from .tcp import TCPStream
from .decoder import DirectionDecoder
from .pkt_writer import PKTWriter
import ipaddress


def _endpoint(value):
    if type(value) not in (tuple,list) or len(value)!=2:
        raise ValueError('invalid_endpoint')
    address,port=value
    if type(address) is not str or type(port) is not int or not 1<=port<=65535:
        raise ValueError('invalid_endpoint')
    return str(ipaddress.IPv4Address(address)),port


def replay(source, destination, *, profile, client, server, keys, encrypted_from,
           max_packets=1000000, max_bytes=1024**3, validate_output=None, process_exited=False):
    client=_endpoint(client);server=_endpoint(server)
    if client==server:raise ValueError('invalid_endpoints')
    codecs={d:DirectionDecoder(profile,d,encrypted_from=encrypted_from[d],key=keys[d])
            for d in ('client','server')}
    streams={};starts={};ends={};writer=None;started=None;selected=0;reset_seen=False
    try:
        for packet in iter_tcp(source,max_packets=max_packets,max_bytes=max_bytes):
            pair=((packet.source,packet.source_port),(packet.destination,packet.destination_port))
            if pair==(client,server):direction='client'
            elif pair==(server,client):direction='server'
            else:continue
            selected+=1
            if started is None:
                started=packet.timestamp_ns
                writer=PKTWriter(destination,build=profile.build,start_unix=started//10**9,start_ticks=0)
            # PKT start_unix is whole seconds. Preserve the fractional second
            # in each record, including when comparing separate connections.
            ticks=packet.timestamp_ns//10**6-(started//10**9)*1000
            if packet.timestamp_ns<started or not 0<=ticks<2**32:
                raise ValueError('timestamp_out_of_range')
            if packet.flags & 4:
                reset_seen=True
                if not process_exited:raise ValueError('connection_reset')
            if packet.flags & 2:
                sequence=(packet.sequence+1)%(2**32)
                if direction in starts:
                    if starts[direction]!=sequence:raise ValueError('connection_reused')
                else:
                    starts[direction]=sequence;streams[direction]=TCPStream(sequence)
            if direction not in streams:raise ValueError('missing_tcp_handshake')
            sequence=(packet.sequence+bool(packet.flags & 2))%(2**32)
            if packet.payload:
                contiguous=streams[direction].feed(sequence,packet.payload)
                for opcode,payload in codecs[direction].feed(contiguous):
                    writer.append(direction,0,ticks,opcode,payload)
            if packet.flags & 1:
                end=(sequence+len(packet.payload))%(2**32)
                if direction in ends and ends[direction]!=end:raise ValueError('conflicting_fin')
                ends[direction]=end
        if writer is None:raise ValueError('selected_connection_not_found')
        for direction in ('client','server'):
            if direction not in streams:raise ValueError('missing_direction')
            streams[direction].finish()
            if ends.get(direction)!=streams[direction].next_sequence and not process_exited:
                raise ValueError('connection_not_fully_captured')
            codecs[direction].finish()
        # Require an authenticated frame; a plaintext handshake cannot validate the key.
        if not any(c.frames > encrypted_from[d] for d,c in codecs.items()):
            raise ValueError('no_authenticated_frames')
        if validate_output is not None:
            writer.stream.flush()
            validate_output(writer.partial, writer.records)
        receipt=writer.commit()
        receipt.update({'selected_tcp_packets':selected,'world_frames':sum(c.frames for c in codecs.values()),
                        'transport_complete':not reset_seen and all(ends.get(d)==streams[d].next_sequence for d in streams),
                        'termination_basis':'process_exit' if process_exited else 'tcp_fin',
                        'frames_by_direction':{d:c.frames for d,c in codecs.items()},
                        'authenticated_frames':sum(max(0,c.frames-encrypted_from[d]) for d,c in codecs.items()),
                        'build':profile.build,'profile_evidence':profile.evidence,
                        'time_basis':'packet_completing_message','source':'local_pcap',
                        'build_compatibility_verified':profile.live_verified})
        return receipt
    finally:
        for codec in codecs.values():codec.close()
        if writer is not None:writer.close()
