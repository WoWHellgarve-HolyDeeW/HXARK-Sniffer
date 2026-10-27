"""Capture counts and transport diagnostics without packet contents."""
import ipaddress
from .pcap import iter_tcp


def _endpoint(value):
    if type(value) not in (list,tuple) or len(value)!=2 or type(value[0]) is not str:
        raise ValueError('invalid_endpoint')
    if type(value[1]) is not int or not 1<=value[1]<=65535:raise ValueError('invalid_endpoint')
    return str(ipaddress.IPv4Address(value[0])),value[1]


def capture_summary(stream,connections,*,max_packets=100000,max_bytes=67108864):
    if type(connections) is not list or not 1<=len(connections)<=32:
        raise ValueError('invalid_connection_scope')
    lookup={};flows=[]
    for row in connections:
        client=_endpoint(row['client']);server=_endpoint(row['server'])
        if client==server:raise ValueError('invalid_connection_scope')
        if (client,server) in lookup:
            if lookup[client,server][1]=='client':continue
            raise ValueError('ambiguous_connection_scope')
        index=len(flows)
        flows.append({'connection':index+1,'packets':0,'payload_bytes':0,
                      'client_syn':False,'server_syn':False,'client_fin':False,'server_fin':False,
                      'reset_seen':False})
        lookup[client,server]=(index,'client');lookup[server,client]=(index,'server')
    packets=0;payload_bytes=0
    for packet in iter_tcp(stream,max_packets=max_packets,max_bytes=max_bytes):
        pair=((packet.source,packet.source_port),(packet.destination,packet.destination_port))
        if pair not in lookup:raise ValueError('unexpected_connection')
        index,direction=lookup[pair];flow=flows[index]
        packets+=1;payload_bytes+=len(packet.payload)
        flow['packets']+=1;flow['payload_bytes']+=len(packet.payload)
        flow[direction+'_syn']|=bool(packet.flags&2);flow[direction+'_fin']|=bool(packet.flags&1)
        flow['reset_seen']|=bool(packet.flags&4)
    for flow in flows:
        flow['started_midstream']=bool(flow['packets'] and not(flow['client_syn'] and flow['server_syn']))
    return {'packets':packets,'payload_bytes':payload_bytes,'connections_observed':sum(bool(f['packets']) for f in flows),
            'flows':[f for f in flows if f['packets']],'decoded':False,
            'transport_completeness_verified':False,'keys_available':False}
