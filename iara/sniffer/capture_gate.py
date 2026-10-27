"""Buffer initial packets until Windows confirms the owning process.

A flow requires a fresh SYN and an exact four-tuple match in the owner table.
"""
from dataclasses import dataclass, field
from .pcap import TCPSegment


@dataclass
class _Flow:
    started: float
    syn: int
    owned: bool = False
    pending: list = field(default_factory=list)
    size: int = 0


class CaptureGate:
    def __init__(self, local, servers, *, server_port=None, interface_scope=False, ttl=10.0, max_bytes=8*1024*1024, max_flows=32):
        import ipaddress
        if type(interface_scope) is not bool or (interface_scope and (local is not None or server_port is None)):
            raise ValueError('invalid_capture_scope')
        # An interface-scoped collector must not freeze a DHCP address. The
        # exact process-owned four-tuple is still required before persistence.
        self.interface_scope = interface_scope
        self.local = None if interface_scope else str(ipaddress.IPv4Address(local))
        self.servers = frozenset((str(ipaddress.IPv4Address(a)), p) for a, p in (servers or ()))
        self.server_port = server_port
        if server_port is not None and (servers is not None or type(server_port) is not int or not 1 <= server_port <= 65535):
            raise ValueError('invalid_capture_scope')
        if server_port is None and (not 1 <= len(self.servers) <= 16 or any(type(p) is not int or not 1 <= p <= 65535 for _, p in self.servers)):
            raise ValueError('invalid_capture_scope')
        if type(ttl) not in (int, float) or not 0 < ttl <= 30:
            raise ValueError('invalid_quarantine_ttl')
        if type(max_bytes) is not int or not 1 <= max_bytes <= 16*1024*1024:
            raise ValueError('invalid_quarantine_limit')
        if type(max_flows) is not int or not 1 <= max_flows <= 32:
            raise ValueError('invalid_flow_limit')
        self.ttl, self.max_bytes, self.max_flows = ttl, max_bytes, max_flows
        self.flows = {}
        self.bytes = 0
        self.discarded = 0
        self.last_time = -1.0

    def _time(self, now):
        import math
        if type(now) not in (int, float) or not math.isfinite(now) or now < self.last_time:
            raise ValueError('invalid_monotonic_time')
        self.last_time = now

    def expire(self, now):
        self._time(now)
        # Keep tombstones for rejected/expired tuples: a later SYN retransmit
        # cannot be mistaken for a new, complete connection.
        for flow in self.flows.values():
            if flow and not flow.owned and now-flow.started >= self.ttl:
                self.bytes -= flow.size
                self.discarded += len(flow.pending)
                flow.pending.clear()
                flow.size = 0
        for key, flow in list(self.flows.items()):
            if flow and not flow.owned and now-flow.started >= self.ttl:
                self.flows[key] = None

    def feed(self, packet, record, now):
        if not isinstance(packet, TCPSegment) or type(record) is not bytes or not 1 <= len(record) <= 262160:
            raise ValueError('invalid_capture_record')
        self.expire(now)
        source = (packet.source, packet.source_port)
        target = (packet.destination, packet.destination_port)
        if self.interface_scope and source[1] == target[1] == self.server_port:
            # Direction cannot be established from the port prefilter alone.
            self.discarded += 1
            return []
        if (self.interface_scope or packet.source == self.local) and (target in self.servers or target[1] == self.server_port):
            key, client = (source, target), True
        elif (self.interface_scope or packet.destination == self.local) and (source in self.servers or source[1] == self.server_port):
            key, client = (target, source), False
        else:
            raise ValueError('packet_outside_prefilter')
        if key not in self.flows:
            if len(self.flows) >= self.max_flows:
                raise ValueError('capture_flow_limit')
            if not client or packet.flags & 0x12 != 2 or packet.flags & 5:
                self.flows[key] = None
                self.discarded += 1
                return []
            self.flows[key] = _Flow(now, packet.sequence)
        flow = self.flows[key]
        if flow is None:
            self.discarded += 1
            return []
        if client and packet.flags & 2 and packet.sequence != flow.syn:
            raise ValueError('capture_tuple_reused')
        if flow.owned:
            return [(key, record)]
        if self.bytes + len(record) > self.max_bytes:
            raise ValueError('capture_quarantine_full')
        flow.pending.append(record)
        flow.size += len(record)
        self.bytes += len(record)
        return []

    def confirm(self, owned, now):
        self.expire(now)
        result = []
        for key in owned:
            flow = self.flows.get(key)
            if flow is not None and not flow.owned:
                flow.owned = True
                result.extend((key, record) for record in flow.pending)
                self.bytes -= flow.size
                flow.size = 0
                flow.pending.clear()
        return result

    def close(self):
        self.flows.clear()
        self.bytes = 0
