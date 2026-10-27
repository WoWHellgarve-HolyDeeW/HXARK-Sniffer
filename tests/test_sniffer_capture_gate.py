import unittest
from dataclasses import replace
from iara.sniffer.capture_gate import CaptureGate
from iara.sniffer.pcap import TCPSegment

C=('192.0.2.1',50000);S=('203.0.113.8',3724);PAIR=(C,S)
SYN=TCPSegment(C[0],S[0],C[1],S[1],100,2,b'')


class GateTests(unittest.TestCase):
    def gate(self,**kw):return CaptureGate(C[0],[S],**kw)
    def test_syn_saved_before_owner_is_known(self):
        g=self.gate();self.assertEqual(g.feed(SYN,b'syn',0),[])
        self.assertEqual(g.feed(replace(SYN,sequence=101,flags=0x18,payload=b'fiction'),b'body',1),[])
        self.assertEqual(g.confirm([PAIR],2),[(PAIR,b'syn'),(PAIR,b'body')])
        self.assertEqual(g.bytes,0)
        self.assertEqual(g.feed(replace(SYN,sequence=108,flags=0x11),b'fin',3),[(PAIR,b'fin')])
        self.assertEqual(g.confirm([PAIR],4),[])

    def test_other_process_never_released(self):
        g=self.gate();g.feed(SYN,b'private',0)
        self.assertEqual(g.confirm([((C[0],50001),S)],1),[])
        self.assertEqual(g.confirm([],10),[]);self.assertEqual(g.bytes,0)
        self.assertEqual(g.confirm([PAIR],11),[])
        self.assertEqual(g.feed(SYN,b'retransmitted',12),[])

    def test_midstream_never_becomes_complete(self):
        g=self.gate();g.feed(replace(SYN,flags=0x18),b'middle',0)
        self.assertEqual(g.confirm([PAIR],1),[])
        self.assertEqual(g.feed(SYN,b'late-syn',2),[])

    def test_server_syn_first_is_not_complete(self):
        g=self.gate();p=TCPSegment(S[0],C[0],S[1],C[1],200,0x12,b'')
        self.assertEqual(g.feed(p,b'synack',0),[])
        self.assertEqual(g.confirm([PAIR],1),[])

    def test_limits_and_cleanup(self):
        g=self.gate(max_bytes=4,max_flows=1);g.feed(SYN,b'1234',0)
        with self.assertRaisesRegex(ValueError,'quarantine_full'):g.feed(SYN,b'x',1)
        self.assertEqual(g.bytes,4)
        with self.assertRaisesRegex(ValueError,'flow_limit'):g.feed(replace(SYN,source_port=50001),b'x',2)
        g.close();self.assertEqual(g.bytes,0);self.assertEqual(g.flows,{})

    def test_reused_tuple_is_error(self):
        g=self.gate();g.feed(SYN,b'syn',0);g.confirm([PAIR],1)
        with self.assertRaisesRegex(ValueError,'tuple_reused'):g.feed(replace(SYN,sequence=999),b'new',2)

    def test_scope_and_time(self):
        g=self.gate()
        with self.assertRaisesRegex(ValueError,'outside_prefilter'):g.feed(replace(SYN,destination='203.0.113.9'),b'x',0)
        for t in [float('nan'),float('inf'),True,-1]:
            with self.assertRaises(ValueError):g.confirm([],t)
        g.expire(10)
        with self.assertRaises(ValueError):g.expire(9)

    def test_duplicate_syn_retained_for_transport_validation(self):
        g=self.gate();g.feed(SYN,b'first',0);g.feed(SYN,b'retry',1)
        self.assertEqual(len(g.confirm([PAIR],2)),2)

    def test_global_quarantine_bound_across_flows(self):
        g=self.gate(max_bytes=4);g.feed(SYN,b'12',0)
        g.feed(replace(SYN,source_port=50001),b'34',1)
        with self.assertRaises(ValueError):g.feed(replace(SYN,source_port=50002),b'5',2)

    def test_interface_scope_survives_address_change_but_keeps_exact_ownership(self):
        g=CaptureGate(None,None,server_port=3724,interface_scope=True)
        new=replace(SYN,source='192.0.2.99')
        other=replace(new,source_port=50001)
        pair=((new.source,new.source_port),S)
        self.assertEqual(g.feed(new,b'new-address-syn',0),[])
        self.assertEqual(g.feed(other,b'other-process',1),[])
        self.assertEqual(g.confirm([PAIR],2),[])  # Old address is not ownership.
        self.assertEqual(g.confirm([pair],3),[(pair,b'new-address-syn')])
        reply=TCPSegment(S[0],new.source,S[1],new.source_port,200,0x12,b'')
        self.assertEqual(g.feed(reply,b'reply',4),[(pair,b'reply')])
        g.expire(12)
        self.assertEqual(g.bytes,0)
        self.assertEqual(g.confirm([((other.source,other.source_port),S)],13),[])

    def test_interface_scope_requires_explicit_bounded_port(self):
        for kw in ({}, {'server_port':3724}, {'server_port':None,'interface_scope':True},
                   {'server_port':3724,'interface_scope':1}):
            with self.assertRaises(ValueError):CaptureGate(None,None,**kw)
        with self.assertRaises(ValueError):CaptureGate(C[0],None,server_port=3724,interface_scope=True)
        with self.assertRaises(ValueError):CaptureGate(None,[S],server_port=3724,interface_scope=True)

    def test_interface_scope_does_not_relax_handshake_limits_or_port(self):
        g=CaptureGate(None,None,server_port=3724,interface_scope=True,max_bytes=4)
        with self.assertRaisesRegex(ValueError,'outside_prefilter'):
            g.feed(replace(SYN,destination_port=443),b'x',0)
        self.assertEqual(g.feed(replace(SYN,source_port=3724),b'ambiguous',1),[])
        self.assertEqual(g.feed(replace(SYN,flags=0x18),b'midstream',2),[])
        self.assertEqual(g.confirm([PAIR],3),[])
        new=replace(SYN,source='192.0.2.99')
        g.feed(new,b'1234',4)
        with self.assertRaisesRegex(ValueError,'quarantine_full'):g.feed(new,b'x',5)
