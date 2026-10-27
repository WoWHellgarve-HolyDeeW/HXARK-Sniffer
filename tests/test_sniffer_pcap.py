import io
import struct
import unittest

from iara.sniffer.pcap import decode_tcp, iter_tcp


def packet(payload=b'abc', *, ip_options=b'', tcp_options=b''):
    tcp = struct.pack('!HHIIBBHHH', 23456, 3724, 0xfffffffe, 0,
                      ((20+len(tcp_options))//4) << 4, 0x18, 65535, 0, 0)+tcp_options+payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x40+(20+len(ip_options))//4, 0,
                     20+len(ip_options)+len(tcp), 1, 0x4000, 64, 6, 0,
                     b'\x7f\0\0\1', b'\x7f\0\0\1')+ip_options+tcp
    return ip


def capture(packets, endian='<', link=101):
    first = struct.pack(endian+'IHHiiII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link)
    return first+b''.join(struct.pack(endian+'IIII', 1, 0, len(p), len(p))+p for p in packets)


class PcapTests(unittest.TestCase):
    def test_payload_and_options(self):
        item = decode_tcp(packet(ip_options=b'\1'*4, tcp_options=b'\1'*12), 101)
        self.assertEqual((item.source, item.source_port, item.destination_port), ('127.0.0.1',23456,3724))
        self.assertEqual(item.payload, b'abc');self.assertEqual(item.sequence,0xfffffffe)

    def test_null_endianness(self):
        for endian in ('<','>'):
            frame=struct.pack(endian+'I',2)+packet()
            result=list(iter_tcp(io.BytesIO(capture([frame],endian,0))))
            self.assertEqual(result[0].payload,b'abc')

    def test_ethernet_vlan_and_padding(self):
        header=bytes(12)+b'\x81\x00'+b'\0\1\x88\xa8'+b'\0\2\x08\x00'
        self.assertEqual(decode_tcp(header+packet()+bytes(8),1).payload,b'abc')

    def test_fragment_refused(self):
        for flags in (0x2000,1):
            raw=bytearray(packet());raw[6:8]=flags.to_bytes(2,'big')
            with self.assertRaisesRegex(ValueError,'fragmented_ipv4'):decode_tcp(bytes(raw),101)

    def test_windows_lso_v2_complete_ethernet_buffer(self):
        body=bytes(range(256))*6
        raw=bytearray(packet(body));raw[2:4]=bytes(2)
        frame=bytes(12)+b'\x08\x00'+bytes(raw)
        self.assertEqual(decode_tcp(frame,1).payload,body)
        self.assertEqual(list(iter_tcp(io.BytesIO(capture([frame],link=1))))[0].payload,body)
        # A nonzero declared length beyond captured data remains a real error.
        raw[2:4]=(len(raw)+1).to_bytes(2,'big')
        with self.assertRaisesRegex(ValueError,'truncated_ipv4'):
            decode_tcp(bytes(12)+b'\x08\x00'+bytes(raw),1)

    def test_lso_exception_does_not_relax_short_raw_or_fragmented_packets(self):
        for body,link in ((b'abc',1),(bytes(1600),101),(bytes(1600),0)):
            raw=bytearray(packet(body));raw[2:4]=bytes(2)
            prefix=bytes(12)+b'\x08\x00' if link==1 else (struct.pack('<I',2) if link==0 else b'')
            with self.assertRaisesRegex(ValueError,'truncated_ipv4'):decode_tcp(prefix+bytes(raw),link)
        raw=bytearray(packet(bytes(1600)));raw[2:4]=bytes(2);raw[6:8]=b'\x20\x00'
        with self.assertRaisesRegex(ValueError,'fragmented_ipv4'):
            decode_tcp(bytes(12)+b'\x08\x00'+bytes(raw),1)

    def test_all_truncation_positions(self):
        raw=packet()
        for size in range(len(raw)):
            with self.subTest(size=size),self.assertRaises(ValueError):decode_tcp(raw[:size],101)
        cap=capture([raw])
        for size in range(len(cap)):
            if size==24:continue # A complete empty PCAP is valid.
            with self.subTest(size=size),self.assertRaises(ValueError):list(iter_tcp(io.BytesIO(cap[:size])))

    def test_header_limits(self):
        raw=capture([packet()])
        for offset,value in ((20,999),(16,262145),(4,3)):
            bad=bytearray(raw);bad[offset:offset+4]=value.to_bytes(4,'little')
            with self.assertRaises(ValueError):list(iter_tcp(io.BytesIO(bad)))
        with self.assertRaisesRegex(ValueError,'unsupported_capture_format'):
            list(iter_tcp(io.BytesIO(bytes(24))))

    def test_truncated_capture_record_and_extra_tail(self):
        raw=bytearray(capture([packet()]));raw[36:40]=(1000).to_bytes(4,'little')
        with self.assertRaisesRegex(ValueError,'truncated_or_invalid_record'):list(iter_tcp(io.BytesIO(raw)))
        with self.assertRaisesRegex(ValueError,'truncated_pcap'):
            list(iter_tcp(io.BytesIO(capture([packet()])+b'x')))

    def test_limits_do_not_claim_partial_as_complete(self):
        raw=capture([packet(),packet()])
        with self.assertRaisesRegex(ValueError,'packet_limit'):list(iter_tcp(io.BytesIO(raw),max_packets=1))
        with self.assertRaisesRegex(ValueError,'byte_limit'):list(iter_tcp(io.BytesIO(raw),max_bytes=24))
        for limit in (True,0,1000001):
            with self.assertRaises(ValueError):list(iter_tcp(io.BytesIO(raw),max_packets=limit))

    def test_short_reads(self):
        class Short(io.BytesIO):
            def read(self,n=-1):return super().read(min(n,2))
        self.assertEqual(len(list(iter_tcp(Short(capture([packet()]))))),1)

    def test_invalid_tcp_header(self):
        for size in (0x40,0xf0):
            raw=bytearray(packet());raw[32]=size
            with self.assertRaisesRegex(ValueError,'truncated_tcp'):decode_tcp(bytes(raw),101)


if __name__=='__main__':unittest.main()
