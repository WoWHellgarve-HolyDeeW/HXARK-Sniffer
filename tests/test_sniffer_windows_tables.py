import random
import struct
import unittest
from iara.sniffer.windows_tables import parse_tcp_table,build_from_fixed_version


def row(pid=81,state=5,client=b'\xc0\x00\x02\x08',server=b'\xcb\x00\x71\x07',cp=49153,sp=3724,pad=b'\x00\x00'):
    return struct.pack('<I',state)+client+cp.to_bytes(2,'big')+pad+server+sp.to_bytes(2,'big')+pad+struct.pack('<I',pid)


class WindowsTablesTests(unittest.TestCase):
    def test_other_processes_and_states_are_never_returned(self):
        rows=[row(pid=p,state=s) for p in (1,81,82) for s in range(1,13)]
        self.assertEqual(parse_tcp_table(struct.pack('<I',len(rows))+b''.join(rows),81),
                         [{'client':['192.0.2.8',49153],'server':['203.0.113.7',3724]}])

    def test_all_truncations_fail_including_filtered_rows(self):
        data=struct.pack('<I',2)+row()+row(pid=10)
        for n in range(len(data)):
            with self.assertRaises(ValueError):parse_tcp_table(data[:n],81)

    def test_unused_port_bytes_are_ignored(self):
        self.assertEqual(parse_tcp_table(struct.pack('<I',1)+row(pad=b'\xff\x81'),81)[0]['client'][1],49153)

    def test_capacity_tail_is_not_another_row(self):
        self.assertEqual(parse_tcp_table(bytes(4)+row(),81),[])
        self.assertEqual(len(parse_tcp_table(struct.pack('<I',1)+row()+row(cp=8),81)),1)

    def test_duplicates_preserve_first_order(self):
        data=struct.pack('<I',4)+row(cp=9)+row(cp=8)+row(cp=9)+row(cp=8)
        self.assertEqual([v['client'][1] for v in parse_tcp_table(data,81)],[9,8])

    def test_types_and_limits(self):
        for pid in (True,False,0,-1,2**32,'81',81.0):
            with self.assertRaises(ValueError):parse_tcp_table(bytes(4),pid)
        for data in (None,'',bytearray(4),memoryview(bytes(4)),b'',bytes(16*1024*1024+1),struct.pack('<I',65537)):
            with self.assertRaises(ValueError):parse_tcp_table(data,81)

    def test_selected_invalid_endpoints_are_rejected(self):
        for ip in (bytes(4),b'\xff'*4,b'\xe0\x00\x00\x01',b'\xef\xff\xff\xff'):
            for side in ('client','server'):
                with self.assertRaises(ValueError):parse_tcp_table(struct.pack('<I',1)+row(**{side:ip}),81)
        for side in ('cp','sp'):
            with self.assertRaises(ValueError):parse_tcp_table(struct.pack('<I',1)+row(**{side:0}),81)

    def test_filtered_invalid_fields_do_not_break_selected_rows(self):
        data=struct.pack('<I',2)+row(pid=1,cp=0,client=bytes(4))+row()
        self.assertEqual(len(parse_tcp_table(data,81)),1)

    def test_port_endianness_randomized(self):
        rng=random.Random(70575)
        for _ in range(100):
            cp=rng.randint(1,65535);sp=rng.randint(1,65535)
            result=parse_tcp_table(struct.pack('<I',1)+row(cp=cp,sp=sp),81)[0]
            self.assertEqual((result['client'][1],result['server'][1]),(cp,sp))

    def test_version_layout_boundaries(self):
        for major in (0,3,99,100,1201,65535):
            self.assertEqual(build_from_fixed_version(major<<16|5,7057<<16|5),70575 if major>=100 else 5)
        self.assertEqual(build_from_fixed_version(3<<16,12340),12340)

    def test_version_type_and_overflow(self):
        for value in (True,-1,2**32,1.0,'1',None):
            for args in ((value,0),(0,value)):
                with self.assertRaises(ValueError):build_from_fixed_version(*args)

    def test_errors_do_not_include_private_input(self):
        with self.assertRaises(ValueError) as error:parse_tcp_table(b'PRIVATE-INPUT',81)
        self.assertNotIn('PRIVATE',str(error.exception))
