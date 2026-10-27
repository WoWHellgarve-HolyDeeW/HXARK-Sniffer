# TCP overlap, retransmission and gap regressions.
import unittest
from iara.sniffer.tcp import TCPStream
class Transport(unittest.TestCase):
 def test_order(self):
  s=TCPStream(100);self.assertEqual(s.feed(103,b'def'),b'');self.assertEqual(s.feed(100,b'abc'),b'abcdef');self.assertEqual(s.next_sequence,106);self.assertEqual(s.buffered_bytes,0);s.finish()
 def test_duplicate(self):
  s=TCPStream(0);self.assertEqual(s.feed(0,b'abc'),b'abc');self.assertEqual(s.feed(0,b'abc'),b'');self.assertEqual(s.feed(1,b'bcde'),b'de')
 def test_conflict(self):
  s=TCPStream(0);s.feed(3,b'def')
  with self.assertRaisesRegex(ValueError,'conflicting_overlap'):s.feed(2,b'cX')
  self.assertEqual(s.feed(0,b'abc'),b'abcdef')
 def test_gap(self):
  s=TCPStream(0);s.feed(2,b'c')
  with self.assertRaisesRegex(ValueError,'incomplete_stream'):s.finish()
 def test_wrap(self):
  s=TCPStream(0xfffffffe);self.assertEqual(s.feed(0,b'cd'),b'');self.assertEqual(s.feed(0xfffffffe,b'ab'),b'abcd');self.assertEqual(s.next_sequence,2)

import random,unittest
from iara.sniffer.tcp import TCPStream
class Reserved(unittest.TestCase):
 def test_permutations(self):
  rng=random.Random(24)
  for start in (0,1000,0xfffffff0):
   for trial in range(50):
    data=rng.randbytes(300);parts=[(i,data[i:i+10]) for i in range(0,300,10)];rng.shuffle(parts)
    s=TCPStream(start);out=b''
    for i,p in parts:out+=s.feed((start+i)%2**32,p)
    self.assertEqual(out,data);self.assertEqual(s.buffered_bytes,0);s.finish()
 def test_old_conflict_rollback(self):
  s=TCPStream(0);s.feed(0,b'abcdef')
  with self.assertRaisesRegex(ValueError,'conflicting_overlap'):s.feed(4,b'XXmore')
  self.assertEqual(s.next_sequence,6);self.assertEqual(s.feed(4,b'efmore'),b'more')
 def test_history(self):
  s=TCPStream(0,history_limit=3);s.feed(0,b'abcdef')
  with self.assertRaisesRegex(ValueError,'history_unavailable'):s.feed(2,b'cdefg')
  self.assertEqual(s.feed(3,b'defg'),b'g')
 def test_limits_atomic(self):
  s=TCPStream(0,max_buffer=10,max_segments=2);s.feed(3,b'd');s.feed(6,b'g')
  with self.assertRaises(ValueError):s.feed(9,b'j')
  self.assertEqual(s.buffered_bytes,2);self.assertEqual(s.feed(0,b'abcdefghi'),b'abcdefghi')
 def test_ambiguous(self):
  s=TCPStream(100)
  with self.assertRaises(ValueError):s.feed(100+2**31,b'a')
  self.assertEqual(s.next_sequence,100)
 def test_overlap_and_coalescing(self):
  s=TCPStream(0,max_segments=1);s.feed(3,b'def');s.feed(4,b'efgh');s.feed(2,b'cdefgh');self.assertEqual(s.buffered_bytes,6);self.assertEqual(s.feed(0,b'ab'),b'abcdefgh')
 def test_limit_distance(self):
  s=TCPStream(0,max_buffer=8)
  for seq,p in [(9,b'x'),(7,b'xy'),(0,b'x'*9)]:
   with self.assertRaises(ValueError):s.feed(seq,p)
  self.assertEqual(s.next_sequence,0);self.assertEqual(s.buffered_bytes,0)
 def test_bad_types(self):
  for v in (True,-1,2**32,1.1,'0'):
   with self.assertRaises(ValueError):TCPStream(v)
  s=TCPStream(0)
  for v in (True,-1,2**32,1.1,'0'):
   with self.assertRaises(ValueError):s.feed(v,b'x')
  for p in (None,'abc',bytearray(b'abc')):
   with self.assertRaises(ValueError):s.feed(0,p)
 def test_duplicate_pending_bounded(self):
  s=TCPStream(0,max_segments=1)
  for _ in range(1000):self.assertEqual(s.feed(1,b'bc'),b'')
  self.assertEqual(s.buffered_bytes,2);self.assertEqual(s.feed(0,b'a'),b'abc')
 def test_bytes_subclass_rejected(self):
  class Exotic(bytes):
   def __getitem__(self,key):raise AssertionError('untrusted override')
  with self.assertRaises(ValueError):TCPStream(0).feed(0,Exotic(b'a'))
if __name__=='__main__':unittest.main()
