import io
import json
import unittest
from iara.sniffer.capture_status import capture_summary
from iara.sniffer.profiles import select_profile
from tests.test_sniffer_replay import pcap,datagram,fixture,CLIENT,SERVER

CONNECTIONS=[{'client':list(CLIENT),'server':list(SERVER)}]


class CaptureStatusTests(unittest.TestCase):
    def test_midstream_is_not_readiness(self):
        report=capture_summary(io.BytesIO(pcap([datagram('client',100,b'PRIVATE-CONTENT')])),CONNECTIONS)
        self.assertTrue(report['flows'][0]['started_midstream'])
        self.assertFalse(report['decoded']);self.assertFalse(report['transport_completeness_verified'])
        serialized=json.dumps(report)
        for private in ('PRIVATE-CONTENT','127.0.0.1','12345','3724'):self.assertNotIn(private,serialized)

    def test_boundary_metadata_does_not_assert_crypto_or_complete_transport(self):
        report=capture_summary(io.BytesIO(pcap(fixture())),CONNECTIONS)
        flow=report['flows'][0]
        self.assertTrue(all(flow[k] for k in ('client_syn','server_syn','client_fin','server_fin')))
        self.assertFalse(flow['started_midstream']);self.assertFalse(report['transport_completeness_verified'])
        self.assertFalse(report['keys_available']);self.assertFalse(report['decoded'])

    def test_empty_capture(self):
        r=capture_summary(io.BytesIO(pcap([])),CONNECTIONS)
        self.assertEqual((r['packets'],r['connections_observed'],r['flows']),(0,0,[]))

    def test_unexpected_flow_fails(self):
        bad=[{'client':[CLIENT[0],1],'server':list(SERVER)}]
        with self.assertRaisesRegex(ValueError,'unexpected_connection'):
            capture_summary(io.BytesIO(pcap([datagram('client',100)])),bad)

    def test_truncation_fails(self):
        raw=pcap(fixture())
        with self.assertRaises(ValueError):capture_summary(io.BytesIO(raw[:-1]),CONNECTIONS)

    def test_invalid_or_ambiguous_scope(self):
        for rows in ([],None,CONNECTIONS*33,[{'client':list(CLIENT),'server':list(CLIENT)}],CONNECTIONS+[{'client':list(SERVER),'server':list(CLIENT)}]):
            with self.assertRaises(ValueError):capture_summary(io.BytesIO(pcap([])),rows)

    def test_duplicates_and_reset(self):
        r=capture_summary(io.BytesIO(pcap([datagram('server',100,flags=4)])),CONNECTIONS*2)
        self.assertEqual(len(r['flows']),1);self.assertTrue(r['flows'][0]['reset_seen'])

    def test_live_evidence_is_build_specific(self):
        profile=select_profile(70575)
        self.assertTrue(profile.control_opcodes_verified);self.assertTrue(profile.live_verified)
        self.assertTrue(profile.key_locator_verified)
        self.assertIn('continued_session',profile.evidence)
        with self.assertRaisesRegex(ValueError,'build_requires_validation'):select_profile(69875)
        with self.assertRaisesRegex(ValueError,'unsupported_build'):select_profile(70576)
