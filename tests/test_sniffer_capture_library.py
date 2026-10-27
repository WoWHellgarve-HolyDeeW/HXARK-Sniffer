import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from iara.sniffer import capture_library as library
from iara.sniffer.capture_files import capture_destination
from iara.sniffer.pkt_writer import header, record

SESSION = '20261026-120000-1234abcd'


def init(map_id=1, area=1637, subarea=0):
    return struct.pack('<iiiI', map_id, area, subarea, 0)


def pkt(messages, build=70575):
    return header(build, 1793016000, 0) + b''.join(
        record(direction, 0, i, opcode, payload)
        for i, (direction, opcode, payload) in enumerate(messages))


def sample(*areas, build=70575):
    return pkt([('server', 0x4501f0, init(*a)) for a in (areas or [(1, 1637)])], build)


class CaptureLibraryTests(unittest.TestCase):
    def fixture(self, raw=None):
        temp = tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root = Path(temp.name);source = root/'captures'/SESSION/'world-001.pkt'
        source.parent.mkdir(parents=True);source.write_bytes(raw if raw is not None else sample())
        return root, source, hashlib.sha256(source.read_bytes()).hexdigest()

    def publish(self, root, source, digest, **kw):
        return library.publish_capture(source, root/'dumps', SESSION, 1, digest, **kw)

    def test_area_name_and_date_come_from_packet_not_account_or_folder(self):
        root, source, digest = self.fixture()
        value = self.publish(root, source, digest)
        self.assertTrue(value['file'].startswith('Orgrimmar_b70575_20261026-120000Z_'))
        self.assertEqual(value['location']['areas'], [[1, 1637]])
        self.assertEqual((root/'dumps'/value['file']).read_bytes(), source.read_bytes())
        self.assertFalse((root/'dumps'/value['file']).samefile(source))
        self.assertEqual([p.suffix for p in (root/'dumps').iterdir()], ['.pkt'])
        self.assertFalse(list((root/'private-exports').iterdir()))

    def test_subareas_do_not_mislabel_streets_as_multiple_zones(self):
        _, source, _ = self.fixture(sample((1, 1637, 5170), (1, 1637, 0), (1, 1637, 1637)))
        self.assertEqual(library.describe_capture(source)['label'], 'Orgrimmar')

    def test_multiple_areas_remain_one_unchanged_file_with_explicit_hint(self):
        root, source, digest = self.fixture(sample((1, 14), (1, 1637)))
        value = self.publish(root, source, digest)
        self.assertEqual(value['location']['label'], 'Durotar-and-more')
        self.assertEqual((root/'dumps'/value['file']).read_bytes(), source.read_bytes())

    def test_map_transition_without_area_message_still_marks_multiple_maps(self):
        raw = pkt([('server', 0x4501f0, init()), ('server', 0x45002b, struct.pack('<i', 2771)+bytes(52))])
        _, source, _ = self.fixture(raw)
        self.assertEqual(library.describe_capture(source)['label'], 'Orgrimmar-and-more')

    def test_unknown_area_uses_numeric_id_and_known_map(self):
        _, source, _ = self.fixture(sample((2771, 15458)))
        self.assertEqual(library.describe_capture(source)['label'], 'Voidstorm-area-15458')
        source.write_bytes(sample((999999, 999998)))
        self.assertEqual(library.describe_capture(source)['label'], 'Map-999999-area-999998')

    def test_unknown_build_and_no_location_keep_neutral_name(self):
        _, source, _ = self.fixture(sample(build=70576))
        self.assertEqual(library.describe_capture(source)['label'], 'Capture')
        source.write_bytes(pkt([('server', 42, b'not a location')]))
        self.assertEqual(library.describe_capture(source)['label'], 'Capture')

    def test_client_opcode_lookalike_cannot_name_capture(self):
        _, source, _ = self.fixture(pkt([('client', 0x4501f0, init())]))
        self.assertEqual(library.describe_capture(source)['label'], 'Capture')

    def test_verify_world_map_zero_is_not_treated_as_missing(self):
        _, source, _ = self.fixture(pkt([('server', 0x45002f, bytes(24))]))
        self.assertEqual(library.describe_capture(source)['label'], 'Eastern-Kingdoms')

    def test_malformed_location_falls_back_without_dropping_valid_container(self):
        for payload in (b'\0'*15, init()+b'x', struct.pack('<iiiI',1,1637,0,0xffffffff),init(-1)):
            with self.subTest(payload_length=len(payload)):
                root, source, digest = self.fixture(pkt([('server',0x4501f0,payload)]))
                value = self.publish(root, source, digest)
                self.assertEqual(value['location']['label'], 'Capture')
                self.assertTrue(value['location']['location_uncertain'])
                self.assertEqual((root/'dumps'/value['file']).read_bytes(), source.read_bytes())

    def test_bad_movement_length_does_not_invent_map_label(self):
        _, source, _ = self.fixture(pkt([('server',0x45002b,bytes(36))]))
        self.assertTrue(library.describe_capture(source)['location_uncertain'])

    def test_many_locations_bound_metadata_without_discarding_capture(self):
        root,source,digest=self.fixture(sample(*[(i,i+1000) for i in range(300)]))
        value=self.publish(root,source,digest)
        self.assertEqual(value['location']['label'],'Capture')
        self.assertLessEqual(len(value['location']['maps']),256)
        self.assertLessEqual(len(value['location']['areas']),256)
        self.assertEqual((root/'dumps'/value['file']).read_bytes(),source.read_bytes())

    def test_truncated_headers_records_and_payload_never_publish(self):
        raw=sample()
        for end in (0,5,65,67,80,len(raw)-1):
            root, source, digest=self.fixture(raw[:end])
            with self.assertRaises(ValueError):self.publish(root,source,digest)
            self.assertFalse(list((root/'dumps').glob('*.pkt')))

    def test_bad_direction_negative_lengths_and_missing_opcode_rejected(self):
        for pos, value in ((66, 1),(78, -1),(82, 3),(82, 1000000)):
            raw=bytearray(sample());struct.pack_into('<i',raw,pos,value)
            _,source,_=self.fixture(bytes(raw))
            with self.assertRaises(ValueError):library.describe_capture(source)

    def test_digest_mismatch_preserves_source_and_cleans_staging(self):
        root,source,_=self.fixture()
        with self.assertRaisesRegex(ValueError,'digest'):self.publish(root,source,'0'*64,remove_source=True)
        self.assertTrue(source.exists());self.assertFalse(list((root/'dumps').iterdir()))
        self.assertFalse(list((root/'private-exports').iterdir()))

    def test_idempotence_and_collisions_never_overwrite(self):
        root,source,digest=self.fixture();value=self.publish(root,source,digest)
        self.assertEqual(self.publish(root,source,digest)['file'],value['file'])
        destination=root/'dumps'/value['file'];destination.write_bytes(b'keep this file')
        with self.assertRaisesRegex(ValueError,'collision'):self.publish(root,source,digest,remove_source=True)
        self.assertEqual(destination.read_bytes(),b'keep this file');self.assertTrue(source.exists())

    def test_successful_new_export_removes_only_its_candidate(self):
        root,source,digest=self.fixture();private=source.parent/'private-session-01.dpapi';private.write_bytes(b'fixture')
        value=self.publish(root,source,digest,remove_source=True)
        self.assertFalse(source.exists());self.assertTrue((root/'dumps'/value['file']).exists())
        self.assertEqual(private.read_bytes(),b'fixture')

    def test_source_cannot_be_its_own_destination(self):
        root,source,digest=self.fixture();value=self.publish(root,source,digest)
        final=root/'dumps'/value['file']
        with self.assertRaisesRegex(ValueError,'source_is_destination'):
            self.publish(root,final,digest,remove_source=True)
        self.assertTrue(final.exists())

    def test_publish_failure_leaves_candidate_and_no_partial_in_dumps(self):
        root,source,digest=self.fixture()
        with patch.object(library.os,'link',side_effect=OSError('fixture failure')):
            with self.assertRaises(OSError):self.publish(root,source,digest,remove_source=True)
        self.assertTrue(source.exists());self.assertFalse(list((root/'dumps').iterdir()))
        self.assertFalse(list((root/'private-exports').iterdir()))

    def test_disk_full_fails_before_copy_and_preserves_candidate(self):
        root,source,digest=self.fixture()
        with patch.object(library.shutil,'disk_usage',return_value=type('Disk',(),{'free':0})()):
            with self.assertRaisesRegex(ValueError,'disk'):self.publish(root,source,digest,remove_source=True)
        self.assertTrue(source.exists());self.assertFalse(list((root/'dumps').iterdir()))

    def test_untrusted_identity_cannot_escape_library(self):
        root,source,digest=self.fixture()
        for session, seq in (('../escape',1),(SESSION,0),(SESSION,257),(SESSION,True)):
            with self.assertRaises(ValueError):library.publish_capture(source,root/'dumps',session,seq,digest)

    def test_symlink_source_and_destination_rejected(self):
        root,source,digest=self.fixture();alias=source.with_name('alias.pkt')
        try:alias.symlink_to(source)
        except OSError:self.skipTest('symlink privilege unavailable')
        with self.assertRaisesRegex(ValueError,'linked'):self.publish(root,alias,digest)
        value=self.publish(root,source,digest);destination=root/'dumps'/value['file'];destination.unlink()
        destination.symlink_to(source)
        with self.assertRaises(ValueError):self.publish(root,source,digest)

    def test_legacy_migration_only_receipted_pkts_once_without_sharing_inode(self):
        root,source,digest=self.fixture();session=source.parent
        (session/'result.json').write_text(json.dumps({'captures':[{'file':source.name,'ok':True,'receipt':{'pkt_sha256':digest}}]}))
        (session/'private-session-01.dpapi').write_bytes(b'private fixture')
        (session/'private-adapter-01').mkdir();(session/'bad.pkt.partial').write_bytes(b'incomplete')
        result=library.migrate_legacy(root/'captures',root/'dumps')
        self.assertEqual(result,{'exported':1,'failed':0})
        saved=list((root/'dumps').iterdir());self.assertEqual(len(saved),1)
        self.assertEqual(saved[0].suffix,'.pkt');self.assertTrue(source.exists())
        saved[0].unlink()
        self.assertEqual(library.migrate_legacy(root/'captures',root/'dumps'),{'exported':0,'failed':0})
        self.assertFalse(list((root/'dumps').iterdir()))  # respect the user's deletion
        self.assertEqual(capture_destination(root/'captures',dumps=root/'dumps'),root/'dumps')

    def test_bad_legacy_receipts_do_not_expose_private_files(self):
        for name,ok,digest in (('../world-001.pkt',True,'a'*64),('private-session-01.dpapi',True,'a'*64),
                              ('world-001.pkt',False,'a'*64),('world-001.pkt',True,None)):
            root,source,_=self.fixture()
            (source.parent/'result.json').write_text(json.dumps({'captures':[{'file':name,'ok':ok,'receipt':{'pkt_sha256':digest}}]}))
            library.migrate_legacy(root/'captures',root/'dumps')
            self.assertFalse(list((root/'dumps').iterdir()))

    def test_no_finished_receipt_means_no_migration(self):
        root,source,_=self.fixture()
        self.assertEqual(library.migrate_legacy(root/'captures',root/'dumps'),{'exported':0,'failed':0})
        self.assertTrue(source.exists())

    def test_exported_receipt_is_not_migrated_again(self):
        root,source,_=self.fixture()
        (source.parent/'result.json').write_text(json.dumps({'captures':[{'file':'Orgrimmar.pkt','ok':True,'storage':'dumps'}]}))
        self.assertEqual(library.migrate_legacy(root/'captures',root/'dumps'),{'exported':0,'failed':0})


if __name__ == '__main__':unittest.main()
