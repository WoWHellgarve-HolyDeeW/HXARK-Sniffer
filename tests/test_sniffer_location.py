import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from iara.sniffer.location import load, save


class LocationTests(unittest.TestCase):
    def test_selection_survives_restart_and_missing_game_is_ignored(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);wow=root/'Custom game folder'/'Wow.exe'
            wow.parent.mkdir();wow.write_bytes(b'synthetic; not executed')
            config=root/'settings'
            self.assertEqual(save(config,wow),wow.resolve())
            self.assertEqual(load(config),wow.resolve())
            self.assertEqual(json.loads((config/'wow-location.json').read_text()),{'path':str(wow.resolve())})
            wow.unlink();self.assertIsNone(load(config))

    def test_invalid_or_oversized_settings_fall_back(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.assertIsNone(load(root))
            for text in ('{','null','[]','{"path": true}','{"path": "Wow.exe"}',
                         '{"path": "missing", "command": "run"}',' '*8193):
                (root/'wow-location.json').write_text(text)
                self.assertIsNone(load(root))

    def test_wrong_name_and_nonexistent_selection_are_not_saved(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);other=root/'other.exe';other.write_bytes(b'fixture')
            for value in (other,root/'Wow.exe',Path('Wow.exe')):
                with self.assertRaises(ValueError):save(root/'settings',value)
            self.assertFalse((root/'settings').exists())

    def test_failed_replace_preserves_previous_selection(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);wow=root/'Wow.exe';wow.write_bytes(b'fixture')
            save(root/'settings',wow)
            old=(root/'settings/wow-location.json').read_bytes()
            with patch('iara.sniffer.location.os.replace',side_effect=OSError('fixture')):
                with self.assertRaises(OSError):save(root/'settings',wow)
            self.assertEqual((root/'settings/wow-location.json').read_bytes(),old)
            self.assertEqual(len(list((root/'settings').iterdir())),1)

    def test_linked_config_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);wow=root/'Wow.exe';wow.write_bytes(b'fixture')
            external=root/'preserve';external.write_bytes(b'preserve')
            config=root/'settings';config.mkdir();os.link(external,config/'wow-location.json')
            with self.assertRaisesRegex(ValueError,'linked_wow_location'):save(config,wow)
            self.assertIsNone(load(config));self.assertEqual(external.read_bytes(),b'preserve')
