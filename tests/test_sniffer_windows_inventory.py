from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from iara.sniffer.windows_inventory import inventory


EXTERNAL={'client':['192.0.2.1',50000],'server':['203.0.113.8',3724]}
LOCAL={'client':['127.0.0.1',1234],'server':['127.0.0.1',5678]}


class WindowsInventoryTests(unittest.TestCase):
    def invoke(self,rows,adapters=None,pids=(81,81)):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'Wow.exe';path.write_bytes(b'fictitious image')
            with patch('iara.sniffer.windows_inventory.find_process',side_effect=pids),patch('iara.sniffer.windows_inventory.fixed_version',return_value=(70575,[1201,5,7057,5])),patch('iara.sniffer.windows_inventory.tcp_rows',return_value=deepcopy(rows)),patch('iara.sniffer.windows_inventory.adapter_addresses',return_value=adapters if adapters is not None else {'192.0.2.1':'test-interface'}):
                return inventory(path)

    def test_excludes_loopback_explicitly_without_broadening(self):
        value=self.invoke([EXTERNAL,LOCAL]);self.assertEqual(value['excluded_loopback_connections'],1)
        self.assertEqual(value['connections'],[dict(EXTERNAL,interface='test-interface')])
        self.assertEqual(value['sha256'],hashlib.sha256(b'fictitious image').hexdigest())

    def test_all_local_has_no_capture_scope(self):
        value=self.invoke([LOCAL]);self.assertEqual(value['connections'],[])
        self.assertEqual(value['excluded_loopback_connections'],1)

    def test_missing_external_adapter_fails_closed(self):
        with self.assertRaisesRegex(ValueError,'game_adapter_unavailable'):self.invoke([EXTERNAL],adapters={})

    def test_process_change_rejected(self):
        with self.assertRaisesRegex(ValueError,'game_process_changed'):self.invoke([EXTERNAL],pids=(81,82))

    def test_empty_inventory_stays_empty(self):
        self.assertEqual(self.invoke([])['connections'],[])

    def test_native_path_does_not_invoke_shell(self):
        from scripts.sniffer_capture_wow import inventory as capture_inventory
        with patch('iara.sniffer.windows_inventory.inventory',return_value={'ok':True}) as native,patch('subprocess.run') as shell:
            self.assertEqual(capture_inventory(Path('Wow.exe')),{'ok':True})
            native.assert_called_once();shell.assert_not_called()
