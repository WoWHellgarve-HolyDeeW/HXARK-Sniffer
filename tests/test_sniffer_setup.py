import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from iara.sniffer import prerequisites as p
from iara.sniffer.capture_files import capture_destination, shell_path


class Response(io.BytesIO):
    def __init__(self, data, *, url=p.INSTALLER_URL, length=None):
        super().__init__(data);self.url=url
        self.headers={} if length is None else {'Content-Length':str(length)}
    def geturl(self):return self.url


class SetupTests(unittest.TestCase):
    def test_clean_trust_store_uses_packaged_roots_and_keeps_verification(self):
        import ssl
        from iara.sniffer import transport
        empty = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(empty.cert_store_stats()['x509_ca'], 0)
        with patch.object(transport.ssl,'create_default_context',return_value=empty):
            context = transport.tls_context()
        self.assertGreater(context.cert_store_stats()['x509_ca'], 50)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_setup_diagnostics_do_not_expose_exception_content(self):
        import ssl
        import urllib.error
        secret='https://user:password@proxy.invalid/private'
        self.assertEqual(p.setup_failure(RuntimeError(secret)),'setup_internal_error')
        self.assertEqual(p.setup_failure(ValueError(secret)),'setup_internal_error')
        self.assertEqual(p.setup_failure(urllib.error.URLError(ssl.SSLCertVerificationError(secret))),
                         'certificate_verification_failed')
        self.assertEqual(p.setup_failure(PermissionError(secret)),'setup_access_denied')
        self.assertEqual(p.setup_failure(ValueError('setup_cancelled')),'setup_cancelled')

    def fixture(self, data=b'official-fixture', response=None, stop=None):
        stack = __import__('contextlib').ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(p,'INSTALLER_SIZE',len(data)))
        stack.enter_context(patch.object(p,'INSTALLER_SHA256',hashlib.sha256(data).hexdigest()))
        folder=Path(stack.enter_context(tempfile.TemporaryDirectory()))
        opener=Mock();opener.open.return_value=response or Response(data)
        return folder, opener, stop or threading.Event()

    def test_verified_download_and_cache_without_second_request(self):
        root,opener,stop=self.fixture();progress=[]
        out=p.download_installer(root,stop,progress.append,opener=opener)
        self.assertEqual(out.read_bytes(),b'official-fixture');self.assertEqual(progress[-1],100)
        self.assertEqual(p.download_installer(root,stop,opener=opener),out)
        self.assertEqual(opener.open.call_count,1);self.assertFalse(list(root.glob('*.partial')))

    def test_repair_incomplete_cache(self):
        root,opener,stop=self.fixture();(root/p.INSTALLER_NAME).write_bytes(b'broken')
        out=p.download_installer(root,stop,opener=opener)
        self.assertEqual(out.read_bytes(),b'official-fixture')

    def test_bad_digest_truncation_oversize_and_redirect_cleanup(self):
        for response in (Response(b'x'*16),Response(b'x'),Response(b'x'*200),
                         Response(b'official-fixture',length=40),
                         Response(b'official-fixture',url='https://evil.invalid/file')):
            with self.subTest(response=response):
                root,opener,stop=self.fixture(response=response)
                with self.assertRaises(ValueError):p.download_installer(root,stop,opener=opener)
                self.assertEqual(list(root.iterdir()),[])

    def test_cancel_and_network_failure_leave_no_installer(self):
        root,opener,stop=self.fixture();stop.set()
        with self.assertRaisesRegex(ValueError,'cancelled'):p.download_installer(root,stop,opener=opener)
        self.assertEqual(list(root.iterdir()),[])
        stop.clear();opener.open.side_effect=OSError('offline')
        with self.assertRaises(OSError):p.download_installer(root,stop,opener=opener)
        self.assertEqual(list(root.iterdir()),[])

    def test_hardlinked_cache_is_not_deleted_or_launched(self):
        root,opener,stop=self.fixture();original=root/'other';original.write_bytes(b'keep')
        os.link(original,root/p.INSTALLER_NAME)
        with self.assertRaisesRegex(ValueError,'linked'):p.download_installer(root,stop,opener=opener)
        self.assertEqual(original.read_bytes(),b'keep');opener.open.assert_not_called()

    def test_url_boundaries(self):
        for url in ('http://wireshark.org/x','https://wireshark.org.evil/x',
                    'https://evilwireshark.org/x','https://a@wireshark.org/x','https://wireshark.org:444/x'):
            self.assertFalse(p.approved_url(url))
        self.assertTrue(p.approved_url(p.INSTALLER_URL))
        with self.assertRaisesRegex(ValueError,'redirect'):
            p.OfficialRedirect().redirect_request(None,None,302,'',{},'https://evil.invalid/x')

    def test_nondefault_installation_is_detected_without_path_search(self):
        with tempfile.TemporaryDirectory() as d:
            custom=Path(d)/'custom/dumpcap.exe';custom.parent.mkdir();custom.write_bytes(b'test')
            with patch.object(p,'dumpcap_candidates',return_value=[Path(d)/'absent',custom]):
                self.assertEqual(p.find_dumpcap(),custom)

    def test_missing_support_and_working_driver(self):
        with patch.object(p,'find_dumpcap',side_effect=ValueError('capture_support_missing')):
            self.assertEqual(p.inspect_support(),{'state':'missing'})
        with patch.object(p,'find_dumpcap',return_value=Path('dumpcap.exe')),patch.object(p.subprocess,'run',return_value=Mock(returncode=0,stdout=b'1. \\Device\\NPF_Loopback')) as run:
            self.assertEqual(p.inspect_support(),{'state':'ready'})
            self.assertEqual(run.call_args.args[0],['dumpcap.exe','-D'])


class CaptureFilesTests(unittest.TestCase):
    def test_latest_saved_session_skips_empty_active_invalid_and_unsafe_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            good=root/'20261026-033819-0ef68a4e';good.mkdir();(good/'world-001.pkt').write_bytes(b'pkt')
            (good/'result.json').write_text(json.dumps({'captures':[{'file':'world-001.pkt'}]}))
            (root/'20261026-045452-3350f902').mkdir()
            bad=root/'20261026-055452-3350f902';bad.mkdir()
            (bad/'result.json').write_text(json.dumps({'captures':[{'file':'../world-001.pkt'}]}))
            self.assertEqual(capture_destination(root),good)

    def test_empty_folder_is_supported(self):
        with tempfile.TemporaryDirectory() as d:self.assertEqual(capture_destination(d),Path(d))

    def test_redirection_requires_same_directory_identity(self):
        with tempfile.TemporaryDirectory() as d:
            local=Path(d);source=local/'HXARK/Sniffer/captures';source.mkdir(parents=True)
            package=local/'Packages/Example.app/LocalCache/Local/HXARK/Sniffer/captures';package.mkdir(parents=True)
            self.assertEqual(shell_path(source,local=local),source)
            with patch.object(Path,'samefile',return_value=True):
                self.assertEqual(shell_path(source,local=local),package)
            self.assertEqual(shell_path(local/'unrelated',local=local),local/'unrelated')


@unittest.skipUnless(os.name=='nt','Tk UI test requires Windows')
class SetupInterfaceTests(unittest.TestCase):
    def exercise(self, cancelled, scaling=None):
        import tkinter as tk
        from contextlib import ExitStack
        from iara.sniffer import desktop
        with tempfile.TemporaryDirectory() as d, ExitStack() as stack:
            folder=Path(d);wow=folder/'Wow.exe';wow.write_bytes(b'fixture')
            root=tk.Tk();root.withdraw()
            if scaling is not None:root.tk.call('tk','scaling',scaling)
            stack.enter_context(patch.object(desktop.tk,'Tk',return_value=root))
            stack.enter_context(patch.object(desktop,'default_store',return_value=folder/'updates'))
            stack.enter_context(patch.object(desktop,'load_location',return_value=wow))
            stack.enter_context(patch.object(desktop,'fetch',side_effect=OSError('offline fixture')))
            stack.enter_context(patch.object(desktop,'inspect_support',side_effect=[{'state':'missing'},{'state':'ready'}]))
            download=stack.enter_context(patch.object(desktop,'download_installer',return_value=folder/'fixture.exe'))
            install=stack.enter_context(patch.object(desktop,'launch_installer',side_effect=ValueError('setup_cancelled') if cancelled else None))
            capture=stack.enter_context(patch('iara.sniffer.automatic.run_session',return_value={'reason':'user_stopped'}))
            state={'clicked':False,'finished':False,'layout':[]}
            def children(widget):
                for child in widget.winfo_children():
                    yield child;yield from children(child)
            def close():
                for pending in root.tk.call('after','info'):root.after_cancel(pending)
                root.destroy()
            def drive():
                labels={str(w.cget('text')):w for w in children(root) if 'text' in w.keys() and w.winfo_manager()}
                if not state['clicked'] and 'Install capture support' in labels:
                    panel=root.winfo_children()[0]
                    state['layout'].append((root.minsize(),(panel.winfo_reqwidth(),panel.winfo_reqheight())))
                    state['clicked']=True;labels['Install capture support'].invoke()
                if (cancelled and 'Retry setup' in labels) or (not cancelled and capture.called):
                    panel=root.winfo_children()[0]
                    state['layout'].append((root.minsize(),(panel.winfo_reqwidth(),panel.winfo_reqheight())))
                    state['finished']=True;close();return
                root.after(25,drive)
            root.after(30,drive);root.after(4000,close)
            desktop.start()
            self.assertTrue(state['clicked']);self.assertTrue(state['finished'])
            for minimum,required in state['layout']:
                self.assertGreaterEqual(minimum[0],required[0]);self.assertGreaterEqual(minimum[1],required[1])
            download.assert_called_once();install.assert_called_once()
            self.assertEqual(capture.call_count,0 if cancelled else 1)

    def test_installer_completion_automatically_starts_capture(self):self.exercise(False)
    def test_cancelled_installer_keeps_capture_stopped_and_offers_retry(self):self.exercise(True)

    def test_setup_controls_fit_native_font_scaling(self):
        for scale in (1.0,1.5,2.0,2.5):
            with self.subTest(scale=scale):self.exercise(True,scale)
