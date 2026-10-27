"""Detect capture support and download the official installer on request."""
import hashlib
import os
from pathlib import Path
import subprocess
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

INSTALLER_URL = 'https://2.na.dl.wireshark.org/win64/Wireshark-4.6.9-x64.exe'
INSTALLER_NAME = 'Wireshark-4.6.9-x64.exe'
INSTALLER_SIZE = 97931232
INSTALLER_SHA256 = 'bf9b5ce8a89f244c376a9b1a946276eaa06463dde3e33069a34d7f102f5878cf'
# Pinned from https://www.wireshark.org/download/src/all-versions/SIGNATURES-4.6.9.txt


def setup_failure(exc):
    """Map exceptions to fixed codes to avoid leaking proxy credentials."""
    if isinstance(exc, urllib.error.URLError):
        exc = exc.reason
    if isinstance(exc, ssl.SSLCertVerificationError):
        return 'certificate_verification_failed'
    if isinstance(exc, ssl.SSLError):return 'secure_connection_failed'
    if isinstance(exc, PermissionError):return 'setup_access_denied'
    if isinstance(exc, TimeoutError):return 'installer_timeout'
    if isinstance(exc, OSError):return 'network_or_file_unavailable'
    known = {'setup_cancelled','installer_redirect_rejected','installer_verification_failed',
             'linked_installer','installer_timeout','installer_launch_failed','installer_wait_failed'}
    return str(exc) if isinstance(exc, ValueError) and str(exc) in known else 'setup_internal_error'


def dumpcap_candidates():
    paths = []
    if os.name == 'nt':
        import winreg
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Wireshark', 0,
                                    winreg.KEY_READ | view) as key:
                    location, _ = winreg.QueryValueEx(key, 'InstallDir')
                    if isinstance(location, str) and Path(location).is_absolute():
                        paths.append(Path(location)/'dumpcap.exe')
            except OSError:
                pass
    for name in ('ProgramW6432', 'ProgramFiles'):
        base = os.environ.get(name)
        if base and Path(base).is_absolute():
            paths.append(Path(base)/'Wireshark/dumpcap.exe')
    paths.append(Path(r'C:\Program Files\Wireshark\dumpcap.exe'))
    return list(dict.fromkeys(paths))


def find_dumpcap():
    for path in dumpcap_candidates():
        if path.is_file():
            return path
    raise ValueError('capture_support_missing')


def inspect_support():
    try:
        path = find_dumpcap()
    except ValueError:
        return {'state':'missing'}
    try:
        result = subprocess.run([str(path), '-D'], capture_output=True, timeout=10,
                                creationflags=0x08000000 if os.name=='nt' else 0)
        if result.returncode == 0 and b'\\Device\\NPF_' in result.stdout:
            return {'state':'ready'}
    except (OSError, subprocess.TimeoutExpired):
        pass
    driver = Path(os.environ.get('SystemRoot', r'C:\Windows'))/'System32/Npcap/wpcap.dll'
    return {'state':'unavailable' if driver.is_file() else 'missing'}


def approved_url(url):
    value = urlsplit(url)
    return (value.scheme == 'https' and value.hostname is not None and
            (value.hostname == 'wireshark.org' or value.hostname.endswith('.wireshark.org')) and
            not value.username and not value.password and value.port in (None,443))


class OfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not approved_url(newurl):
            raise ValueError('installer_redirect_rejected')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def verify_installer(path):
    path = Path(path)
    if (path.is_symlink() or getattr(path.lstat(),'st_file_attributes',0)&0x400 or
            path.stat().st_nlink != 1 or path.stat().st_size != INSTALLER_SIZE):
        raise ValueError('installer_verification_failed')
    with path.open('rb') as f:
        if hashlib.file_digest(f,'sha256').hexdigest() != INSTALLER_SHA256:
            raise ValueError('installer_verification_failed')


def download_installer(folder, stop, progress=lambda n:None, *, opener=None):
    from .updates import safe_store
    folder = safe_store(folder)
    target = folder/INSTALLER_NAME
    if target.is_symlink() or (target.exists() and (target.stat().st_nlink != 1 or
            getattr(target.lstat(), 'st_file_attributes', 0) & 0x400)):
        raise ValueError('linked_installer')
    if target.exists():
        try:
            verify_installer(target)
            return target
        except ValueError:
            target.unlink()  # Use a fresh temporary file in the checked installer cache.
    import tempfile
    started = time.monotonic()
    if opener is None:
        from .transport import tls_context
        opener = urllib.request.build_opener(
            OfficialRedirect(), urllib.request.HTTPSHandler(context=tls_context()))
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=folder, suffix='.partial', delete=False) as out:
            temporary = Path(out.name)
            with opener.open(INSTALLER_URL, timeout=15) as response:
                if not approved_url(response.geturl()):
                    raise ValueError('installer_redirect_rejected')
                size = response.headers.get('Content-Length')
                if size is not None and int(size) != INSTALLER_SIZE:
                    raise ValueError('installer_verification_failed')
                total = 0
                while True:
                    if stop.is_set():raise ValueError('setup_cancelled')
                    if time.monotonic()-started > 300:raise ValueError('installer_timeout')
                    chunk = response.read(256*1024)
                    if not chunk:break
                    total += len(chunk)
                    if total > INSTALLER_SIZE:raise ValueError('installer_verification_failed')
                    out.write(chunk);progress(total*100//INSTALLER_SIZE)
        verify_installer(temporary)
        if stop.is_set():raise ValueError('setup_cancelled')
        # Do not replace another process's installer.
        if target.exists():
            verify_installer(target)
        else:
            temporary.rename(target)
        return target
    finally:
        if temporary is not None and temporary.exists():temporary.unlink()


def launch_installer(path, stop):
    verify_installer(path)
    from .capture_files import shell_path
    path = shell_path(path)
    # Launch the hash-checked vendor installer interactively for UAC and setup.
    import ctypes as c
    from ctypes import wintypes as w
    class ExecuteInfo(c.Structure):
        _fields_ = [('cbSize',w.DWORD),('fMask',w.ULONG),('hwnd',w.HWND),
                    ('lpVerb',w.LPCWSTR),('lpFile',w.LPCWSTR),('lpParameters',w.LPCWSTR),
                    ('lpDirectory',w.LPCWSTR),('nShow',c.c_int),('hInstApp',w.HINSTANCE),
                    ('lpIDList',w.LPVOID),('lpClass',w.LPCWSTR),('hkeyClass',w.HKEY),
                    ('dwHotKey',w.DWORD),('hIcon',w.HANDLE),('hProcess',w.HANDLE)]
    shell=c.WinDLL('shell32',use_last_error=True);kernel=c.WinDLL('kernel32',use_last_error=True)
    shell.ShellExecuteExW.argtypes=[c.POINTER(ExecuteInfo)];shell.ShellExecuteExW.restype=w.BOOL
    kernel.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];kernel.WaitForSingleObject.restype=w.DWORD
    kernel.CloseHandle.argtypes=[w.HANDLE];kernel.CloseHandle.restype=w.BOOL
    info=ExecuteInfo();info.cbSize=c.sizeof(info);info.fMask=0x40|0x100
    info.lpVerb='open';info.lpFile=str(Path(path).absolute());info.lpDirectory=str(Path(path).parent);info.nShow=1
    if stop.is_set():raise ValueError('setup_cancelled')
    if not shell.ShellExecuteExW(c.byref(info)):
        code=c.get_last_error()
        if code==1223:raise ValueError('setup_cancelled')
        raise OSError(code,'installer_launch_failed')
    if not info.hProcess:raise ValueError('installer_launch_failed')
    try:
        while not stop.is_set():
            state=kernel.WaitForSingleObject(info.hProcess,250)
            if state==0:return
            if state!=258:raise ValueError('installer_wait_failed')
        raise ValueError('setup_cancelled')
    finally:
        kernel.CloseHandle(info.hProcess)
