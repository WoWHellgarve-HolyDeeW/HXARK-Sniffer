"""Signed profile updates with atomic storage and rollback checks."""
from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit
from .catalog import verify,MAX_CATALOG,canonical


def default_store():
    return Path(os.environ.get('LOCALAPPDATA',str(Path.home()/'.local/share')))/'HXARK'/'Sniffer'/'updates'


def safe_store(root):
    root=Path(root).absolute()
    for p in [root,*root.parents]:
        if p.exists() and (p.is_symlink() or getattr(p.lstat(),'st_file_attributes',0)&0x400):
            raise ValueError('linked_update_store')
    root.mkdir(parents=True,exist_ok=True)
    return root


def read_bounded(path):
    if path.is_symlink() or (path.exists() and (path.stat().st_nlink!=1 or getattr(path.lstat(),'st_file_attributes',0)&0x400)):
        raise ValueError('linked_update_file')
    with path.open('rb') as f:value=f.read(MAX_CATALOG+1)
    if len(value)>MAX_CATALOG:raise ValueError('catalog_size_limit')
    return value


@contextmanager
def update_lock(root):
    path=root/'update.lock'
    if path.is_symlink() or path.exists() and (path.stat().st_nlink!=1 or getattr(path.lstat(),'st_file_attributes',0)&0x400):
        raise ValueError('linked_update_file')
    with path.open('a+b') as f:
        # Do not append on every use (a+b ignores seek for writes).
        if f.seek(0,2)==0:f.write(b'0');f.flush()
        f.seek(0)
        if os.name=='nt':
            import msvcrt
            try:msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
            except OSError:raise ValueError('update_in_progress') from None
        else:
            import fcntl
            try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError:raise ValueError('update_in_progress') from None
        try:yield
        finally:
            if os.name=='nt':f.seek(0);msvcrt.locking(f.fileno(),msvcrt.LK_UNLCK,1)
            else:fcntl.flock(f,fcntl.LOCK_UN)


def apply(raw,root,public_key,*,now=None):
    now=time.time() if now is None else now
    value=verify(raw,public_key,now=now)
    root=safe_store(root);target=root/'installed.json'
    with update_lock(root):
        if target.exists():
            previous=verify(read_bounded(target),public_key,now=now,allow_expired=True)
            if value['revision']<previous['revision']:raise ValueError('catalog_rollback')
            if value['revision']==previous['revision']:
                if canonical(value)!=canonical(previous):raise ValueError('catalog_revision_conflict')
                return {'updated':False,'revision':value['revision'],'profiles':len(value['profiles'])}
        descriptor,name=tempfile.mkstemp(prefix='catalog-',suffix='.tmp',dir=root)
        try:
            with os.fdopen(descriptor,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
            os.replace(name,target)
        finally:
            if os.path.exists(name):os.unlink(name)
    return {'updated':True,'revision':value['revision'],'profiles':len(value['profiles'])}


def installed(root,public_key):
    path=Path(root)/'installed.json'
    if not path.exists():return []
    # Already installed known-good profiles remain usable offline after expiry.
    return verify(read_bounded(path),public_key,now=time.time(),allow_expired=True)['profiles']


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('update_redirect_refused')


def fetch(url):
    value=urlsplit(url)
    if (value.scheme!='https' or not value.hostname or value.username or value.password or
            value.fragment or value.query or value.port not in (None,443)):
        raise ValueError('invalid_update_url')
    request=urllib.request.Request(url,headers={'User-Agent':'HXARK-Sniffer/0.1 staff','Accept':'application/json'})
    from .transport import tls_context
    with urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=tls_context())).open(request,timeout=5) as response:
        raw=response.read(MAX_CATALOG+1)
    if len(raw)>MAX_CATALOG:raise ValueError('catalog_size_limit')
    return raw
