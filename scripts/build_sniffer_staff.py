"""Build the Windows EXE or an unpacked development bundle."""
import argparse
import hashlib
from importlib.metadata import distribution,version
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from iara.sniffer.trust import APP_VERSION


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--layout',choices=('onefile','onedir'),default='onefile')
    layout=parser.parse_args(argv).layout
    if os.name!='nt':raise ValueError('windows_builder_required')
    if version('pyinstaller')!='6.22.3':raise ValueError('unreviewed_builder_version')
    if not re.fullmatch(r'\d+\.\d+\.\d+-beta',APP_VERSION):raise ValueError('invalid_release_version')
    destination=ROOT/'dist/sniffer-staff'/APP_VERSION.split('-')[0]/layout
    work=ROOT/'.iara/sniffer-release/build'/APP_VERSION/layout
    assets=ROOT/'.iara/sniffer-release/assets'/APP_VERSION
    # Keep PyInstaller output inside the fixed build directories.
    for p,parent in [(destination,ROOT/'dist'),(work,ROOT/'.iara'),(assets,ROOT/'.iara')]:
        if not p.resolve().is_relative_to(parent.resolve()):raise ValueError('unsafe_build_path')
    resources={'QUICK-START.txt':ROOT/'assets/QUICK-START.txt',
               'hxark-mark.png':ROOT/'assets/hxark-mark.png',
               'licenses/HXARK-Sniffer-LICENSE.txt':ROOT/'LICENSE',
               'licenses/HXARK-THIRD-PARTY.txt':ROOT/'NOTICE',
               'licenses/Python-LICENSE.txt':Path(sys.base_prefix)/'LICENSE.txt'}
    for name in ('pyinstaller','cryptography','cffi','certifi','pillow','altgraph','packaging',
                 'pefile','pycparser','pyinstaller-hooks-contrib','pywin32-ctypes','setuptools'):
        d=distribution(name)
        for p in d.files:
            if 'license' in p.name.lower() or 'copying' in p.name.lower():
                resources['licenses/'+name+'-'+p.name]=d.locate_file(p)
    for name,source in resources.items():
        target=assets/name;target.parent.mkdir(parents=True,exist_ok=True)
        if target.is_symlink():raise ValueError('linked_distribution_file')
        shutil.copyfile(source,target)
    for p in assets.rglob('*'):
        if p.is_symlink() or getattr(p.lstat(),'st_file_attributes',0)&0x400:raise ValueError('linked_distribution_file')
        if p.is_file() and p.relative_to(assets).as_posix() not in resources:raise ValueError('unexpected_resource')
    log=work/'build.log';log.parent.mkdir(exist_ok=True,parents=True)
    cmd=[sys.executable,'-B','-m','PyInstaller','--noconfirm','--'+layout,'--windowed',
        '--icon',str(resources['hxark-mark.png']),
        '--name','HXARKSniffer','--distpath',str(destination),'--workpath',str(work),
        '--specpath',str(log.parent),'--paths',str(ROOT),'--add-data',str(assets)+';hxark-sniffer',
        str(ROOT/'scripts/sniffer_staff.py')]
    with log.open('w',encoding='utf-8') as f:
        subprocess.run(cmd,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT,check=True,timeout=180,creationflags=0x08000000)
    package=destination/'HXARKSniffer' if layout=='onedir' else destination
    exe=package/'HXARKSniffer.exe'
    with tempfile.TemporaryDirectory(prefix='hxark-sniffer-check-') as tmp:
        checks={}
        for command in ('version','ui-check'):
            receipt=Path(tmp)/(command+'.json')
            subprocess.run([str(exe),'--result',str(receipt),command],cwd=tmp,check=True,timeout=30,creationflags=0x08000000)
            checks[command]=json.loads(receipt.read_text())
        if checks['version']['version']!=APP_VERSION or checks['ui-check']['ui_initialized'] is not True:
            raise ValueError('compiled_smoke_failed')
    sources=[ROOT/'scripts'/name for name in ('sniffer_staff.py','sniffer_record.py','sniffer_capture_start.py',
        'sniffer_session_snapshot.py','sniffer_decode_session.py','sniffer_start_loopback_probe.py','sniffer_auto_probe.py')]
    sources+=list((ROOT/'iara/sniffer').glob('*.py'))+[ROOT/'iara/capture_inspector.py']
    manifest={'version':APP_VERSION,'channel':'beta','layout':layout,'python':sys.version.split()[0],
        'pyinstaller':version('pyinstaller'),'cryptography':version('cryptography'),'certifi':version('certifi'),
        'sources':{str(p.relative_to(ROOT)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        'resources':{n:hashlib.sha256(p.read_bytes()).hexdigest() for n,p in resources.items()},
        'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'checks':checks,
        'contains_private_capture':False,'contains_signing_key':False,
        'authenticode_signed':False,'end_to_end_gui_capture_verified':False}
    if layout=='onefile':
        artifact=ROOT/'dist'/('HXARK-Sniffer-'+APP_VERSION+'-Windows-x64.exe')
        shutil.copyfile(exe,artifact)
        artifact.with_suffix('.exe.build.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
        checksum=hashlib.sha256(artifact.read_bytes()).hexdigest()
        artifact.with_suffix('.exe.sha256').write_text(checksum+'  '+artifact.name+'\n')
        print(json.dumps({'executable':str(artifact),'bytes':artifact.stat().st_size,'sha256':checksum,
            'compiled_checks_passed':True,'layout':layout}))
        return
    (package/'BUILD.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    archive=ROOT/'dist'/('HXARK-Sniffer-'+APP_VERSION+'-Windows-x64.zip')
    temp=archive.with_suffix('.zip.partial')
    try:
        with zipfile.ZipFile(temp,'w',zipfile.ZIP_DEFLATED) as z:
            for file in sorted(package.rglob('*')):
                if file.is_symlink() or getattr(file.lstat(),'st_file_attributes',0)&0x400:
                    raise ValueError('linked_distribution_file')
                if not file.is_file():continue
                if file.suffix.lower() in ('.pkt','.pcap','.dpapi','.sqlite3','.pem') or file.name.startswith('private-'):
                    raise ValueError('private_distribution_file')
                z.write(file,'HXARKSniffer/'+file.relative_to(package).as_posix())
        with zipfile.ZipFile(temp) as z:
            if z.testzip() is not None:raise ValueError('archive_check_failed')
        os.replace(temp,archive)
    finally:
        if temp.exists():temp.unlink()
    checksum=hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.zip.sha256').write_text(checksum+'  '+archive.name+'\n')
    print(json.dumps({'archive':str(archive),'bytes':archive.stat().st_size,'sha256':checksum,
        'compiled_checks_passed':True}))


if __name__=='__main__':main()
