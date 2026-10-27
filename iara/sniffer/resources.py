"""Bundled icon, quick start and license files."""
from pathlib import Path
import sys


def brand_icon():
    if getattr(sys,'frozen',False):
        return Path(sys._MEIPASS)/'hxark-sniffer'/'hxark-mark.png'
    return Path(__file__).resolve().parents[2]/'assets/hxark-mark.png'


def documents():
    if getattr(sys,'frozen',False):
        root=Path(sys._MEIPASS)/'hxark-sniffer'
        instructions=(root/'QUICK-START.txt').read_text(encoding='utf-8')
        licenses=sorted((root/'licenses').glob('*'))
        if not licenses:raise ValueError('bundled_licenses_missing')
        license_text='\n\n'.join(p.name+'\n'+'='*60+'\n'+p.read_text(encoding='utf-8',errors='replace') for p in licenses)
    else:
        instructions=(Path(__file__).resolve().parents[2]/'assets/QUICK-START.txt').read_text(encoding='utf-8')
        license_text='Development mode. Release builds include the Python, PyInstaller, cryptography and cffi license texts.'
    return instructions,license_text
