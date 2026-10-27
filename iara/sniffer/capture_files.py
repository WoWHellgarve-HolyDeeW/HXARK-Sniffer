"""Locate saved PKTs, including redirected Windows app storage."""
import json
import os
from pathlib import Path
import re


def shell_path(path, *, local=None):
    path = Path(path).absolute()
    local = Path(local or os.environ.get('LOCALAPPDATA', Path.home()))
    try:
        relative = path.relative_to(local)
    except ValueError:
        return path
    # Packaged apps can redirect AppData. Resolve only this package's directory.
    if relative.parts[:2] != ('HXARK', 'Sniffer'):
        return path
    packages = local/'Packages'
    if packages.is_dir():
        for package in packages.iterdir():
            candidate = package/'LocalCache/Local'/relative
            try:
                if candidate.samefile(path):
                    return candidate
            except OSError:
                pass
    return path


def capture_destination(root, *, dumps=None):
    """Find the latest saved session, skipping empty armed directories."""
    if dumps is not None:
        from .updates import safe_store
        return shell_path(safe_store(dumps))
    root = Path(root)
    for directory in sorted(root.iterdir(), key=lambda p:p.name, reverse=True):
        if not re.fullmatch(r'\d{8}-\d{6}-[a-f0-9]{8}', directory.name) or directory.is_symlink():
            continue
        try:
            receipt = directory/'result.json'
            if receipt.stat().st_size > 1024*1024:
                continue
            value = json.loads(receipt.read_text(encoding='utf-8'))
            captures = value.get('captures', [])
            if not isinstance(captures, list):
                continue
            for item in captures:
                name = item.get('file', '') if isinstance(item, dict) else ''
                if re.fullmatch(r'world-\d{3}\.pkt', name) and (directory/name).is_file():
                    return shell_path(directory)
        except (OSError, ValueError, AttributeError, TypeError):
            continue
    return shell_path(root)
