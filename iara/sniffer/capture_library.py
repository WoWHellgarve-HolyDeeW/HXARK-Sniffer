"""Export finalized PKTs and label filenames from recognized location packets.

Unknown locations use numeric IDs or a neutral filename.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import tempfile

from .updates import safe_store

MAX_BYTES = 1024**3
SESSION = re.compile(r'\d{8}-\d{6}-[a-f0-9]{8}')
# Known labels; unknown locations keep their numeric IDs.
MAP_NAMES = {0: 'Eastern-Kingdoms', 1: 'Kalimdor', 2771: 'Voidstorm'}
AREA_NAMES = {(1, 14): 'Durotar', (1, 1637): 'Orgrimmar'}


def _regular(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError('linked_capture_file')
    for parent in path.parents:
        if parent.is_symlink() or getattr(parent.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('linked_capture_directory')
    return info


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def describe_capture(source):
    """Read location headers from a validated PKT.

    Unknown or malformed locations use a fallback filename. No payload is changed.
    """
    source = Path(source)
    before = _regular(source)
    if not 66 <= before.st_size <= MAX_BYTES:
        raise ValueError('capture_size_limit')
    maps, areas = [], []
    uncertain = False
    with source.open('rb') as stream:
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ValueError('capture_changed')
        header = stream.read(66)
        if header[:6] != b'PKT\x01\x03\x00' or struct.unpack_from('<i', header, 62)[0] != 0:
            raise ValueError('unsupported_capture_container')
        build = struct.unpack_from('<I', header, 6)[0]
        started = struct.unpack_from('<I', header, 54)[0]
        offset, records = 66, 0
        while offset < before.st_size:
            if records >= 1000000:
                raise ValueError('capture_record_limit')
            stream.seek(offset)
            raw = stream.read(20)
            if len(raw) != 20:
                raise ValueError('truncated_capture')
            direction, _, _, extra, length = struct.unpack('<IiIii', raw)
            end = offset + 20 + extra + length
            if (direction not in (0x47534d53, 0x47534d43) or extra < 0 or length < 4
                    or end > before.st_size):
                raise ValueError('invalid_capture_record')
            stream.seek(offset + 20 + extra)
            opcode = struct.unpack('<I', stream.read(4))[0]
            if direction == 0x47534d53 and build == 70575:
                location = None
                if opcode == 0x4501f0:  # SMSG_INIT_WORLD_STATES
                    if length - 4 < 16:
                        uncertain = True
                    else:
                        map_id, area, subarea, count = struct.unpack('<iiiI', stream.read(16))
                        if length - 4 != 16 + count * 8 or min(map_id, area, subarea) < 0:
                            uncertain = True
                        else:
                            location = map_id
                            if area and (map_id, area) not in areas:
                                if len(areas) < 256:
                                    areas.append((map_id, area))
                                else:
                                    uncertain = True
                elif opcode in (0x45002f, 0x45002b):  # LOGIN_VERIFY_WORLD / NEW_WORLD
                    expected = 24 if opcode == 0x45002f else 56
                    if length - 4 != expected:
                        uncertain = True
                    else:
                        location = struct.unpack('<i', stream.read(4))[0]
                        if location < 0:
                            uncertain, location = True, None
                if location is not None and location not in maps:
                    if len(maps) < 256:
                        maps.append(location)
                    else:
                        uncertain = True
            offset, records = end, records + 1
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ValueError('capture_changed')
    if _identity(source.stat()) != _identity(before):
        raise ValueError('capture_changed')
    label = 'Capture'
    if not uncertain:
        if areas:
            map_id, area = areas[0]
            label = AREA_NAMES.get((map_id, area), f'{MAP_NAMES.get(map_id, f"Map-{map_id}")}-area-{area}')
        elif maps:
            label = MAP_NAMES.get(maps[0], f'Map-{maps[0]}')
        if len(maps) > 1 or len(areas) > 1:
            label += '-and-more'
    return {'build': build, 'started_utc': datetime.fromtimestamp(started, timezone.utc).strftime('%Y%m%d-%H%M%SZ'),
            'label': label, 'maps': maps, 'areas': [list(a) for a in areas],
            'location_hint_only': True, 'location_uncertain': uncertain,
            'records': records, 'bytes': before.st_size}


def _hash(path):
    _regular(path)
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def publish_capture(source, dumps, session, sequence, expected_sha256, *, remove_source=False):
    """Export an independent copy atomically, without overwriting existing files."""
    if not SESSION.fullmatch(session) or type(sequence) is not int or not 1 <= sequence <= 256:
        raise ValueError('invalid_capture_identity')
    if type(expected_sha256) is not str or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
        raise ValueError('missing_capture_digest')
    source = Path(source)
    before = _regular(source)
    details = describe_capture(source)
    dumps = safe_store(dumps)
    name = f'{details["label"]}_b{details["build"]}_{details["started_utc"]}_{session[-8:]}_{sequence:03d}.pkt'
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,180}\.pkt', name):
        raise ValueError('invalid_capture_name')
    destination = dumps / name
    if source.resolve() == destination.resolve():
        raise ValueError('capture_source_is_destination')
    if destination.exists() or destination.is_symlink():
        if _hash(destination) != expected_sha256 or _hash(source) != expected_sha256:
            raise ValueError('capture_name_collision')
    else:
        if shutil.disk_usage(dumps).free < before.st_size + 64*1024**2:
            raise ValueError('insufficient_export_disk')
        staging = safe_store(dumps.parent/'private-exports')
        fd, temporary_name = tempfile.mkstemp(prefix='pkt-', suffix='.partial', dir=staging)
        temporary = Path(temporary_name)
        try:
            digest = hashlib.sha256()
            with os.fdopen(fd, 'wb') as target, source.open('rb') as origin:
                if _identity(os.fstat(origin.fileno())) != _identity(before):
                    raise ValueError('capture_changed')
                remaining = before.st_size
                while remaining:
                    chunk = origin.read(min(1024*1024, remaining))
                    if not chunk:
                        raise ValueError('capture_changed')
                    digest.update(chunk)
                    target.write(chunk)
                    remaining -= len(chunk)
                if origin.read(1) or _identity(os.fstat(origin.fileno())) != _identity(before):
                    raise ValueError('capture_changed')
                target.flush()
                os.fsync(target.fileno())
            if digest.hexdigest() != expected_sha256 or _identity(source.stat()) != _identity(before):
                raise ValueError('capture_digest_mismatch')
            try:
                os.link(temporary, destination)  # fails instead of replacing an existing PKT
            except FileExistsError:
                if _hash(destination) != expected_sha256:
                    raise ValueError('capture_name_collision') from None
        finally:
            temporary.unlink(missing_ok=True)
    if remove_source:
        # Preserve the export record if staging cleanup fails.
        try:
            if _identity(source.stat()) == _identity(before):
                source.unlink()
        except OSError:
            pass
    return {'file': name, 'storage': 'dumps', 'location': details, 'sha256': expected_sha256}


def _json(path):
    _regular(path)
    with path.open('rb') as stream:
        raw = stream.read(1024*1024+1)
    if len(raw) > 1024*1024:
        raise ValueError('receipt_size_limit')
    return json.loads(raw)


def migrate_legacy(captures, dumps):
    """Import validated legacy PKTs while preserving the originals.

    Saved mappings prevent reimporting files the user has deleted from dumps.
    """
    captures, dumps = safe_store(captures), safe_store(dumps)
    result = {'exported': 0, 'failed': 0}
    for session in sorted(captures.iterdir()):
        if not SESSION.fullmatch(session.name) or not session.is_dir() or session.is_symlink():
            continue
        receipt = session/'result.json'
        if not receipt.exists():
            continue  # an active or interrupted session is not a completed capture
        try:
            value = _json(receipt)
            items = value.get('captures', [])
            if not isinstance(items, list) or len(items) > 256:
                raise ValueError('invalid_capture_receipt')
            marker = session/'dumps-export.json'
            previous = _json(marker) if marker.exists() else {}
            if not isinstance(previous, dict):
                raise ValueError('invalid_export_receipt')
            changed = False
            for item in items:
                if not isinstance(item, dict) or item.get('ok') is not True or item.get('storage') == 'dumps':
                    continue
                name = item.get('file', '')
                if type(name) is not str or not re.fullmatch(r'world-\d{3}\.pkt', name):
                    raise ValueError('invalid_capture_name')
                digest = item.get('receipt', {}).get('pkt_sha256')
                if previous.get(name, {}).get('sha256') == digest and digest:
                    continue
                published = publish_capture(session/name, dumps, session.name, int(name[6:9]), digest)
                previous[name] = published
                changed = True
                result['exported'] += 1
            if changed:
                if marker.exists():
                    _regular(marker)
                fd, temporary = tempfile.mkstemp(prefix='export-', suffix='.tmp', dir=session)
                try:
                    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                        json.dump(previous, stream, indent=2)
                        stream.flush();os.fsync(stream.fileno())
                    os.replace(temporary, marker)
                finally:
                    Path(temporary).unlink(missing_ok=True)
        except (OSError, ValueError, TypeError, AttributeError):
            result['failed'] += 1
    return result
