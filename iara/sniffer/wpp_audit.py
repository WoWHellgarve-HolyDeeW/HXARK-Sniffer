"""Aggregate WPP parser results and record coverage."""

import json


_STATUSES = ("Success", "WithErrors", "NotParsed", "NoStructure", "None")
_ROW_KEYS = frozenset(("index", "opcode", "direction", "status", "remaining"))


def summarize(rows, expected_records):
    """Validate audit rows and report ordinal coverage, not semantic correctness."""
    if type(expected_records) is not int or not 0 <= expected_records <= 1000000:
        raise ValueError("invalid_expected_records")

    seen = bytearray(expected_records)
    counts = dict.fromkeys(_STATUSES, 0)
    groups = {}
    observed = 0
    remaining_bytes = 0
    try:
        iterator = iter(rows)
    except TypeError:
        raise ValueError("invalid_audit_row") from None

    for row in iterator:
        if not isinstance(row, dict) or row.keys() != _ROW_KEYS:
            raise ValueError("invalid_audit_row")
        index = row["index"]
        opcode = row["opcode"]
        direction = row["direction"]
        status = row["status"]
        remaining = row["remaining"]
        if (
            type(index) is not int
            or not 0 <= index < expected_records
            or type(opcode) is not int
            or not 0 <= opcode <= 0xffffffff
            or type(direction) is not str
            or direction not in ("client", "server")
            or type(status) is not str
            or status not in _STATUSES
            or type(remaining) is not int
            or not 0 <= remaining <= 16777216
            or (status == "Success" and remaining != 0)
        ):
            raise ValueError("invalid_audit_row")
        if seen[index]:
            raise ValueError("invalid_audit_row")

        key = (direction, opcode)
        if key not in groups:
            if len(groups) >= 4096:
                raise ValueError("opcode_limit")
            groups[key] = {
                "direction": direction,
                "opcode": opcode,
                "counts": dict.fromkeys(_STATUSES, 0),
                "remaining_bytes": 0,
            }
        group = groups[key]
        seen[index] = 1
        observed += 1
        counts[status] += 1
        remaining_bytes += remaining
        group["counts"][status] += 1
        group["remaining_bytes"] += remaining

    return {
        "expected": expected_records,
        "observed": observed,
        "complete": observed == expected_records,
        "counts": counts,
        "remaining_bytes": remaining_bytes,
        "opcodes": [groups[key] for key in sorted(groups)],
    }


def read_jsonl(stream, expected_records):
    """Read a binary metadata stream. Reject duplicate keys and oversized rows.

This validates declared parser observations, not their provenance. The caller
must bind the audit to the actual input hash and pinned parser invocation.
"""
    def object_pairs(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError('invalid_audit_row')
            out[key] = value
        return out

    def rows():
        total = 0
        while True:
            line = stream.readline(1025)
            if not line:
                return
            total += len(line)
            if len(line) > 1024 or total > 128 * 1024 * 1024:
                raise ValueError('audit_size_limit')
            try:
                yield json.loads(line.decode('utf-8'), object_pairs_hook=object_pairs)
            except (ValueError, UnicodeError, RecursionError):
                raise ValueError('invalid_audit_row') from None

    return summarize(rows(), expected_records)
