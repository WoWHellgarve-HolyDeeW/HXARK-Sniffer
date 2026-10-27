"""Bounded in-memory TCP reassembly."""


_MODULUS = 1 << 32
_HALF_RANGE = 1 << 31


def _integer(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(name)
    return value


class TCPStream:
    """Reassemble payload beginning at an explicitly supplied TCP sequence.

    Pending ranges use unwrapped positions and contain only unique, un-emitted
    bytes. History is a contiguous suffix of emitted data, not queued data.
    """

    def __init__(self, first_sequence, max_buffer=1048576, max_segments=128,
                 history_limit=65536):
        _integer(first_sequence, 0, _MODULUS - 1, 'first_sequence')
        _integer(max_buffer, 1, 1048576, 'max_buffer')
        _integer(max_segments, 1, 1024, 'max_segments')
        _integer(history_limit, 1, 1048576, 'history_limit')
        self._next = first_sequence
        self._max_buffer = max_buffer
        self._max_segments = max_segments
        self._history_limit = history_limit
        self._history = b''
        self._pending = []
        self._buffered = 0

    @property
    def next_sequence(self):
        return self._next % _MODULUS

    @property
    def buffered_bytes(self):
        return self._buffered

    def feed(self, sequence, payload):
        """Return newly contiguous bytes, committing only after all checks pass."""
        _integer(sequence, 0, _MODULUS - 1, 'sequence')
        if type(payload) is not bytes or len(payload) > self._max_buffer:
            raise ValueError('payload')
        if not payload:
            return b''

        delta = (sequence - self.next_sequence) % _MODULUS
        if delta == _HALF_RANGE:
            raise ValueError('ambiguous_sequence')
        if delta > _HALF_RANGE:
            delta -= _MODULUS
        start = self._next + delta
        end = start + len(payload)
        if delta > self._max_buffer or end > self._next + self._max_buffer:
            raise ValueError('buffer_limit')

        history_start = self._next - len(self._history)
        if start < history_start:
            raise ValueError('history_unavailable')
        if start < self._next:
            overlap_end = min(end, self._next)
            if (payload[:overlap_end - start] !=
                    self._history[start - history_start:overlap_end - history_start]):
                raise ValueError('conflicting_overlap')

        # Validate every queued overlap, including after a retransmitted prefix.
        for position, data in self._pending:
            left = max(start, position)
            right = min(end, position + len(data))
            if left < right and (payload[left - start:right - start] !=
                                 data[left - position:right - position]):
                raise ValueError('conflicting_overlap')

        if end <= self._next:
            return b''
        new_start = max(start, self._next)
        new_data = payload[new_start - start:]
        ranges = sorted(self._pending + [(new_start, new_data)],
                        key=lambda item: item[0])
        merged = []
        for position, data in ranges:
            if merged and position <= merged[-1][0] + len(merged[-1][1]):
                previous, prefix = merged[-1]
                covered = previous + len(prefix) - position
                if covered < len(data):
                    merged[-1] = (previous, prefix + data[covered:])
            else:
                merged.append((position, data))

        emitted = b''
        if merged and merged[0][0] == self._next:
            _, emitted = merged.pop(0)
        buffered = sum(len(data) for _, data in merged)
        if buffered > self._max_buffer:
            raise ValueError('buffer_limit')
        if len(merged) > self._max_segments:
            raise ValueError('segment_limit')

        # Commit after all overlap and capacity checks pass.
        history = (self._history + emitted)[-self._history_limit:]
        self._pending = merged
        self._buffered = buffered
        self._history = history
        self._next += len(emitted)
        return emitted

    def finish(self):
        """Check for a remaining gap, not completeness of the whole capture."""
        if self._pending:
            raise ValueError('incomplete_stream')
