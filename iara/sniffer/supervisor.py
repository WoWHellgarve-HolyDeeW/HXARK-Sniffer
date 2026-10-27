"""Capture lifecycle and retry handling for idle interface loss."""


def supervise(wow, captures, stop, notify, *, dumps=None, session=None):
    if session is None:
        from .automatic import run_session
        session = run_session
    delay = 2
    while not stop.is_set():
        try:
            result = session(wow, captures, stop, notify, dumps=dumps)
        except ValueError as exc:
            # Retry discovery failures only before capture starts.
            if str(exc) not in ('capture_adapter_unavailable', 'capture_adapter_query_failed'):
                raise
            notify({'state': 'network_wait'})
            if stop.wait(delay):
                return
            delay = min(30, delay * 2)
            continue
        if stop.is_set():
            return
        if result.get('retry_before_game'):
            notify({'state': 'network_wait'})
            if stop.wait(delay):
                return
            delay = min(30, delay * 2)
            continue
        if result['reason'] != 'process_exited':
            return result
        delay = 2
        if stop.wait(1):
            return result
