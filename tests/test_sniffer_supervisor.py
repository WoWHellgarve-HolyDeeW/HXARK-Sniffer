import subprocess
import unittest
from unittest.mock import Mock

from iara.sniffer.supervisor import supervise


class Stop:
    def __init__(self, after=99):
        self.after, self.waits = after, []
    def is_set(self):
        return len(self.waits) >= self.after
    def wait(self, delay):
        self.waits.append(delay)
        return self.is_set()


class SupervisorTests(unittest.TestCase):
    def test_idle_detach_and_missing_interface_recover_without_restart(self):
        stop = Stop()
        session = Mock(side_effect=[{'reason':'adapter_error','retry_before_game':True},
            ValueError('capture_adapter_unavailable'),
            {'reason':'process_exited','complete':True}, {'reason':'user_stopped'}])
        events = []
        supervise('wow', 'captures', stop, events.append, dumps='dumps', session=session)
        self.assertEqual(session.call_count, 4)
        self.assertEqual(stop.waits, [2,4,1])
        self.assertEqual([e['state'] for e in events], ['network_wait','network_wait'])
        self.assertEqual(session.call_args.kwargs['dumps'], 'dumps')

    def test_backoff_is_bounded_and_close_interrupts_wait(self):
        stop = Stop(after=8)
        session = Mock(side_effect=ValueError('capture_adapter_unavailable'))
        supervise('w','c',stop,Mock(),session=session)
        self.assertEqual(stop.waits,[2,4,8,16,30,30,30,30])
        self.assertEqual(session.call_count,8)

    def test_failed_capture_is_not_retried_or_relabelled_as_success(self):
        session=Mock(return_value={'reason':'adapter_error','complete':False})
        stop=Stop();notify=Mock()
        self.assertFalse(supervise('w','c',stop,notify,session=session)['complete'])
        session.assert_called_once();notify.assert_not_called();self.assertEqual(stop.waits,[])

    def test_other_failure_is_not_swallowed(self):
        for code in ('unsupported_build','update_in_progress','capture_shutdown_incomplete'):
            with self.subTest(code=code),self.assertRaisesRegex(ValueError,code):
                supervise('w','c',Stop(),Mock(),session=Mock(side_effect=ValueError(code)))

    def test_discovery_process_errors_retry_and_successful_sessions_continue(self):
        session=Mock(side_effect=[ValueError('capture_adapter_query_failed'),
            ValueError('capture_adapter_unavailable'),{'reason':'process_exited'},
            {'reason':'process_exited'},{'reason':'user_stopped'}])
        stop=Stop();supervise('w','c',stop,Mock(),session=session)
        self.assertEqual(stop.waits,[2,4,1,1]);self.assertEqual(session.call_count,5)

    def test_subprocess_failure_outside_discovery_is_not_hidden(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            supervise('w','c',Stop(),Mock(),session=Mock(side_effect=subprocess.TimeoutExpired('capture',10)))

    def test_already_closed_never_starts_capture(self):
        session=Mock();supervise('w','c',Stop(after=0),Mock(),session=session)
        session.assert_not_called()
