import threading
import unittest

from snapquiz.core.busyguard import BusyGuard


class BusyGuardTest(unittest.TestCase):
    def test_runs_fn_when_free_and_returns_true(self):
        guard = BusyGuard()
        ran = []
        accepted = guard.try_run(lambda: ran.append(1))
        guard.wait_idle(timeout=2)
        self.assertTrue(accepted)
        self.assertEqual(ran, [1])

    def test_drops_second_call_while_busy(self):
        guard = BusyGuard()
        release = threading.Event()
        second_ran = []

        accepted1 = guard.try_run(lambda: release.wait(2))
        # 第一个还在运行(阻塞在 release 上),此时并发触发应被丢弃
        accepted2 = guard.try_run(lambda: second_ran.append(1))

        self.assertTrue(accepted1)
        self.assertFalse(accepted2)
        self.assertEqual(second_ran, [])

        release.set()
        guard.wait_idle(timeout=2)

    def test_free_again_after_completion(self):
        guard = BusyGuard()
        first = []
        guard.try_run(lambda: first.append(1))
        guard.wait_idle(timeout=2)

        second = []
        accepted = guard.try_run(lambda: second.append(2))
        guard.wait_idle(timeout=2)
        self.assertTrue(accepted)
        self.assertEqual(second, [2])

    def test_releases_busy_even_if_fn_raises(self):
        errors = []
        guard = BusyGuard(on_error=errors.append)

        def boom():
            raise RuntimeError("boom")

        guard.try_run(boom)
        guard.wait_idle(timeout=2)

        # 未因异常永久卡在 busy
        after = []
        accepted = guard.try_run(lambda: after.append(1))
        guard.wait_idle(timeout=2)
        self.assertTrue(accepted)
        self.assertEqual(after, [1])

    def test_routes_fn_exception_to_on_error(self):
        errors = []
        guard = BusyGuard(on_error=errors.append)
        guard.try_run(lambda: (_ for _ in ()).throw(ValueError("bad")))
        guard.wait_idle(timeout=2)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ValueError)


if __name__ == "__main__":
    unittest.main()
