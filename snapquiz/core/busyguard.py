"""单槽 busy-guard:同一时刻只允许一个查询在跑。

热键回调调用 try_run():空闲则在后台线程执行任务并立即返回 True;正忙则直接
返回 False 丢弃这次触发。这样长按/连击热键不会引发并发截图与重复 API 调用,
也是首要的成本护栏。
"""
from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class BusyGuard:
    def __init__(self, on_error: Optional[Callable[[Exception], None]] = None) -> None:
        self._lock = threading.Lock()
        self._busy = False
        self._worker: Optional[threading.Thread] = None
        self._on_error = on_error

    def try_run(self, fn: Callable[[], None]) -> bool:
        """空闲则后台执行 fn 并返回 True;正忙则返回 False 且不执行 fn。"""
        with self._lock:
            if self._busy:
                return False
            self._busy = True
        worker = threading.Thread(target=self._run, args=(fn,), daemon=True)
        self._worker = worker
        worker.start()
        return True

    def _run(self, fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception as exc:  # 不让异常逃逸到线程默认 excepthook
            if self._on_error is not None:
                self._on_error(exc)
            else:
                logger.exception("busy-guard task failed")
        finally:
            with self._lock:
                self._busy = False

    def wait_idle(self, timeout: Optional[float] = None) -> None:
        """等待当前在跑的任务结束(用于测试与优雅关闭)。"""
        worker = self._worker
        if worker is not None:
            worker.join(timeout)
