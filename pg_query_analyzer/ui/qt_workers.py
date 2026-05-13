"""QThread wrappers for blocking work opened from PyQt GUIs."""

from __future__ import annotations

from typing import Any, Callable, Optional

from PyQt5.QtCore import QObject, QThread, pyqtSignal

CallableFn = Callable[[], Any]


class CallableWorkerThread(QThread):
    """Run ``callable()`` off the GUI thread.

    Connect to :meth:`completed` with ``(success, payload)`` —
    ``payload`` is the callable's return value on success, otherwise the error string.
    """

    completed = pyqtSignal(bool, object)

    def __init__(
        self,
        fn: CallableFn,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:
        try:
            out = self._fn()
        except BaseException as e:
            msg = getattr(e, "args", None) and str(e) if e else "unknown error"
            if not isinstance(msg, str) or not msg:
                msg = str(e)
            self.completed.emit(False, msg)
            return

        self.completed.emit(True, out)
