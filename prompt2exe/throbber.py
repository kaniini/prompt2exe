from __future__ import annotations

import threading
from types import TracebackType
from typing import TextIO


class Throbber:
    FRAMES = ("|", "/", "-", "\\")

    def __init__(
        self,
        message: str,
        *,
        stream: TextIO,
        enabled: bool,
        interval: float = 0.1,
    ) -> None:
        self.message = message
        self.stream = stream
        self.enabled = enabled
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._rendered = False

    def _write(self, value: str) -> None:
        try:
            self.stream.write(value)
            self.stream.flush()
        except (OSError, ValueError):
            self._stop.set()

    def _render(self, frame: str) -> None:
        self._write(f"\r{frame} {self.message}")
        self._rendered = True

    def _animate(self) -> None:
        frame_index = 1
        while not self._stop.wait(self.interval):
            self._render(self.FRAMES[frame_index])
            frame_index = (frame_index + 1) % len(self.FRAMES)

    def start(self) -> None:
        if not self.enabled or self._thread is not None:
            return
        self._render(self.FRAMES[0])
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join()
        if self._rendered:
            self._write("\r" + " " * (len(self.message) + 2) + "\r")
        self._thread = None

    def __enter__(self) -> Throbber:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.stop()
