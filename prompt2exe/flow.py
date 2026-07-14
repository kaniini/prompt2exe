from __future__ import annotations

import os
import shutil
import unicodedata
from collections.abc import Callable
from typing import TextIO


def character_width(character: str) -> int:
    if unicodedata.combining(character):
        return 0
    return 2 if unicodedata.east_asian_width(character) in {"F", "W"} else 1


def display_width(text: str) -> int:
    return sum(character_width(character) for character in text)


def terminal_width(stream: TextIO) -> int:
    try:
        return os.get_terminal_size(stream.fileno()).columns
    except (AttributeError, OSError):
        return shutil.get_terminal_size(fallback=(80, 24)).columns


def split_at_width(text: str, width: int) -> tuple[str, str]:
    used = 0
    split_index = 0
    for index, character in enumerate(text):
        character_cells = character_width(character)
        if split_index and used + character_cells > width:
            break
        used += character_cells
        split_index = index + 1
        if used >= width:
            break
    return text[:split_index], text[split_index:]


class TerminalFlowWriter:
    MIN_CONTENT_WIDTH = 8

    def __init__(
        self,
        *,
        stream: TextIO,
        prefix: str,
        width: Callable[[], int] | None = None,
    ) -> None:
        self.stream = stream
        self.prefix = prefix
        self._get_width = width or (lambda: terminal_width(stream))
        self._word = ""
        self._pending_space = False
        self._at_line_start = True
        self._first_line = True
        self._column = 0
        self._started = False
        self._ended_with_newline = False
        self._saw_carriage_return = False
        self._failed = False

    @property
    def started(self) -> bool:
        return self._started

    def _width(self) -> int:
        try:
            return max(1, int(self._get_width()))
        except (OSError, TypeError, ValueError):
            return 80

    def _write(self, value: str) -> None:
        if self._failed:
            return
        try:
            self.stream.write(value)
        except (OSError, ValueError):
            self._failed = True

    def _indent(self, width: int) -> str:
        if width <= display_width(self.prefix) + self.MIN_CONTENT_WIDTH:
            return ""
        return self.prefix if self._first_line else " " * display_width(self.prefix)

    def _start_line(self, width: int) -> None:
        indent = self._indent(width)
        self._write(indent)
        self._column = display_width(indent)
        self._at_line_start = False
        self._first_line = False
        self._started = True
        self._ended_with_newline = False

    def _newline(self) -> None:
        if not self._started and self._at_line_start:
            self._start_line(self._width())
        self._write("\n")
        self._at_line_start = True
        self._column = 0
        self._pending_space = False
        self._ended_with_newline = True

    def _flush_word(self) -> None:
        if not self._word:
            return
        word = self._word
        self._word = ""
        width = self._width()
        if self._at_line_start:
            self._start_line(width)

        word_width = display_width(word)
        if self._pending_space:
            if self._column + 1 + word_width > width:
                self._newline()
                width = self._width()
                self._start_line(width)
            else:
                self._write(" ")
                self._column += 1
            self._pending_space = False

        while word:
            width = self._width()
            if self._at_line_start:
                self._start_line(width)
            available = max(1, width - self._column)
            chunk, word = split_at_width(word, available)
            self._write(chunk)
            self._column += display_width(chunk)
            self._ended_with_newline = False
            if word:
                self._newline()

    def write(self, text: str) -> None:
        for character in text:
            if self._saw_carriage_return:
                self._saw_carriage_return = False
                if character == "\n":
                    continue
            if character == "\r":
                self._flush_word()
                self._newline()
                self._saw_carriage_return = True
            elif character == "\n":
                self._flush_word()
                self._newline()
            elif character.isspace():
                self._flush_word()
                if not self._at_line_start:
                    self._pending_space = True
            else:
                self._word += character
        if not self._failed:
            try:
                self.stream.flush()
            except (OSError, ValueError):
                self._failed = True

    def finish(self) -> None:
        self._flush_word()
        if self._started and not self._ended_with_newline:
            self._newline()
        if not self._failed:
            try:
                self.stream.flush()
            except (OSError, ValueError):
                self._failed = True
