"""CLI: check — live layered access/L3 diagnostics for a subscriber port."""

from __future__ import annotations

import sys
import threading
from typing import TextIO

from vlan_tool.diagnostics.runner import run_client_check
from vlan_tool.diagnostics.report import CheckLine, ClientCheckReport


_SPINNER_FRAMES = r"-\|/"
_SPINNER_INTERVAL_SECONDS = 0.12


class LiveCheckDisplay:
    """Stream completed checks while one in-place status flag keeps spinning."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream if stream is not None else sys.stdout
        self._is_tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._active: str | None = None
        self._last_width = 0
        self._frame_index = 0
        self._begun = False
        self._finished = False

    def __enter__(self) -> LiveCheckDisplay:
        if self._is_tty:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *_exc_info) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.5)
        with self._lock:
            self._clear_active_locked()
            self._active = None

    def begin(self, report: ClientCheckReport) -> None:
        with self._lock:
            if self._begun:
                return
            self._clear_active_locked()
            self._active = None
            title = f"Client check: {report.switch_name} ({report.switch_host}) port {report.port}"
            if report.description:
                title = f"{title} — {report.description}"
            self.stream.write(f"{title}\n\n")
            self.stream.flush()
            self._begun = True

    def start(self, label: str) -> None:
        with self._lock:
            if self._finished:
                return
            self._clear_active_locked()
            self._active = label
            if self._is_tty:
                self._write_active_locked()

    def complete(self, line: CheckLine) -> None:
        with self._lock:
            self._clear_active_locked()
            self._active = None
            self.stream.write(f"[{line.status}] {line.message}\n")
            self.stream.flush()

    def finish(self, report: ClientCheckReport) -> None:
        if not self._begun:
            self.begin(report)
        with self._lock:
            self._clear_active_locked()
            self._active = None
            if report.verdict:
                self.stream.write(f"\nLikely cause: {report.verdict}\n")
            if report.session_logs:
                self.stream.write("\nSession logs:\n")
                for path in report.session_logs:
                    self.stream.write(f"  {path}\n")
            self.stream.flush()
            self._finished = True

    def _spin(self) -> None:
        while not self._stop.wait(_SPINNER_INTERVAL_SECONDS):
            with self._lock:
                if self._active and not self._finished:
                    self._write_active_locked()

    def _write_active_locked(self) -> None:
        if not self._active:
            return
        # ponytail: checks are sequential, so redraw only the bottom line;
        # use ANSI if stages ever become concurrent.
        frame = _SPINNER_FRAMES[self._frame_index % len(_SPINNER_FRAMES)]
        text = f"[{frame}] {self._active}"
        width = max(self._last_width, len(text))
        self.stream.write(f"\r{text.ljust(width)}")
        self.stream.flush()
        self._last_width = width
        self._frame_index += 1

    def _clear_active_locked(self) -> None:
        if self._is_tty and self._last_width:
            self.stream.write(f"\r{' ' * self._last_width}\r")
            self.stream.flush()
        self._last_width = 0


def run(
    config,
    switch_query: str,
    port: str,
    *,
    client_ip: str | None = None,
    l3_switch: str | None = None,
    vlan_alt: int | None = None,
    debug: bool = True,
) -> int:
    with LiveCheckDisplay() as display:
        display.start("Port link: resolving access switch")
        report = run_client_check(
            config,
            switch_query=switch_query,
            port=port,
            client_ip=client_ip,
            l3_override=l3_switch,
            vlan_alt=vlan_alt,
            # This command owns the console; transport debug would corrupt its live line.
            debug=False,
            on_ready=display.begin,
            on_step=display.start,
            on_line=display.complete,
        )
        display.finish(report)

    return 1 if any(line.status == "FAIL" for line in report.lines) else 0
