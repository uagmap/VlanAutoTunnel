"""Claude-style live layout for plan/deploy: scrolling debug + fixed hop pane.

Uses Rich Live on the alternate screen so the tree stays put while debug scrolls
in its own region. On exit, the log is dumped back to the normal console so it
remains readable in scrollback.
"""

from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
import sys
from typing import Iterator


try:
    from rich.console import Console
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.text import Text

    _RICH = True
except ImportError:  # pragma: no cover
    _RICH = False


_panel: "LiveTracePanel | None" = None


@dataclass
class _Hop:
    name: str
    host: str
    role: str = ""


class LiveTracePanel:
    def __init__(self) -> None:
        self.vlan: int | None = None
        self.hops: list[_Hop] = []
        self._lines: deque[str] = deque(maxlen=4000)
        self.enabled = False
        self._live: object | None = None
        self._console: object | None = None

    @property
    def active(self) -> bool:
        return bool(self.enabled and self._live is not None)

    def __enter__(self) -> "LiveTracePanel":
        if not _RICH or not sys.stdout.isatty():
            self.enabled = False
            return self
        console = Console()
        self._console = console
        self.enabled = True
        self._live = Live(
            self._build_layout(),
            console=console,
            refresh_per_second=12,
            screen=True,
            transient=False,
        )
        self._live.__enter__()  # type: ignore[union-attr]
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        live = self._live
        self._live = None
        self.enabled = False
        if live is not None:
            live.__exit__(exc_type, exc, tb)  # type: ignore[union-attr]
        # Restore a readable scrollback copy after the alt-screen closes.
        if self._lines:
            print("--- plan/deploy debug log ---")
            for line in self._lines:
                print(line)
            print("--- end debug log ---")
        tree = self._tree_text_lines()
        if tree:
            print("--- path ---")
            for line in tree:
                print(line)

    def emit(self, message: str, *, echo: bool = False) -> None:
        text = str(message).rstrip("\n")
        if not text:
            return
        self._lines.append(text)
        if self.active:
            self._refresh()
        elif echo:
            print(text)

    def set_vlan(self, vlan_id: int) -> None:
        self.vlan = vlan_id
        self._refresh()

    def add_hop(self, name: str, host: str, *, role: str = "") -> None:
        key = host.casefold()
        if any(item.host.casefold() == key for item in self.hops):
            self._refresh()
            return
        self.hops.append(_Hop(name=name, host=host, role=role))
        self._refresh()

    def _refresh(self) -> None:
        if not self.active:
            return
        self._live.update(self._build_layout())  # type: ignore[union-attr]

    def _build_layout(self) -> Layout:
        assert self._console is not None
        term_width = self._console.size.width  # type: ignore[union-attr]
        term_height = self._console.size.height  # type: ignore[union-attr]
        tree_lines = self._tree_text_lines()
        tree_inner = max((len(line) for line in tree_lines), default=16)
        tree_width = min(max(tree_inner + 4, 34), max(34, term_width // 2))

        layout = Layout()
        layout.split_row(
            Layout(name="log", ratio=1),
            Layout(name="tree", size=tree_width),
        )
        # Leave room for panel borders/title in the log window.
        visible = max(4, term_height - 4)
        log_slice = list(self._lines)[-visible:]
        log_text = Text("\n".join(log_slice) if log_slice else "…", overflow="fold")
        layout["log"].update(Panel(log_text, title="Debug", border_style="cyan", padding=(0, 1)))
        layout["tree"].update(
            Panel(
                Text("\n".join(tree_lines), overflow="fold"),
                title="Path",
                border_style="green",
                padding=(0, 1),
            )
        )
        return layout

    def _tree_text_lines(self) -> list[str]:
        vlan_text = f"VLAN: {self.vlan}" if self.vlan is not None else "VLAN: -"
        titles: list[str] = []
        for hop in self.hops:
            role = hop.role.strip().casefold()
            if role == "l3":
                titles.append(f"[L3] {hop.name} ({hop.host})")
            elif role == "destination":
                titles.append(f"[dest] {hop.name} ({hop.host})")
            else:
                titles.append(f"{hop.name} ({hop.host})")
        if not titles:
            return [vlan_text, "", "(tracing...)"]

        width = max(len(vlan_text), *(len(item) for item in titles))
        arrow = "↓".center(width)
        lines = [vlan_text, "─" * width]
        for index, title in enumerate(titles):
            lines.append(title)
            if index < len(titles) - 1:
                lines.append(arrow)
        return lines

    # Kept for unit tests / fallback render checks.
    def _render_lines(self) -> list[str]:
        return self._tree_text_lines()


def start_trace_panel() -> LiveTracePanel:
    """Return the active panel, or a passive placeholder if UI was not started."""
    global _panel
    if _panel is None:
        _panel = LiveTracePanel()
    return _panel


def ui_print(message: str) -> None:
    """Print into the live debug pane when a panel exists, else stdout."""
    panel = _panel
    if panel is not None:
        # echo: the line still shows immediately when the Rich live view is off (non-TTY).
        panel.emit(message, echo=True)
    else:
        print(message)


@contextmanager
def live_trace_ui() -> Iterator[LiveTracePanel]:
    """Own the Rich Live session for one plan/deploy run."""
    global _panel
    panel = LiveTracePanel()
    previous = _panel
    _panel = panel
    panel.__enter__()
    try:
        yield panel
    finally:
        panel.__exit__(None, None, None)
        _panel = previous
