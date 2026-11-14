"""Presentation-only terminal rendering for Neverbandits' compact control menu."""
from __future__ import annotations

import os
import shutil
import sys
import textwrap
from typing import Iterable

from . import __version__


_CYAN = "\033[1;36m"
_BLUE = "\033[1;34m"
_GREEN = "\033[1;32m"
_YELLOW = "\033[1;33m"
_RED = "\033[1;31m"
_WHITE = "\033[1;37m"
_RESET = "\033[0m"


def _color_enabled() -> bool:
    return bool(
        sys.stdout.isatty()
        and os.environ.get("TERM") not in {None, "", "dumb"}
        and "NO_COLOR" not in os.environ
    )


def paint(text: str, color: str | None) -> str:
    if not color or not _color_enabled():
        return text
    codes = {"cyan": _CYAN, "blue": _BLUE, "green": _GREEN,
             "yellow": _YELLOW, "red": _RED, "white": _WHITE}
    return f"{codes.get(color, '')}{text}{_RESET}"


def clear_screen() -> None:
    """Replace the visible terminal page, with a plain scroll fallback for TERM=dumb."""
    if not sys.stdout.isatty():
        return
    if os.environ.get("TERM") not in {None, "", "dumb"}:
        print("\033[2J\033[H", end="", flush=True)
        return
    _, lines = _dimensions()
    print("\n" * max(24, lines), end="", flush=True)


def _unicode_supported() -> bool:
    encoding = (getattr(sys.stdout, "encoding", None) or "utf-8").lower()
    return "utf" in encoding and os.environ.get("TERM") not in {None, "", "dumb"}


def _dimensions() -> tuple[int, int]:
    try:
        size = shutil.get_terminal_size(fallback=(80, 24))
        return max(20, size.columns), max(8, size.lines)
    except OSError:
        return 80, 24


def _wrap(text: str, width: int) -> list[str]:
    if not text:
        return [""]
    return textwrap.wrap(text, width=max(12, width), replace_whitespace=False,
                         drop_whitespace=True, break_long_words=True,
                         break_on_hyphens=False) or [""]


def panel(title: str, rows: Iterable[str | tuple[str, str]], *, accent: str = "cyan",
          style: str = "double") -> None:
    """Render a responsive panel, using the reference's compact 60-column width."""
    columns, _ = _dimensions()
    rows = list(rows)
    if columns < 58:
        for line in _wrap(title, columns):
            print(paint(line, accent))
        print("-" * min(columns, 40))
        for row in rows:
            text, color = row if isinstance(row, tuple) else (row, None)
            for part in _wrap(text, max(18, columns - 2)):
                print(paint(part, color))
        print()
        return

    inner = max(48, min(56, columns - 4))
    unicode = _unicode_supported()
    if unicode and style == "single":
        top_left, top_right = "┌", "┐"
        mid_left, mid_right = "├", "┤"
        bottom_left, bottom_right = "└", "┘"
        vertical = "│"
        horizontal = "─"
    elif unicode:
        top_left, top_right = "╔", "╗"
        mid_left, mid_right = "╠", "╣"
        bottom_left, bottom_right = "╚", "╝"
        vertical = "║"
        horizontal = "═"
    else:
        top_left, top_right = "+", "+"
        mid_left, mid_right = "+", "+"
        bottom_left, bottom_right = "+", "+"
        vertical = "|"
        horizontal = "-"

    print(paint(top_left + horizontal * (inner + 2) + top_right, accent))
    for line in _wrap(title, inner):
        print(f"{vertical} {paint(line.center(inner), accent)} {vertical}")
    print(paint(mid_left + horizontal * (inner + 2) + mid_right, accent))
    for row in rows:
        text, color = row if isinstance(row, tuple) else (row, None)
        for line in _wrap(text, inner):
            rendered = paint(line, color)
            print(f"{vertical} {rendered}{' ' * max(0, inner - len(line))} {vertical}")
    print(paint(bottom_left + horizontal * (inner + 2) + bottom_right, accent))
    print()


def state_color(state: str) -> str:
    normalized = state.strip().lower()
    if normalized in {"active", "ready", "available", "ok", "healthy", "success"}:
        return "green"
    if normalized in {"failed", "error", "unreachable", "corrupt"}:
        return "red"
    return "yellow"


def _status_label(state: str, *, listener: bool = False) -> str:
    normalized = state.strip().lower()
    if listener and normalized == "ready":
        return "LISTENING"
    if normalized == "active":
        return "ON"
    if normalized in {"inactive", "unreachable", "failed"}:
        return "OFF"
    if normalized == "available":
        return "OK"
    if normalized == "not managed":
        return "N/A"
    return "UNKNOWN"


def _status_rows(health: Iterable[tuple[str, str]], columns: int) -> list[str]:
    """Mirror the reference's compact status strip without implying client access."""
    states = {str(label).strip().lower(): str(state) for label, state in health}
    definitions = (
        ("SSH", "ssh unit", False),
        ("NGINX", "nginx unit", False),
        ("XRAY", "xray unit", False),
        ("TROJAN", "trojan port", True),
        ("SSH-WS", "ssh-ws unit", False),
        ("VLESS", "vless port", True),
        ("DATABASE", "database", False),
    )
    tokens: list[str] = []
    for label, source, listener in definitions:
        state = states.get(source, "not managed" if source == "stunnel unit" else "unknown")
        value = _status_label(state, listener=listener)
        color = state_color(state)
        tokens.append(f"{paint(label, 'cyan')} : {paint(value, color)}")
    limit = max(24, min(76, columns - 2))
    rows: list[str] = []
    current: list[str] = []
    width = 0
    for token in tokens:
        visible = len(token.replace("\033[1;36m", "").replace("\033[1;32m", "")
                     .replace("\033[1;33m", "").replace("\033[1;31m", "").replace("\033[0m", ""))
        if current and width + visible + 3 > limit:
            rows.append("  " + "   ".join(current))
            current, width = [], 0
        current.append(token)
        width += visible + (3 if len(current) > 1 else 0)
    if current:
        rows.append("  " + "   ".join(current))
    return rows


def _version_footer(columns: int) -> None:
    text = f"Version : {__version__}"
    if columns < 42 or not _unicode_supported():
        for line in _wrap(text, columns):
            print(paint(line, "cyan"))
        return
    inner = 35
    top = "┌" + "─" * (inner + 2) + "┐"
    content = "│  " + text + " " * max(0, inner - 2 - len(text)) + "  │"
    bottom = "└" + "─" * (inner + 2) + "┘"
    print(paint(top, "cyan"))
    print(paint(content, "cyan"))
    print(paint(bottom, "cyan"))


def _options_panel(rows: Iterable[tuple[str, str | None]]) -> None:
    columns, _ = _dimensions()
    rows = list(rows)
    if columns < 58:
        width = max(20, columns)
        print("-" * min(width, 40))
        for text, color in rows:
            for line in _wrap(text, max(16, width - 2)):
                print(paint(line, color))
        print("-" * min(width, 40))
        return
    inner = max(48, min(56, columns - 4))
    if _unicode_supported():
        top = "┌" + "─" * (inner + 2) + "┐"
        bottom = "└" + "─" * (inner + 2) + "┘"
        vertical = "│"
        accent = "cyan"
    else:
        top = "+" + "-" * (inner + 2) + "+"
        bottom = top
        vertical = "|"
        accent = "cyan"
    print(paint(top, accent))
    for text, color in rows:
        for line in _wrap(text, inner):
            print(f"{paint(vertical, accent)} {paint(line, color)}{' ' * max(0, inner - len(line))} {paint(vertical, accent)}")
    print(paint(bottom, accent))
    print()


def show_dashboard(snapshot: dict[str, object], section_items: Iterable[tuple[str, str]],
                   quick_actions: Iterable[str] = (), *, reference_options: Iterable[object] = ()) -> None:
    columns, _ = _dimensions()
    overview = snapshot.get("overview", [])
    panel("Server Informations", overview if isinstance(overview, list) else [str(overview)],
          style="single")

    health = snapshot.get("health", [])
    if isinstance(health, list):
        for row in _status_rows(health, columns):
            print(row)
    print()

    protocol_counts = snapshot.get("protocol_counts")
    action_rows: list[tuple[str, str | None]] = []
    count_keys = {"1": "ssh", "2": "vless", "3": "trojan"}
    options = list(reference_options)
    if options:
        for item in options:
            key = str(getattr(item, "key", ""))
            label = str(getattr(item, "label", ""))
            available = bool(getattr(item, "available", False))
            if not available or not bool(getattr(item, "dashboard", True)):
                continue
            shown_key = key.zfill(2) if key.isdigit() and len(key) < 2 else key
            suffix = ""
            if key in count_keys:
                counts = protocol_counts if isinstance(protocol_counts, dict) else {}
                count = counts.get(count_keys[key])
                suffix = f"[{count}]" if count is not None else "[?]"
            row = f"     [{shown_key}] {label:<13} {suffix}".rstrip()
            action_rows.append((row, "cyan"))
    else:
        action_rows.extend((str(action), "cyan") for action in quick_actions)
    action_rows.append(("     [x ] EXIT", "cyan"))
    _options_panel(action_rows)

    if any(key == "L" for key, _ in section_items):
        for line in _wrap("[L] More actions", columns):
            print(paint(line, "cyan"))
    _version_footer(columns)
    print(paint("Select menu : ", "cyan"), end="", flush=True)


def show_section(key: str, title: str, description: str,
                 actions: Iterable[tuple[str, str, str]], *, extra: Iterable[str | tuple[str, str]] = ()) -> None:
    rows: list[str | tuple[str, str]] = []
    for choice, label, _hint in actions:
        rows.append((f"[{choice}] {label}", "cyan"))
    rows.extend(extra)
    rows.extend(("", "[B] Back to More Actions     [0/Q] Exit"))
    panel(f"NEVERBANDITS / {title}", rows)
    print(paint("Select menu : ", "cyan"), end="", flush=True)


def show_more_actions(actions: Iterable[tuple[str, str, str]]) -> None:
    rows: list[str | tuple[str, str]] = []
    for choice, label, _hint in actions:
        rows.append((f"[{choice}] {label}", "cyan"))
    rows.extend(("", "[R] Refresh dashboard", "[0] Back to Control Centre   [Q/X] Exit"))
    panel("NEVERBANDITS / MORE ACTIONS", rows)
    print(paint("Select menu : ", "cyan"), end="", flush=True)


def show_diagnostics(rows: Iterable[tuple[str, str]]) -> None:
    formatted = [(f"{label:<28} {state}", state_color(state)) for label, state in rows]
    formatted.append("")
    formatted.append(("EXTERNAL CLIENT CONNECTIVITY: NOT TESTED", "yellow"))
    formatted.append("[R] Refresh diagnostics     [B] Back")
    panel("NEVERBANDITS / DIAGNOSTICS", formatted)


def show_result(result: str, message: str) -> None:
    color = {"SUCCESS": "green", "FAILED": "red", "CANCELLED": "yellow"}.get(result, "yellow")
    columns, _ = _dimensions()
    for line in _wrap(f"[{result}] {message}", columns):
        print(paint(line, color))
