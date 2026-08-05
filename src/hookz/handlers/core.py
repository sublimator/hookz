"""Core hook lifecycle — accept, rollback, guard, trace."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

# Functions with underscore-prefixed names that are real hook API imports
__handlers__ = {"_g", "__on_source_line"}

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

log = logging.getLogger("hookz.trace")


@dataclass
class Trace:
    """A single trace entry from a hook execution."""
    tag: str
    value: Any        # decoded: int, float, str, hex string
    raw: int | bytes  # the original bits: raw bytes or raw i64/xfl
    line: int | None = None  # C source line (from DWARF instrumentation)

    def __repr__(self) -> str:
        loc = f" @{self.line}" if self.line else ""
        return f"Trace({self.tag!r}, {self.value!r}{loc})"


def _not_in_bounds(rt: HookRuntime, ptr: int, length: int) -> bool:
    """The host wrapper's memory-bounds test, on the hook's linear memory.

    xahaud:include/xrpl/hook/Macro.h:230
        (ptr >= memory_length) || (ptr + len > memory_length)

    The macro casts both operands to `uint64_t` and every wrapper parameter
    is `uint32_t`, so the comparison is unsigned. Arguments are normalized
    again here — the linker already does it for real hook calls
    (`HookRuntime._make_host_functions`), but this predicate is also called
    directly, and a signed `-1` slipping through reads as "in bounds",
    which is the one answer it must never give.
    """
    ptr = ptr & 0xFFFFFFFF
    length = length & 0xFFFFFFFF
    memory_length = rt._memory.data_len(rt._store)
    return ptr >= memory_length or ptr + length > memory_length


def _read_tag(rt: HookRuntime, tag_ptr: int, tag_len: int) -> str:
    raw = rt._read_memory(tag_ptr, tag_len).rstrip(b"\x00") if tag_len > 0 else b""
    return raw.decode(errors="replace")


def _g(rt: HookRuntime, id: int, maxiter: int) -> int:
    return 1


def accept(rt: HookRuntime, msg_ptr: int, msg_len: int, code: int) -> int:
    from hookz.runtime import HookAccepted
    msg = rt._read_memory(msg_ptr, msg_len) if msg_len > 0 else b""
    raise HookAccepted(msg, code)


def rollback(rt: HookRuntime, msg_ptr: int, msg_len: int, code: int) -> int:
    from hookz.runtime import HookRejected
    msg = rt._read_memory(msg_ptr, msg_len) if msg_len > 0 else b""
    raise HookRejected(msg, code)


def _line(rt: HookRuntime) -> int | None:
    return rt._current_line


def _loc(rt: HookRuntime) -> str:
    """Format location as clickable 'label:line' (OSC 8 hyperlink in supported terminals)."""
    label = rt._label
    line = rt._current_line
    source = rt._source_path
    if not line:
        return "?"
    text = f"{label}:{line}" if label else f"L{line}"
    if source:
        import os
        editor = os.environ.get("HOOKZ_EDITOR", "")
        if editor:
            from hookz.editor import editor_url, osc8_link
            return osc8_link(text, editor_url(source, line, editor))
    return text


def trace(rt: HookRuntime, tag_ptr: int, tag_len: int, data_ptr: int, data_len: int, as_hex: int) -> int:
    tag = _read_tag(rt, tag_ptr, tag_len)
    data = rt._read_memory(data_ptr, data_len) if data_len > 0 else b""
    display = data.hex() if as_hex else repr(data)
    ln = _line(rt)
    rt.traces.append(Trace(tag=tag, value=display, raw=data, line=ln))
    log.info("%-12s %s: %s", _loc(rt), tag, display)
    return 0


def trace_num(rt: HookRuntime, tag_ptr: int, tag_len: int, val: int) -> int:
    tag = _read_tag(rt, tag_ptr, tag_len)
    raw = val
    if val > 0x7FFFFFFFFFFFFFFF:
        val -= 0x10000000000000000
    ln = _line(rt)
    rt.traces.append(Trace(tag=tag, value=val, raw=raw, line=ln))
    log.info("%-12s %s: %d", _loc(rt), tag, val)
    return 0


def trace_float(rt: HookRuntime, tag_ptr: int, tag_len: int, val: int) -> int:
    from hookz.xfl import xfl_to_float
    tag = _read_tag(rt, tag_ptr, tag_len)
    f = xfl_to_float(val)
    ln = _line(rt)
    rt.traces.append(Trace(tag=tag, value=f, raw=val, line=ln))
    log.info("%-12s %s: %s (xfl=0x%016X)", _loc(rt), tag, f, val)
    return 0


_step_delay: float | None = None
_step_editor: str | None = None
_step_project: str | None = None


def _init_stepper():
    global _step_delay, _step_editor, _step_project
    if _step_delay is not None:
        return
    import os
    raw = os.environ.get("HOOKZ_STEP", "")
    if raw:
        try:
            _step_delay = float(raw)
        except ValueError:
            _step_delay = 0.3
        _step_editor = os.environ.get("HOOKZ_EDITOR", "")
        _step_project = os.environ.get("HOOKZ_PROJECT", "")
    else:
        _step_delay = 0.0


def __on_source_line(rt: HookRuntime, line: int, col: int) -> None:
    rt.coverage.hit(line, col)
    rt._current_line = line

    _init_stepper()
    if _step_delay and _step_delay > 0:
        prev = rt._step_prev_line
        if line != prev:
            rt._step_prev_line = line
            source = rt._source_path
            loc = _loc(rt)
            import sys
            sys.stderr.write(f"  [step] {loc}\n")
            sys.stderr.flush()
            if source and _step_editor:
                _step_open_in_ide(source, line)
            import time
            time.sleep(_step_delay)


def _step_open_in_ide(source, line):
    """Open file:line via JetBrains REST API (localhost:63342)."""
    import os
    port = os.environ.get("HOOKZ_IDE_PORT", "63342")
    url = f"http://localhost:{port}/api/file{source}:{line}"
    try:
        import urllib.request
        urllib.request.urlopen(url, timeout=0.1)
    except Exception:
        pass
