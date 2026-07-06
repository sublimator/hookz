"""Development-only host calls generated from hookz comment directives."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime


def _read_label(rt: HookRuntime, ptr: int, length: int) -> str:
    raw = rt._read_memory(ptr, length) if length > 0 else b""
    return raw.rstrip(b"\x00").decode(errors="replace")


def _append_event(rt: HookRuntime, event: dict) -> None:
    event.setdefault("line", rt._current_line)
    rt.dev_events.append(event)
    rt._dev_pending_events.append(event)


def hookz_dev_check(rt: HookRuntime, tag_ptr: int, tag_len: int) -> int:
    event = {
        "kind": "check",
        "tag": _read_label(rt, tag_ptr, tag_len),
    }
    _append_event(rt, event)

    from hookz.dev_lean import dispatch_dev_lean_checks
    dispatch_dev_lean_checks(rt._dev_pending_events, source_path=rt._source_path)
    rt._dev_pending_events = []
    return 0


def hookz_dev_u64(rt: HookRuntime, name_ptr: int, name_len: int, value: int) -> int:
    _append_event(rt, {
        "kind": "u64",
        "name": _read_label(rt, name_ptr, name_len),
        "value": value,
    })
    return 0


def hookz_dev_i64(rt: HookRuntime, name_ptr: int, name_len: int, value: int) -> int:
    if value > 0x7FFFFFFFFFFFFFFF:
        value -= 0x10000000000000000
    _append_event(rt, {
        "kind": "i64",
        "name": _read_label(rt, name_ptr, name_len),
        "value": value,
    })
    return 0


def hookz_dev_bytes(
    rt: HookRuntime,
    name_ptr: int,
    name_len: int,
    data_ptr: int,
    data_len: int,
) -> int:
    _append_event(rt, {
        "kind": "bytes",
        "name": _read_label(rt, name_ptr, name_len),
        "value": rt._read_memory(data_ptr, data_len) if data_len > 0 else b"",
    })
    return 0
