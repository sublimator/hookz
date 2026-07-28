"""Development-only host calls generated from hookz comment directives.

A hook can observe its own locals at chosen points:

    /* hookz:
    HOOKZ_U64("tracked", tracked);
    HOOKZ_U64("delta", delta);
    HOOKZ_CHECK("yield_absorb");
    */

Those live in comments, so production builds never see them; `compile_hook_dev`
unwraps them into a temporary source. At runtime each `HOOKZ_CHECK` closes a
Checkpoint holding everything observed since the previous one, and appends it
to `result.checkpoints`.

Recording is all this does. What a checkpoint *means* is the caller's business
— assert on it in a test, diff it against a model, feed it to a solver, store
it as a golden fixture, or just print it. Deciding here would make every user
pay for one opinion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime


@dataclass
class Checkpoint:
    """Values observed at one `HOOKZ_CHECK` point."""
    tag: str
    line: int | None = None
    values: dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, name: str) -> Any:
        return self.values[name]

    def __contains__(self, name: str) -> bool:
        return name in self.values


def _read_label(rt: HookRuntime, ptr: int, length: int) -> str:
    raw = rt._read_memory(ptr, length) if length > 0 else b""
    return raw.rstrip(b"\x00").decode(errors="replace")


def _append_event(rt: HookRuntime, event: dict) -> None:
    event.setdefault("line", rt._current_line)
    rt.dev_events.append(event)
    rt._dev_pending_events.append(event)


def hookz_dev_check(rt: HookRuntime, tag_ptr: int, tag_len: int) -> int:
    """Close the current checkpoint: bundle the values captured since the last one.

    Recording only. Checking is deliberately not done here — a checkpoint is
    evidence, and what counts as correct evidence belongs to whoever is asking.
    Tests replay `result.checkpoints` afterwards; anything heavier (a solver, a
    model comparison) consumes the same record without the hook run paying for
    it inline.
    """
    tag = _read_label(rt, tag_ptr, tag_len)
    _append_event(rt, {"kind": "check", "tag": tag})

    rt.checkpoints.append(Checkpoint(
        tag=tag,
        line=rt._current_line,
        values={e["name"]: e["value"]
                for e in rt._dev_pending_events if "name" in e},
    ))
    rt._dev_pending_events = []

    for observer in rt.checkpoint_observers:
        observer(rt.checkpoints[-1], rt)
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
