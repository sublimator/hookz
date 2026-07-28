"""Hook execution runtime — run WASM hooks with mocked host functions.

Uses wasmtime to execute hooks. All hook API imports are dynamically
dispatched to Python handlers. Unknown imports get a default no-op handler.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

import wasmtime

from pathlib import Path

from hookz.coverage.tracker import CoverageTracker
from hookz.handlers import collect_handlers

# Auto-discovered handlers from hookz.handlers package
_BUILTIN_HANDLERS = collect_handlers()


# XFL helpers — canonical home is hookz.xfl, aliased here for compat
from hookz.xfl import xfl_to_float as _xfl_to_float  # noqa: F401
from hookz.xfl import float_to_xfl as _float_to_xfl  # noqa: F401
from hookz.xfl import xfl_mantissa as _xfl_mantissa  # noqa: F401
from hookz.xfl import xfl_exponent as _xfl_exponent  # noqa: F401


@dataclass
class Hook:
    """Compiled + instrumented hook binary with metadata."""
    wasm: bytes
    label: str
    source: Path | None = None


class HookAccepted(Exception):
    """Raised when hook calls accept()."""
    def __init__(self, msg: bytes, code: int):
        self.msg = msg
        self.code = code
        super().__init__(f"accept({msg!r}, {code})")


class HookRejected(Exception):
    """Raised when hook calls rollback()."""
    def __init__(self, msg: bytes, code: int):
        self.msg = msg
        self.code = code
        super().__init__(f"rollback({msg!r}, {code})")


@dataclass
class HostCall:
    """Record of a single host function call."""
    name: str
    args: tuple
    result: Any = None


@dataclass
class HookResult:
    """Result of a hook execution."""
    accepted: bool = False
    rejected: bool = False
    return_msg: bytes = b""
    return_code: int = 0
    call_log: list[HostCall] = field(default_factory=list)
    error: Exception | None = None
    # Values the hook observed about itself, one entry per HOOKZ_CHECK.
    checkpoints: list = field(default_factory=list)
    dev_events: list[dict] = field(default_factory=list)

    @property
    def return_msg_str(self) -> str:
        """`return_msg` as text, without its trailing NUL.

        The message is bytes, because that is what the hook handed to
        `accept`/`rollback`. But the thing a test wants to say is
        `"no listed signers" in result.return_msg_str`, and writing that against
        the bytes raises TypeError rather than failing — an error where an
        assertion was intended, which reads as a broken test rather than a
        broken hook.

        Hooks build these with `SBUF(msg)`, which is `msg, sizeof(msg)`, and
        `sizeof` a string literal counts its terminator. So every message
        arrives with a trailing NUL that nobody wants and an equality
        comparison trips over. It is stripped here rather than in each caller;
        `return_msg` keeps the bytes exactly as the hook sent them.

        Decoded leniently: a rollback message is a literal from the source, but
        nothing stops a hook passing arbitrary bytes, and a test should still
        get to see them.
        """
        raw = self.return_msg
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw).decode("utf8", "replace").rstrip("\x00")
        return (raw or "").rstrip("\x00")

    def checkpoint(self, tag: str):
        """The single checkpoint with this tag, or None. Raises if repeated."""
        hits = [c for c in self.checkpoints if c.tag == tag]
        if not hits:
            return None
        if len(hits) > 1:
            raise ValueError(
                f"{tag!r} was reached {len(hits)} times; use checkpoints_for()")
        return hits[0]

    def checkpoints_for(self, tag: str) -> list:
        return [c for c in self.checkpoints if c.tag == tag]


# Amendments enabled by default.
# The whitelist-gating amendments (featureHooksUpdate1, featureHooksUpdate2)
# are derived from hook_api.macro at runtime. The behavioral amendments
# (fixHookAPI20251128, etc.) are listed here since they don't appear in
# the macro file — they affect handler behavior, not the import whitelist.
_BEHAVIORAL_AMENDMENTS: set[str] = {
    "fixHookAPI20251128",
    "featureHookAPISerializedType240",
    "featureHooksUpdate1",
    "featureDID",
    "featurePriceOracle",
    "featureCron",
    # VoteBehavior::DefaultYes — validators adopt it unless told otherwise, so
    # the fixed long-division is the behaviour a hook should expect to meet.
    "fixFloatDivide",
}


def _get_default_amendments() -> set[str]:
    """Build default amendments: behavioral + whitelist-gating from macro."""
    try:
        from hookz.wasm.whitelist import get_default_amendments
        return _BEHAVIORAL_AMENDMENTS | get_default_amendments()
    except Exception:
        return _BEHAVIORAL_AMENDMENTS.copy()


_MODULE_CACHE: dict[bytes, tuple] = {}
_MODULE_CACHE_LIMIT = 32


def _module_for(wasm_bytes: bytes):
    """(engine, module) for these bytes, compiled once.

    A wasmtime Module is immutable and tied to its Engine, so both are safe to
    share across runs; only the Store carries per-execution state. Bounded so a
    suite that compiles many variants (mutation testing) cannot grow without
    limit.
    """
    hit = _MODULE_CACHE.get(wasm_bytes)
    if hit is not None:
        return hit
    engine = wasmtime.Engine()
    entry = (engine, wasmtime.Module(engine, wasm_bytes))
    if len(_MODULE_CACHE) >= _MODULE_CACHE_LIMIT:
        _MODULE_CACHE.pop(next(iter(_MODULE_CACHE)))
    _MODULE_CACHE[wasm_bytes] = entry
    return entry


class HookRuntime:
    """Execute WASM hooks with mocked hook API.

    Example:
        rt = HookRuntime()
        rt.state_db[key] = value
        rt.set_param(0, opinion_bytes)
        result = rt.run(wasm_bytes)
        assert result.accepted
        assert rt.state_db[key] == expected

    Amendments:
        rt.amendments is a set[str]. All current Xahau amendments are
        enabled by default. Toggle with:
            rt.amendments.discard("fixHookAPI20251128")
            rt.amendments.add("someNewFeature")
    """

    def __init__(self) -> None:
        self.state_db: dict[bytes, bytes] = {}
        # Two namespaces, as on chain. `params` are the hook's install
        # parameters (hook_param); `tx_params` are carried by the originating
        # transaction (otxn_param). A name may appear in both without colliding.
        self.params: dict[bytes, bytes] = {}
        self.tx_params: dict[bytes, bytes] = {}
        self.hook_account: bytes = b"\x00" * 20
        self.otxn_account: bytes = b"\x00" * 20
        self.otxn_type: int = 0
        self.ledger_seq_val: int = 100
        self.ledger_last_time_val: int = 0  # seconds since Ripple epoch
        self.call_log: list[HostCall] = []
        self.emitted_txns: list[bytes] = []
        self.traces: list = []  # list[Trace] from handlers.core
        # HOOKZ_CHECK recording. `checkpoint_observers` lets a caller react as
        # each one closes — a live model comparison, a log — without the
        # runtime having to know what any of them are for.
        self.checkpoints: list = []
        self.dev_events: list[dict] = []
        self.checkpoint_observers: list = []
        self._dev_pending_events: list[dict] = []
        self.coverage = CoverageTracker()
        self._shared_coverage: CoverageTracker | None = None
        self.handlers: dict[str, Callable] = {}
        self._slot_overrides: dict[str, Any] = {}
        self.ledger: dict[bytes, bytes] = {}  # keylet → serialized STObject
        self.amendments: set[str] = _get_default_amendments()
        self._memory: wasmtime.Memory | None = None
        self._store: wasmtime.Store | None = None

        # Per-run source context (assigned in run()).
        self._label: str | None = None
        self._source_path: Path | None = None
        self._current_line: int | None = None  # last line hit under coverage
        self._step_prev_line: int | None = None

        # Handler-owned state, populated during execution.
        # Emitted transactions are validated the way xahaud validates them.
        # Turn this off only to test a deliberately malformed emit; leaving it
        # off is how a hook that cannot emit on chain passes a suite here.
        self._has_cbak: bool | None = None
        self.validate_emissions: bool = True
        self.emission_rejections: list = []
        self._etxn_reserved: bool = False
        self._etxn_count: int = 0
        self._emit_nonce_counter: int = 0
        self._foreign_state_db: dict[tuple[bytes, bytes, bytes], bytes] = {}
        self._param_overrides: dict[bytes, dict[bytes, bytes]] = {}

    def set_param(self, key: int | bytes, value: bytes) -> None:
        """Set an install parameter (read by `hook_param`)."""
        if isinstance(key, int):
            key = key.to_bytes(1, "little")
        self.params[key] = value

    def set_tx_param(self, key: int | bytes, value: bytes) -> None:
        """Set a parameter carried by the originating transaction (`otxn_param`)."""
        if isinstance(key, int):
            key = key.to_bytes(1, "little")
        self.tx_params[key] = value

    def _read_memory(self, ptr: int, length: int) -> bytes:
        """Read bytes from WASM linear memory."""
        assert self._memory is not None and self._store is not None
        buf = self._memory.read(self._store, ptr, ptr + length)
        return bytes(buf)

    def _write_memory(self, ptr: int, data: bytes) -> None:
        """Write bytes to WASM linear memory."""
        assert self._memory is not None and self._store is not None
        self._memory.write(self._store, data, ptr)

    def _make_host_functions(
        self, store: wasmtime.Store, module: wasmtime.Module
    ) -> wasmtime.Linker:
        """Create a linker with all host functions dynamically registered."""
        linker = wasmtime.Linker(store.engine)
        rt = self

        for imp in module.imports:
            typ = imp.type
            if not isinstance(typ, wasmtime.FuncType):
                continue

            name = imp.name
            mod = imp.module

            # Resolution order: test overrides → builtin handlers → _hook_* legacy → default
            handler = self.handlers.get(name)
            if handler is None and name in _BUILTIN_HANDLERS:
                builtin = _BUILTIN_HANDLERS[name]
                # Builtin handlers take (rt, *wasm_args)
                handler = lambda *args, _fn=builtin: _fn(rt, *args)
            if handler is None:
                handler = getattr(self, f"_hook_{name}", None)

            if handler is not None:
                def make_wrapper(h, n):
                    def wrapper(*args):
                        call = HostCall(name=n, args=args)
                        rt.call_log.append(call)
                        result = h(*args)
                        call.result = result
                        return result
                    return wrapper

                linker.define_func(mod, name, typ, make_wrapper(handler, name))
            else:
                # Unimplemented handler — fail loudly
                def make_unimpl(n):
                    def unimpl_handler(*args):
                        raise NotImplementedError(
                            f"Hook called unimplemented host function '{n}'. "
                            f"Run 'hookz show {n}' to see the C++ implementation."
                        )
                    return unimpl_handler

                linker.define_func(mod, name, typ, make_unimpl(name))

        return linker

    def run(self, hook: Hook | bytes, label: str | None = None, coverage: bool = False) -> HookResult:
        """Execute a hook and return the result.

        Args:
            hook: Hook object or raw WASM bytes
            label: human-readable name (ignored if hook is a Hook object)
            coverage: If True, instrument the WASM for line:col coverage tracking
        """
        if isinstance(hook, Hook):
            wasm_bytes = hook.wasm
            self._label = hook.label
            self._source_path = hook.source
        else:
            wasm_bytes = hook
            self._label = label
            self._source_path = None
        result = HookResult()
        self.call_log = []
        self.traces = []
        self.checkpoints = []
        self.dev_events = []
        self._dev_pending_events = []
        # share the lists so a caller can read checkpoints mid-run via an
        # observer, and off the result afterwards
        result.checkpoints = self.checkpoints
        result.dev_events = self.dev_events
        # Preserve markers if already loaded
        markers = self.coverage._markers
        self.coverage = CoverageTracker()
        self.coverage._markers = markers

        if coverage:
            from hookz.coverage.rewriter import instrument_wasm
            wasm_bytes, _locs = instrument_wasm(wasm_bytes)

        # Compiling the module is the expensive part — a few hundred KB of
        # wasm costs tens of milliseconds, and a test suite runs the same
        # bytes hundreds of times. The result depends only on the bytes, so
        # cache it against them. (Hooks are large because nothing inside one
        # can be a function, so everything is inlined.)
        engine, module = _module_for(wasm_bytes)
        store = wasmtime.Store(engine)
        self._store = store
        linker = self._make_host_functions(store, module)

        instance = linker.instantiate(store, module)

        # Get memory export
        memory = instance.exports(store).get("memory")
        if isinstance(memory, wasmtime.Memory):
            self._memory = memory

        # Get hook export
        # xahaud attaches sfEmitCallback to an emitted transaction exactly
        # when the emitting hook exports cbak, and refuses the emit if the
        # two disagree. The module is the only place that is knowable.
        self._has_cbak = instance.exports(store).get("cbak") is not None
        hook_fn = instance.exports(store).get("hook")
        if hook_fn is None:
            raise RuntimeError("WASM module does not export 'hook'")

        try:
            ret = hook_fn(store, 0)
            result.return_code = ret if isinstance(ret, int) else 0
        except HookAccepted as e:
            result.accepted = True
            result.return_msg = e.msg
            result.return_code = e.code
        except HookRejected as e:
            result.rejected = True
            result.return_msg = e.msg
            result.return_code = e.code
        except wasmtime.Trap as e:
            result.error = e
        except Exception as e:
            result.error = e

        result.call_log = self.call_log

        # Merge coverage into shared tracker(s)
        if self._shared_coverage is not None:
            for (line, col), count in self.coverage.all_hits.items():
                for _ in range(count):
                    self._shared_coverage.hit(line, col)
        # Also try auto-wiring from plugin's tracker registry
        if self._shared_coverage is None and isinstance(hook, Hook):
            from hookz.testing.plugin import _coverage_trackers, _hook_registry
            for name, path in _hook_registry.items():
                if path.name == hook.label:
                    tracker = _coverage_trackers[name]
                    for (line, col), count in self.coverage.all_hits.items():
                        for _ in range(count):
                            tracker.hit(line, col)
                    break

        self._store = None
        self._memory = None
        return result
