"""Hook execution runtime — run WASM hooks with mocked host functions.

Uses wasmtime to execute hooks. All hook API imports are dynamically
dispatched to Python handlers. Unknown imports get a default no-op handler.
"""

from __future__ import annotations

from contextlib import contextmanager
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


def _param_key(key: str | bytes) -> bytes:
    """Param names are bytes on the hook side; tests naturally write str."""
    return key.encode() if isinstance(key, str) else key


class ParamMap(dict):
    """A parameter mapping that normalizes str keys to UTF-8 bytes.

    `hook_param` and `otxn_param` look names up as bytes, but a test that
    writes `rt.tx_params["CMD"] = b"SWAP"` means the same parameter as one
    that writes `rt.tx_params[b"CMD"]` — and before this existed, every test
    project carried its own str→bytes bridging helper. Values are stored
    untouched; only keys are normalized, on every path into the dict.
    """

    def __init__(self, *args, **kwargs):
        super().__init__()
        if args or kwargs:
            self.update(*args, **kwargs)

    def __setitem__(self, key, value):
        super().__setitem__(_param_key(key), value)

    def __getitem__(self, key):
        return super().__getitem__(_param_key(key))

    def __delitem__(self, key):
        super().__delitem__(_param_key(key))

    def __contains__(self, key):
        return super().__contains__(_param_key(key))

    def get(self, key, default=None):
        return super().get(_param_key(key), default)

    def pop(self, key, *default):
        return super().pop(_param_key(key), *default)

    def setdefault(self, key, default=None):
        return super().setdefault(_param_key(key), default)

    def update(self, *args, **kwargs):
        for mapping in args:
            items = mapping.items() if hasattr(mapping, "items") else mapping
            for key, value in items:
                self[key] = value
        for key, value in kwargs.items():
            self[key] = value


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
    # What the hook actually emitted — empty unless it accepted, since a
    # rolled-back hook's emissions are discarded rather than applied.
    emitted_txns: list[bytes] = field(default_factory=list)
    # What it emitted before rolling back. Kept so a test can prove a hook
    # tried to pay out and then refused, which is a different statement from
    # never having reached the emit at all.
    attempted_emissions: list[bytes] = field(default_factory=list)

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


# Amendments enabled by default: whatever mainnet has, read off a live node
# and vendored as data/amendments-mainnet.json. See hookz.amendments — the
# short version is that a hand-curated list was wrong in both directions at
# once, and neither error is visible from inside a curated list.
#
# Override per test with rt.amendments.discard(...) / .add(...), or point at
# another network's manifest with hookz.amendments.enabled_on("testnet").


def _get_default_amendments() -> set[str]:
    """Mainnet's enabled set, or a minimal fallback if no manifest is vendored.

    The fallback is deliberately small and behavioural-only: if the manifest is
    missing, the honest position is "we do not know what the network has", and
    a large guessed set would look authoritative while being invented.
    """
    from hookz.amendments import enabled_on

    recorded = enabled_on()
    if recorded:
        return set(recorded)

    # Reaching here means the vendored manifest is gone. Every amendment that
    # changes behaviour goes with it — a signer list of 9 is refused, float
    # division takes the unfixed path — and each of those looks like a verdict
    # about the hook rather than a missing file. Say so once, loudly.
    import warnings
    warnings.warn(
        "no amendment manifest is vendored, so hookz does not know what the "
        "network has enabled. Behaviour that depends on an amendment will not "
        "match mainnet. Regenerate with: x-inspect-net amendments --net "
        "mainnet --json src/hookz/data/amendments-mainnet.json",
        RuntimeWarning, stacklevel=3)

    try:
        from hookz.wasm.whitelist import get_default_amendments
        return set(get_default_amendments())
    except Exception:                                      # noqa: BLE001
        return set()


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
        # transaction (otxn_param). A name may appear in both without
        # colliding. Both accept str or bytes keys (normalized to bytes), and
        # assigning any mapping to either attribute re-wraps it in a ParamMap
        # so `rt.params = {"CMD": ...}` behaves the same as item assignment.
        self.params: dict[bytes, bytes] = {}
        self.tx_params: dict[bytes, bytes] = {}
        self.hook_account: bytes = b"\x00" * 20
        self.otxn_account: bytes = b"\x00" * 20
        self.otxn_type: int = 0
        # Fields of the originating transaction, by sfCode, as serialized
        # payload bytes. Consulted ahead of the built-ins above, so a
        # transaction can carry whatever field the hook under test reads.
        self.otxn_fields: dict[int, bytes] = {}
        # True while a *failure* callback is running. The ledger applies a
        # ttEMIT_FAILURE pseudo-transaction in that case, and field presence is
        # checked against it rather than against the emission that failed — so
        # a hook can read only sfLedgerSequence and sfTransactionHash, whatever
        # the original transaction carried. See `handlers.otxn.otxn_field`.
        self.emit_failure: bool = False
        # The whole originating transaction, serialized. Set it when a hook
        # slots the transaction and navigates into it (otxn_slot), which needs
        # bytes rather than a field map. Left None, otxn_slot serializes
        # otxn_fields instead, so the two views agree by construction.
        self.otxn_blob: bytes | None = None
        self.ledger_seq_val: int = 100
        self.ledger_last_time_val: int = 0  # seconds since Ripple epoch
        self.call_log: list[HostCall] = []
        self.emitted_txns: list[bytes] = []
        # Emissions from a run that rolled back. See the note in `run`.
        self.attempted_emissions: list[bytes] = []
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
        # Emits hookz could not fully read, so applied no rules to. Distinct
        # from rejections: an empty rejections list means either 'judged and
        # clean' or 'never judged', and only this says which.
        self.emission_undecided: list = []
        self._etxn_reserved: bool = False
        self._etxn_count: int = 0
        self._emit_nonce_counter: int = 0
        self._foreign_state_db: dict[tuple[bytes, bytes, bytes], bytes] = {}
        self._param_overrides: dict[bytes, dict[bytes, bytes]] = {}

    @property
    def params(self) -> ParamMap:
        return self._params

    @params.setter
    def params(self, mapping) -> None:
        self._params = ParamMap(mapping or {})

    @property
    def tx_params(self) -> ParamMap:
        return self._tx_params

    @tx_params.setter
    def tx_params(self, mapping) -> None:
        self._tx_params = ParamMap(mapping or {})

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

    @contextmanager
    def callback(self, ctx: int):
        """Scope a `cbak` invocation, deriving what the ledger would expose.

        `emit_failure` is not something a caller should be trusted to set. The
        chain derives it — `isCallback && wasmParam & 1`
        (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:1076) — and the failure
        mode of getting it wrong is silent and one-directional: forget it, and
        the harness serves fields the ledger would refuse, so a dead restore
        path looks alive. Deriving it from `ctx` here means a test cannot be
        wrong about it without being wrong about which callback it is driving.

        Restores on exit, so a runtime reused for a later transaction is not
        left in callback mode.

            with rt.callback(CALLBACK_NOT_APPLIED):
                run_export(rt, hook, "cbak", CALLBACK_NOT_APPLIED)

        **`ctx == 0` does not mean the emission succeeded.** The ledger calls
        back whenever `applied` is true, and `applied = isTecClaim(result)`
        (xahaud:src/xrpld/app/tx/detail/Transactor.cpp:2158) with
        `isTecClaim(x) { return ((x) >= tecCLAIM); }`
        (xahaud:include/xrpl/protocol/TER.h:688) — so every `tec` arrives here
        as 0, indistinguishable from success. A hook branching on `ctx == 0` to
        mean "it worked" is wrong about `tecNO_LINE` and `tecUNFUNDED_PAYMENT`,
        which are the realistic ways an emitted payout dies. Use
        `CALLBACK_APPLIED` / `CALLBACK_NOT_APPLIED` rather than 0 and 1, so a
        test says which of the two it is modelling.
        """
        previous = self.emit_failure
        self.emit_failure = bool(ctx & 1)
        try:
            yield self
        finally:
            self.emit_failure = previous

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
            wasm_bytes, locs = instrument_wasm(wasm_bytes)
            # The instrumentation is what knows which lines are coverable, and
            # dropping it left the tracker with hits and no denominator — every
            # ratio 0/0, which reads as "nothing to cover" rather than "we never
            # asked". `source` is optional; without it the DWARF lines stand
            # alone, unfiltered by the AST.
            source = getattr(hook, "source", None) if isinstance(hook, Hook) else None
            if locs:
                self.coverage.set_executable_lines(locs, source_path=source)

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

        # Emitted transactions are held until the hook finishes and applied
        # only if it succeeded: `finalizeHookResult(hookResult, ctx_,
        # isTesSuccess(result))` (xahaud:src/xrpld/app/tx/detail/Transactor.cpp:2026)
        # drains the queue under `if (doEmit)`, and the field itself is
        # commented "etx stored here until accept/rollback"
        # (xahaud:src/xrpld/app/hook/applyHook.h:149).
        #
        # So a hook that rolls back emits nothing. Leaving them here would let
        # a test assert a payout happened on a run the hook refused. They move
        # to `attempted_emissions`, because "it tried to pay and then rolled
        # back" is a thing a test may legitimately want to prove.
        if not result.accepted and self.emitted_txns:
            self.attempted_emissions = list(self.emitted_txns)
            self.emitted_txns = []
        result.emitted_txns = self.emitted_txns
        result.attempted_emissions = self.attempted_emissions

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
