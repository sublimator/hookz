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


class HookRuntime:
    """Execute WASM hooks with mocked hook API.

    Example:
        rt = HookRuntime()
        rt.state_db[key] = value
        rt.set_param(0, opinion_bytes)
        result = rt.run(wasm_bytes)
        assert result.accepted
        assert rt.state_db[key] == expected
    """

    def __init__(self) -> None:
        self.state_db: dict[bytes, bytes] = {}
        self.params: dict[bytes, bytes] = {}
        self.hook_account: bytes = b"\x00" * 20
        self.otxn_account: bytes = b"\x00" * 20
        self.otxn_type: int = 0
        self.ledger_seq_val: int = 100
        self.call_log: list[HostCall] = []
        self.emitted_txns: list[bytes] = []
        self.traces: list = []  # list[Trace] from handlers.core
        self.coverage = CoverageTracker()
        self._shared_coverage: CoverageTracker | None = None
        self.handlers: dict[str, Callable] = {}
        self._slot_overrides: dict[str, Any] = {}
        self._memory: wasmtime.Memory | None = None
        self._store: wasmtime.Store | None = None

    def set_param(self, key: int | bytes, value: bytes) -> None:
        """Set a hook parameter for the next execution."""
        if isinstance(key, int):
            key = key.to_bytes(1, "little")
        self.params[key] = value

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
        # Preserve markers if already loaded
        markers = self.coverage._markers
        self.coverage = CoverageTracker()
        self.coverage._markers = markers

        if coverage:
            from hookz.coverage.rewriter import instrument_wasm
            wasm_bytes, _locs = instrument_wasm(wasm_bytes)

        engine = wasmtime.Engine()
        store = wasmtime.Store(engine)
        self._store = store

        module = wasmtime.Module(engine, wasm_bytes)
        linker = self._make_host_functions(store, module)

        instance = linker.instantiate(store, module)

        # Get memory export
        memory = instance.exports(store).get("memory")
        if isinstance(memory, wasmtime.Memory):
            self._memory = memory

        # Get hook export
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
