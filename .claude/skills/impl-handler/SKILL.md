---
name: impl-handler
description: Implement a hookz host function handler. Use when porting a hook API function from xahaud C++ to Python, or when a test hits NotImplementedError for an unimplemented handler.
allowed-tools: Read, Write, Edit, Bash, Glob, Grep, Agent
---

# Implement a hookz Handler

You are implementing a hook API host function handler for the hookz testing framework.

**Target function:** $ARGUMENTS

## Step 1: Look up the C++ implementation

Run `hookz show $ARGUMENTS` to see:
- The WASM wrapper (applyHook.cpp) — shows the function signature and how args are passed
- The real implementation (HookAPI.cpp) — the logic to port

```bash
uv run hookz show $ARGUMENTS
```

Also check the implementation status:
```bash
uv run hookz show --list | grep $ARGUMENTS
```

## Step 2: Understand the function

From the C++ source, determine:
- **Input args**: What WASM values does it receive? (i32 pointers, i64 XFL values, etc.)
- **Memory access**: Does it read/write WASM linear memory? Use `rt._read_memory()` / `rt._write_memory()`
- **Return value**: What does it return? (i64 result, error codes from hookapi.py, etc.)
- **Side effects**: Does it modify state? Emit transactions? Access slots?

## Step 3: Find the right handler module

Handlers live in `src/hookz/handlers/`. Pick the right file:

| Module | Functions |
|--------|-----------|
| `core.py` | accept, rollback, _g, trace, __on_source_line |
| `state.py` | state, state_set |
| `otxn.py` | otxn_field, otxn_param, otxn_id, otxn_slot |
| `float.py` | float_compare, float_sum, float_negate, float_int, float_set, float_divide, float_sto, float_sto_set |
| `emit.py` | emit, etxn_reserve, etxn_details, etxn_fee_base |
| `slot.py` | slot, slot_set, slot_subfield, slot_count, slot_subarray |
| `util.py` | util_sha512h, util_keylet, hook_account, ledger_seq, ledger_nonce |

Create a new module if none fits.

## Step 4: Write the handler

The handler signature is always:
```python
def function_name(rt: HookRuntime, ...wasm_args) -> int:
```

- First arg is always `rt` (the HookRuntime instance)
- Remaining args match the WASM import signature
- Return type matches the WASM return type (usually i64)
- Use `TYPE_CHECKING` guard for the HookRuntime import to avoid circular imports

Example:
```python
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

def float_multiply(rt: HookRuntime, a: int, b: int) -> int:
    from hookz.xfl import xfl_to_float, float_to_xfl
    fa = xfl_to_float(a)
    fb = xfl_to_float(b)
    if fa == 0 or fb == 0:
        return 0
    return float_to_xfl(fa * fb)
```

**Important**: The handler is auto-discovered. Just add the function — no registration needed.

If the function name starts with `_` (like `_g`), add it to the module's `__handlers__` set:
```python
__handlers__ = {"_g", "__on_source_line"}
```

## Step 5: Write tests

Add tests in `tests/test_handlers/test_<module>.py` — one file per handler module so multiple agents can work in parallel without conflicts.

For handlers that do memory operations, create a real wasmtime Memory:
```python
import wasmtime
from hookz.runtime import HookRuntime

@pytest.fixture
def rt():
    r = HookRuntime()
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    memory = wasmtime.Memory(store, wasmtime.MemoryType(wasmtime.Limits(1, None)))
    r._store = store
    r._memory = memory
    return r
```

For pure value handlers (like float math), just call directly:
```python
def test_float_multiply_basic(rt):
    from hookz.handlers.float import float_multiply
    result = float_multiply(rt, float_to_xfl(3.0), float_to_xfl(4.0))
    assert xfl_to_float(result) == pytest.approx(12.0)
```

## Step 6: Verify

```bash
# Run the handler tests
uv run pytest tests/test_handlers/ -v

# Run the example tests to check nothing broke
cd examples/tipbot && uv run hookz test

# Check implementation status
uv run hookz show --list | grep $ARGUMENTS
```

## Reference

- Error codes: `src/hookz/hookapi.py` (auto-generated, 482 constants)
- XFL conversion: `src/hookz/xfl.py` (xfl_to_float, float_to_xfl)
- Account conversion: `src/hookz/account.py` (to_raddr, to_accid)
- All hook API functions: `uv run hookz show --list`
- xahaud source lookup: `uv run hookz show <function_name>`
