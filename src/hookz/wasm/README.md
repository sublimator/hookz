# hookz.wasm — WASM binary manipulation for Xahau hooks

Parse, validate, clean, and serialize Xahau hook WASM binaries in pure Python.

## Why this exists

Xahau hooks are WebAssembly modules with strict constraints enforced by xahaud. A hook binary must:

1. Export exactly `hook()` and optionally `cbak()` — nothing else
2. Import only whitelisted functions from the `env` module
3. Have a `_g()` guard call at the top of every `loop`
4. Have worst-case execution count under 65,535 instructions
5. Contain no custom sections, no `call_indirect`, no `memory.grow`

Compilers (clang/wasi-sdk) produce binaries that violate most of these: they add extra exports (`__wasm_call_ctors`, `memory`), custom debug sections, and may place guard calls away from loop tops due to optimization.

Two tools in the Xahau ecosystem fix this:

- **hook-cleaner** — rewrites the binary to strip sections, fix exports, and move guard calls to loop tops
- **guard_checker** — validates the final binary meets all constraints

This package reimplements both in Python, using our own internal types.

## Reference implementations

| Tool | Location | Language | Lines |
|------|----------|----------|-------|
| Hook cleaner | [`RichardAH/hook-cleaner-c`](https://github.com/RichardAH/hook-cleaner-c) | C | 1559 |
| Guard checker | `xahaud include/xrpl/hook/Guard.h` | C++ | 1529 |
| Guard checker (also) | `xahaud src/xrpld/app/tx/detail/SetHook.cpp` (calls `validateGuards`) | C++ | 2156 |
| Hook API whitelist | `xahaud include/xrpl/hook/Enum.h` (`getImportWhitelist`) | C++ | 466 |
| Hook API signatures | `xahaud include/xrpl/hook/hook_api.macro` | C macro | 374 |
| Genesis hook makefile | `xahaud hook/genesis/makefile` | make | — |

## How the guard checker works

Reference: `Guard.h` — `validateGuards()` + `check_guard()`

### What it validates

The guard checker makes two passes over the WASM binary:

**Pass 1 — Section parsing:**
- Verifies WASM magic number and version
- Rejects custom sections (section id 0)
- Parses the import section to find `_g` and verify all imports are whitelisted
- Parses the export section to find `hook` and `cbak` function indices
- Parses the function section to map function indices to type indices
- Validates the type section: `hook`/`cbak` must be `int64_t (*)(uint32_t)`
- Sections must appear in order and not repeat

**Pass 2 — Instruction walking (per code body):**

For each function body, `check_guard()` walks the raw bytecode instruction by instruction, building a tree of `WasmBlkInf` (block info) nodes:

```
root (iteration_bound=1)
├── loop (iteration_bound=21)  ← from _g(id, 21)
│   ├── if (iteration_bound=21) ← inherits from parent
│   └── loop (iteration_bound=5)  ← nested _g(id, 5)
└── if (iteration_bound=1)
```

At every `loop` instruction, it expects exactly this pattern:

```wasm
loop $label
  i32.const <guard_id>      ;; unique ID (line number << 31 | maxiter)
  i32.const <maxiter>        ;; maximum iterations
  call $_g                   ;; guard function
  ...loop body...
end
```

If any instruction other than `i32.const` appears between the `loop` and the `call $_g`, it's rejected.

Other things checked per-instruction:
- `call` — target must be an imported function (index ≤ last_import_idx)
- `call_indirect` — always rejected (disallowed in hooks)
- `memory.grow` — always rejected
- `memory.copy` / `memory.fill` — rejected if `rulesVersion & 0x01`
- Block nesting depth — max 16 levels

**Worst-case execution (WCE) computation:**

After walking all instructions, `compute_wce()` traverses the block tree bottom-up:

```
WCE(node) = instruction_count + sum(WCE(children))
multiplier = node.iteration_bound / parent.iteration_bound
WCE *= multiplier
```

If the total exceeds 65,535, the hook is rejected.

## How the cleaner works

Reference: `cleaner.c`

The cleaner does a two-pass rewrite of the entire WASM binary:

### Pass 1 — Analysis

Walks all sections to discover:
- Type section: records all function type signatures (`param_types`, `result_types`)
- Import section: counts function imports, finds `_g` index, maps `func_idx → type_idx`
- Function section: maps defined functions to their type indices
- Export section: finds `hook` and `cbak` function indices
- Code section: measures the byte size of hook/cbak function bodies

### Pass 2 — Rewrite

Writes a new WASM binary with these transforms:

**Sections dropped entirely:**
- Custom sections (id 0) — debug info, producer metadata
- Table section (id 4) — not needed for hooks
- Start section (id 8) — hooks don't use start functions
- Element section (id 9) — not needed without tables

**Sections copied as-is:**
- Memory (id 5)
- Data (id 11)
- Data count (id 12)
- Global (id 6)

**Sections rebuilt from scratch:**

*Type section:* Only types actually referenced by remaining imports + hook/cbak. Type indices are remapped.

*Import section:* Only function imports (drops table/memory/global imports). Type indices remapped to match new type section.

*Function section:* Contains exactly 1 or 2 entries (hook, and optionally cbak), all pointing to the hook/cbak type.

*Export section:* Exactly `hook` (and optionally `cbak`), with corrected function indices (`import_count + 0`, `import_count + 1`).

*Code section:* Only hook/cbak function bodies. **This is where guard rewriting happens.**

### Guard rewriting (the interesting part)

The cleaner walks each instruction in the hook/cbak code bodies looking for "dirty" guard patterns. Compilers sometimes place the `_g()` call away from the loop top:

```wasm
;; "Dirty" guard — compiler scattered the instructions
loop $label
  i32.store ...          ;; ← other instructions between loop and guard
  local.get $x
  i32.const <guard_id>   ;; ← found
  i32.const <maxiter>    ;; ← found
  call $_g               ;; ← found
  drop                   ;; ← trigger: drop after guard call
  ...rest of loop...
```

When it detects this pattern (two `i32.const` values followed by `call _g` followed by `drop`, with intervening instructions), it:

1. Reconstructs the canonical guard: `i32.const <id>, i32.const <maxiter>, call _g, drop`
2. Inserts it at the loop top
3. NOP-fills the original guard location
4. Adjusts code section and body sizes to account for any added bytes

The result is a binary where every loop has a clean guard pattern at the top, which the guard checker can then validate.

## Production pipeline

From `xahaud hook/genesis/makefile`:

```bash
# 1. Compile with size optimization
wasmcc hook.c -o hook.wasm -Oz -Wl,--allow-undefined -I../

# 2. Optimize aggressively (optional, for size)
wasm-opt hook.wasm -o hook.wasm --flatten --dce --vacuum -Oz ...

# 3. Clean: strip sections, rewrite guards, fix exports
hook-cleaner hook.wasm

# 4. Validate: check guards, compute WCE
guard_checker hook.wasm
```

Our hookz equivalent:

```bash
# Production build (compile + optimize + clean + guard-check)
hookz build hook.c

# Individual steps
hookz clean hook.wasm              # strip sections, rewrite guards
hookz guard-check hook.wasm        # validate guards, show WCE

# WCE budget analysis with source line mapping
hookz wce hook.c                   # per-loop breakdown
hookz wce --source hook.c          # annotated source with per-line cost
```

### hookz build pipeline

```
source.c
  → compile (wasi-sdk clang, -Oz)
  → optimize (wasm-opt --flatten ... -Oz, if available)
  → clean (strip sections, rewrite guards, rebuild exports)
  → guard-check (validate patterns, compute WCE)
  → output.wasm (production-ready)
```

### hookz wce pipeline

```
source.c
  → compile (wasi-sdk clang, -g -O0, debug build with DWARF)
  → clean with KeepDebugVisitor (rewrite guards, keep .debug_line)
  → analyze_wce (best-effort, never fails)
  → cross-reference guard_id → source line
  → display per-loop WCE breakdown + optional annotated source
```

## Visitor pattern

The cleaner uses a visitor pattern for pluggable control over what gets
kept or stripped. Subclass `Visitor` to customize:

```python
from hookz.wasm.visitor import Visitor, Action

class MyVisitor(Visitor):
    def on_custom_section(self, name, size):
        if name == ".debug_line":
            return Action.KEEP
        return Action.STRIP

    def on_export(self, name, kind, index):
        return Action.KEEP  # keep all exports

cleaned = clean_hook(wasm, visitor=MyVisitor())
```

Built-in visitors:
- `Visitor` — default hook cleaner (strip everything non-essential)
- `KeepDebugVisitor` — preserves `.debug_line` for DWARF mapping
- `KeepAllVisitor` — keeps everything (analysis only)
- `WceVisitor` — collects loop/instruction data during walking

## Package structure

```
src/hookz/wasm/
    __init__.py
    README.md         ← you are here
    types.py          — Module, FuncType, Import, Export, CodeBody, etc.
    decode.py         — WASM binary → Module (wraps wasm-tob)
    encode.py         — Module → WASM binary (LEB128 writer)
    guard.py          — guard checker + WCE analysis (three layers)
    clean.py          — cleaner (strip, rewrite guards, rebuild sections)
    optimize.py       — wasm-opt CLI wrapper (strip, optimize, DCE)
    visitor.py        — visitor pattern for pluggable clean decisions
```

### guard.py layers

1. `_walk_code()` — builds BlockInfo tree from bytecode, best-effort, never raises
2. `validate_guards()` — strict validation (canonical patterns, call restrictions)
3. `analyze_wce()` — best-effort WCE analysis, works on dirty/debug builds

## Dependencies

- **wasm-tob** — pure Python WASM decoder. Used in `decode.py` for section parsing and instruction decoding. We wrap its types in our own (`types.py`) so the rest of the package doesn't depend on it directly.
- **wasm-opt** (optional) — binaryen CLI tool for size optimization. Installed via `brew install binaryen`. Used by `hookz build` if available; skipped with a warning if not. Not required for correctness.
