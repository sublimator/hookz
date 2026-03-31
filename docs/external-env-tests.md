# xahaud integration testing

xahaud's `external-env-tests` branch turns xahaud into a test runner for
external hook projects. You write C++ test files in your own repo, point
xahaud's CMake at them, and it builds and runs them with real ledger
simulation — without forking xahaud.

## The setup

Your project has:
- `src/my_hook.c` — your hook source
- `tests/MyHook_test.cpp` — C++ tests using xahaud's `Env` framework

xahaud has:
- The `external-env-tests` branch checked out
- `hookz` on PATH (for `hookz build-test-hooks`)

At build time, CMake:
1. Finds your `*_test.cpp` files via `HOOKS_TEST_DIR`
2. Runs `hookz build-test-hooks` on each → generates `*_test_hooks.h`
3. Compiles your tests into rippled
4. Runs them like any xahaud unit test

Your tests and hooks live in your repo. xahaud is just the engine.

## What the external-env-tests branch changes

### CMake: external test support

`RippledCore.cmake` accepts three variables:

| Variable | Example | Purpose |
|----------|---------|---------|
| `HOOKS_TEST_DIR` | `~/my-hooks/tests` | Directory with `*_test.cpp` files |
| `HOOKS_C_DIR` | `tipbot=~/my-hooks` | `domain=path` pairs for file refs (`;`-separated) |
| `HOOKS_COVERAGE` | `ON` | Instrument hooks with coverage callbacks |

CMake runs `hookz build-test-hooks` per test file, tracks `.c`/`.h`
dependencies, and only recompiles when sources change. Set
`HOOKS_FORCE_RECOMPILE=ON` to bypass caching.

### Enum.h: `__on_source_line` whitelist

The coverage callback is added to the import whitelist with a `void_t`
return type (0x00). Production hooks don't import it, so this has no
effect on normal operation.

### Guard.h: void return types

Changed from "every import must return exactly 1 value" to consulting
the whitelist: if it specifies `void_t`, `result_count == 0` is valid.
Hook/cbak exports still require exactly 1 return value (i64).

### applyHook.h: coverage infrastructure

- `hook::onSourceLine()` — WasmEdge host callback, registered for every
  hook execution. Records `(line << 16 | col)` hits keyed by hook hash.
- `hook::coverageMap()` — global accumulator persisting across all hook
  executions in the process.
- `hook::coverageDump(path)` — writes accumulated coverage to a file.
- `hook::coverageLabel(hash, label)` — register human-readable names.
- `hook::coverageReset()` — clear all data between test runs.

### applyHook.cpp: trace journal

`trace`, `trace_num`, `trace_float` use a dedicated `HooksTrace` journal
partition, allowing per-partition log control in tests without drowning
in unrelated output.

### Macro.h

Added `jh` (HooksTrace journal) to the `DEFINE_HOOK_FUNCTION` template.

### TestEnv.h (new)

`TestEnv` wraps `Env` with:
- Named accounts: `env.account("alice")` — auto-created, reusable
- Log transform: r-addresses replaced with `Account(name)` in all output
- `TESTENV_LOGGING` env var for per-partition log levels

### SuiteLogsWithOverrides.h (new)

Per-partition severity overrides with stderr output (always visible,
not buried in `suite_.log`).

## Coverage pipeline

### How hookz instruments hooks

`hookz build --coverage` (or `hookz build-test-hooks --hook-coverage`):

1. **Two-stage compile**: `clang -c -g -O2` → `wasm-ld`
   - Must be `-O2`: wasi-sdk 32 ignores `-mno-bulk-memory` at other levels,
     emitting `memory.fill` that xahaud rejects
   - Two-stage bypasses wasm-opt, preserving DWARF on optimized code
2. **Instrument**: reads DWARF `.debug_line`, inserts
   `i32.const line; i32.const col; call __on_source_line` at each source
   location boundary
3. **Clean**: strips custom sections, rewrites guard calls to canonical
   form (handles coverage calls interleaved with guard patterns)
4. **Guard-check**: validates with `__on_source_line` in the whitelist

### How xahaud collects coverage

When a coverage-instrumented hook executes, each `__on_source_line` call
hits `hook::onSourceLine()`, which records the (line, col) pair in a
global map keyed by hook hash. After tests:

```cpp
hook::coverageDump("coverage.txt");
```

Output format:
```
[file:tipbot/tip.c]
hits=42:5,43:9,44:13,...

[file:tipbot/top.c]
hits=15:5,16:9,...
```

## Vendored xahaud files

hookz ships a minimal subset of xahaud in `src/hookz/xahaud_lite/` so
it can compile hooks and run `hookz show` without a full xahaud checkout.
Files are vendored from `origin/dev`:

```bash
python scripts/vendor-xahaud.py ~/projects/xahaud --ref origin/dev
```

All paths are centralized in `XahaudFile` enum (`src/hookz/xahaud_files.py`).
When `hookz.toml` points at a full checkout, it takes precedence.

## Build cache

Compiled WASM is cached at `~/.cache/hookz-builds/` keyed on source
content + hookz version. The hookz version includes git SHA and dirty
diff hash, so any code change invalidates the cache.

```bash
hookz config path build-cache    # print the path
rm -rf $(hookz config path build-cache)  # nuke it
```
