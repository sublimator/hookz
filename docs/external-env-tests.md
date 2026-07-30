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

By default, `build-test-hooks` compiles locally. For report or CI proofs that
must embed artifacts from the public Xahau compiler, pass `--buildbox`
(`--build-box` is equivalent). Remote mode records the endpoint, request hash,
source hash, and WASM hash in the generated output, retries transient failures,
and never falls back locally.

xahaud's CMake invocation recognizes `HOOKZ_BUILDBOX=1`, passes `--buildbox`
explicitly, and makes hook-header generation an always-run target. This
prevents an existing locally generated header from satisfying an
`OUTPUT`-cached build after the compiler mode changes. Forward the variable
into Docker explicitly.

## What you get

Beyond the CMake mechanism, the branch adds test-writing quality of life:

- **~10s iteration** — xahaud compiles once; edits to your tests or hooks
  recompile only those files and re-link.
- **`TestEnv`** (wraps `Env`) — named accounts: `env.account("alice")`
  auto-creates, funds, and reuses accounts by name.
- **Readable logs** — a log transform rewrites r-addresses to
  `Account("alice")` in all output (including the test suite journal), and
  `env.setPrefix("phase name")` prepends `[phase name]` to every line.
- **`TESTENV_LOGGING`** — per-partition log levels at runtime, no recompile:
  `TESTENV_LOGGING="HooksTrace=trace,View=debug"`.
- **`HooksTrace` journal** — hook `trace()`/`trace_num`/`trace_float` output
  gets a dedicated partition, so you can crank it to trace level without
  drowning in unrelated `View` output.
- **Hook coverage** — with `HOOKS_COVERAGE`, hooks are instrumented with
  `__on_source_line` and xahaud records line:col hits per hook — see
  [Coverage pipeline](#coverage-pipeline).

## Branch status & vendored patch

The canonical branch is [`external-env-tests` on Xahau/xahaud](https://github.com/Xahau/xahaud/tree/external-env-tests).
The Docker image fetches it from GitHub at image build time, so images are
only as fresh as the branch. `origin/dev` was merged into the branch on
2026-07-05, so it carries dev plus the env-tests changes and nothing else.

The change is vendored in this repo as
[`patches/xahaud-external-env-tests.patch`](../patches/xahaud-external-env-tests.patch),
generated as the branch's diff against `origin/dev`, so it applies cleanly
to a current `dev` checkout:

```bash
git checkout dev
git apply /path/to/hookz/patches/xahaud-external-env-tests.patch
```

Keep the branch fresh by merging dev into it periodically — conflicts, if
any, concentrate in `applyHook.h`/`.cpp` (the trace/coverage code) — then
regenerate the patch and push (the Docker build pulls the branch, not your
local checkout):

```bash
git diff origin/dev external-env-tests > patches/xahaud-external-env-tests.patch
```

## What the external-env-tests branch changes

### CMake: external test support

`RippledCore.cmake` accepts the following variables, either as CMake
options (`-DFOO=value`) or environment variables (`FOO=value`), or both:

| Variable | CMake `-D` | Env var | Purpose |
|----------|:----------:|:-------:|---------|
| `HOOKS_TEST_DIR` | path | path | Directory with `*_test.cpp` files |
| `HOOKS_C_DIR` | `domain=path;...` | `domain=path;...` | Hook source dirs for file refs |
| `HOOKS_COVERAGE` | `ON` | set = enabled | Instrument hooks with coverage callbacks |
| `HOOKS_TEST_ONLY` | `ON` | set = enabled | Exclude built-in `*_test.cpp` from `src/test/` |
| `HOOKS_FORCE_RECOMPILE` | `ON` | set = enabled | Bypass dependency tracking and bytecode cache |
| `HOOKZ_BUILDBOX` | `ON` | `1` | Use the canonical service and always regenerate hook headers |

**Note:** The `HOOKS_*` Boolean env vars are existence-checked — setting them
to any value (even `0`) enables the feature. `HOOKZ_BUILDBOX` is stricter:
its environment value must be `1`.

CMake runs `hookz build-test-hooks` per test file. Local mode tracks `.c`/`.h`
dependencies and recompiles when sources change; buildbox mode deliberately
runs every time.

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
- `env.setPrefix("phase name")` — prepends `[phase name]` to every log line
- `TESTENV_LOGGING` env var for per-partition log levels
  (e.g. `TESTENV_LOGGING="HooksTrace=trace,View=debug"`)

### Log.h / SuiteJournal.h

`Logs::setTransform()` hooks into all log output (including
`SuiteJournalSink` used by the test framework). TestEnv installs a
transform that replaces r-addresses with `Account(name)` and prepends
the current prefix.

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
global map keyed by hook hash.

#### Wiring up coverage in your test suite

In your `run()` method, reset coverage at the start, label your hooks,
and dump after all tests:

```cpp
void run() override
{
    using namespace test::jtx;
    auto const sa = supported_amendments();

    // Reset and label hooks
    hook::coverageReset();
    {
        HOOK_WASM(tip, "file:tipbot/tip.c");
        HOOK_WASM(top, "file:tipbot/top.c");
        hook::coverageLabel(tip_hash, "file:tipbot/tip.c");
        hook::coverageLabel(top_hash, "file:tipbot/top.c");
    }

    // Run tests...
    RUN(testDeposit);
    RUN(testWithdraw);

    // Dump coverage to a file
    auto const* covDir = std::getenv("HOOKS_COVERAGE_DIR");
    if (covDir)
    {
        auto now = std::chrono::system_clock::now().time_since_epoch();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        std::string path = std::string(covDir) + "/MyHook_" + std::to_string(ms) + ".dat";
        hook::coverageDump(path);
    }
}
```

#### Output format

Each section is a hook (by label or hash), followed by comma-separated
`line:col` pairs sorted by packed key:

```
[file:tipbot/tip.c]
hits=42:5,43:9,44:13,...

[file:tipbot/top.c]
hits=15:5,16:9,...
```

The `line:col` values come directly from DWARF debug info — no
post-processing symbolication needed.

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
