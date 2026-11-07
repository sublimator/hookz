# hookz

Test framework for [Xahau](https://xahau.network) WASM hooks, in two modes: a millisecond-feedback unit loop that executes C hooks in Python with line-level coverage — no xahaud required — and integration testing against real xahaud via a pre-built Docker image. Plus a production build toolchain: cleaner, guard checker, WCE budget analysis.

**Experimental** — expect bugs and dragons for a while.

## Why

There are several ways to test Xahau hooks today:

| Approach | Build | Feedback | Coverage | Trace |
|----------|-------|----------|----------|-------|
| Official live/testnet | N/A | 3-4s per ledger close | None | Log scraping |
| Standalone xahaud | Touched a header? Minutes | 3-4s per ledger close | None | Log scraping |
| xahaud C++ test env (`Env`) | Touched a header? Minutes | ~1s per ledger close | C++ only (gcov) | Buried in journal |
| **hookz** | **~1s (WASM compile)** | **Milliseconds** | **Line-level C source** | **Structured + clickable** |

Multi-ledger scenarios (governance votes, settlement, cleanup) compound those per-ledger waits.

- hookz runs hooks in Python via wasmtime with mocked host functions
- All 70 hook API functions implemented
- Full power of Python and pytest for setup, assertions, parametrization
- `hookz show` lets you (or AI agents) look up the C++ source for any host function
- `/impl-handler` skill teaches agents to port handlers and write tests
- Designed for fast iteration — write a test, see coverage, fix the hook, repeat

For integration testing against real xahaud, see [Integration testing with xahaud](#integration-testing-with-xahaud) below.



## Using hookz

### Prerequisites

- [uv](https://docs.astral.sh/uv/)
- [wasi-sdk](https://github.com/WebAssembly/wasi-sdk) (C to WASM compiler — `mise install wasi-sdk`, or auto-detected from common paths)
- [wasm-opt](https://github.com/WebAssembly/binaryen) (`brew install binaryen` / `apt install binaryen`) — **required to build**: `hookz build` and `hookz wce hook.c` both fail without it, because the production pipeline runs it. Not needed to run tests, or for `hookz wce hook.wasm` / `guard-check` on an artifact you already have.
- Optional: xahaud checkout (for `hookz show` source lookup — falls back to vendored headers)

### Setup

```bash
mkdir -p ~/projects && cd ~/projects
git clone <hookz-repo> hookz
git clone <xahaud-repo> xahaud

# Start a new hook project
mkdir dao-hook && cd dao-hook
uv init
uv add hookz --editable ../hookz
uv add pytest
```

### Configure

Create `hookz.toml` in your project root:

```toml
[paths]
xahaud = "../xahaud"
wasi_sdk = "~/.local/share/mise/installs/wasi-sdk/32/wasi-sdk"

[hooks]
dao = "src/dao.c"
```

All `[paths]` entries support `${var}` substitution, `~` expansion, and `HOOKZ_<KEY>` env var overrides.

For machine-specific overrides (different wasi-sdk path, etc.), create `.hookz.local.toml` — same format, not committed.

### Write tests

```python
# tests/conftest.py
from hookz.testing import register_hooks_from_config
register_hooks_from_config()
```

```python
# tests/test_my_hook.py
from hookz.runtime import HookRuntime
from hookz import hookapi

def test_outgoing_passes(dao_hook):
    rt = HookRuntime()
    rt.hook_account = b"\x01" * 20
    rt.otxn_account = rt.hook_account  # same = outgoing
    rt.otxn_type = hookapi.ttINVOKE
    result = rt.run(dao_hook)
    assert result.accepted

def test_non_member_rejected(dao_hook):
    rt = HookRuntime()
    rt.hook_account = b"\x01" * 20
    rt.otxn_account = b"\x02" * 20
    rt.otxn_type = hookapi.ttINVOKE
    result = rt.run(dao_hook)
    assert result.rejected
    assert b"not a member" in result.return_msg
```

The `dao_hook` fixture is auto-generated from `[hooks] dao = "src/dao.c"`. It compiles, instruments, and caches the WASM.

### Run

```bash
uv run hookz test                             # run all tests
uv run hookz test -k "test_outgoing"          # filter
uv run hookz test -sv                         # verbose + see print output
HOOKZ_TRACE=1 uv run hookz test -sv          # see hook trace output
```

### Try the included example

```bash
cd ~/projects/hookz/examples/tipbot
uv sync
uv run hookz test
```

## CLI

```
hookz doctor                         Check install: toolchain, config, smoke test
hookz test [pytest args...]          Run tests
hookz build hook.c                   Local structural build + validation
hookz build hook.c --hooks-compiler  Reference compiler build + local validation
hookz wce hook.wasm                  WCE of the exact artifact you hand it
hookz wce hook.c                     Build production-style, then weigh the result
hookz wce hook.c --loops             Add the partial guard-line loop mapping
hookz guard-check hook.wasm          Validate guard calls and show WCE
hookz clean hook.wasm                Clean WASM for deployment (strip + rewrite guards)
hookz show float_multiply            Show C++ source + xahaud test vectors
hookz show --list                    All 70 functions: implemented vs stub
hookz coverage                       Tests + uncovered line report
hookz find-tests tip.c:225-400       Which tests cover these lines?
hookz surface hook.c                 Every host call, with the constants resolved
hookz env-test-context hook.c        One document to write a C++ env test from
hookz debug-compile hook.c           Debug build for testing (not for deployment)
```

## Production builds

`hookz build` uses hookz's own `local-structural` pipeline and produces
deployment-ready WASM from C source in one command:

```bash
hookz build reward.c
  Built reward.c via 'local-structural' pipeline (clang -O3 → binaryen → cleaner)
    3,281 bytes, block depth 6
    Guard check PASSED (hook WCE=8,446 — 12.9% of budget)
    rules: 0x03 (nesting limit 32)      # which amendments produced that verdict
    → reward.wasm (3281 bytes)
```

`--explain` prints size, depth and WCE after every stage. The `rules:` line is
there because a verdict without its basis invites the reader to supply one:
wasm-opt runs on this path and the build fails without it, so a "PASSED" here
is a claim about the binary that toolchain produced, judged under the
amendments that manifest records.

The cleaner (Python port of [hook-cleaner-c](https://github.com/RichardAH/hook-cleaner-c)) strips custom sections, rebuilds exports to only `hook`/`cbak`, rewrites guard calls to canonical loop-top form, and remaps type indices. The guard checker (port of xahaud `Guard.h`) validates the result.

`local-structural` is not a reference build. Its flags were copied from the
retired hook-buildbox service, and its bytes match no Xahau compiler exactly.
For the artifact Xahau's own tools produce, use the reference compiler:

```bash
hookz build reward.c --hooks-compiler
hookz build-test-hooks Reward_test.cpp --hooks-compiler
```

That is [tequdev/hooks-compiler](https://github.com/tequdev/hooks-compiler),
which `@xahau/hooks-cli` 3.x and the Hooks Builder IDE both use: clang 22,
wasm-ld, `wasm-opt -Oz` and hook-cleaner, all run as WebAssembly inside Node,
deterministically, with no server. hookz runs it through `npx` at a pinned
version (`hookz.hooks_compiler.VERSION`), so this mode needs Node >= 20.12. The
first run downloads the toolchain (about 30 MB) into npm's cache; later builds
take a few seconds each.

The mode strips hookz audit annotations and gives hooks-compiler what a local
build would find, in clang's order: the `.h` files beside the source, the
project's `extra_cflags` `-I` directories, then the hook headers. It records
the source and WASM SHA-256 and independently guard-checks the returned
bytes. It never falls back to a local
compiler. `HOOKZ_HOOKS_COMPILER=1` selects it in CMake/CI pipelines.

`--buildbox` and `HOOKZ_BUILDBOX=1` are refused, and say where to go:
hook-buildbox.xrpl.org was retired in October 2026, when Xahau's tools moved to
hooks-compiler. `hookz build --pipeline buildbox` is refused too. It used to be
an alias for the **local** `local-structural` pipeline. Use `--hooks-compiler`
for the reference compiler, or `--pipeline local-structural` for hookz's own
build — `hookz pipelines` lists what the flag will take.

## WCE analysis

WCE is a property of the WASM xahaud executes, so `hookz wce` weighs one exact
artifact and says which one:

```bash
hookz wce govern.wasm

  govern.wasm — exact-artifact WCE
    sha256: 6f1c…                         # the bytes that were weighed
    bytes: 3,171
    provenance: provided artifact: govern.wasm
    rules: 0x03 (nesting limit 32)        # the amendments mainnet has in force

    DEPLOYABILITY: PASSED

    hook() WCE: 19,314 / 65,535 (29.5%)
```

The verdict is given under stated rules, because the rules are not a constant:
xahaud derives `rulesVersion` per-ledger from the amendments in force, and
hookz derives it from the same manifest. `fixGuardDepth32` is `DefaultNo`;
mainnet voted it in before the 2026-11-07 manifest read, so the nesting limit
is now 32 (it was 16). There was never a flag to assume it: when the vote
landed the manifest carried it and every verdict moved at once. `hookz doctor`
prints which vote produced which bit.
See [`src/hookz/wasm/README.md`](src/hookz/wasm/README.md).

Given C instead, it builds first and names the compiler it used: the local
`local-structural` pipeline by default, or the reference compiler with
`--hooks-compiler`. Only then does it weigh the result. Deployability is the headline
— a hook xahaud would reject exits non-zero, and its WCE total is reported as a
floor rather than a number.

Add `--loops` for the per-loop breakdown. Loop rows come from guard IDs (`_g`
encodes `__LINE__`), and they are labelled a partial mapping on purpose: loop
subtree costs nest, so they overlap and do not sum to the total. When the build
stripped hookz annotations — `local-structural` and `--hooks-compiler` both do — each
row cites the annotated line alongside the artifact's own, as
`line 43 (artifact 42)`.

```
    line 722  GUARD(3    )  subtree WCE  14,700
    line 724  GUARD(67   )  subtree WCE   4,891
    line 279  GUARD(21   )  subtree WCE   1,953
```

`--source` appends a per-line view built from separate DWARF-carrying twin
builds, with `ELIM` markers for lines missing from the optimized twin. It is a
navigation aid, not the artifact's WCE: the twins have their own control-flow
trees, and the command labels the panel accordingly. A standalone `.wasm` has
no verified source twin, so `--source` is refused there rather than guessed.

```
 debug │   -Oz │      │
 ──────┼──────┼──────┼──────────────────────────────────
     7 │    6 │   27 │     ► for (int i = 0; GUARD(20), i < 20; ++i)
     5 │    5 │   28 │         if (hook_acc != otxn_acc)
     1 │ ELIM │   30 │             equal = 0;
     2 │ ELIM │   31 │             break;
     1 │    1 │   36 │     if (equal)
```

## Ledger model

Hooks that look up accounts or trust lines via keylets work without mocking:

```python
from hookz.ledger import account_root, book_directory, offer

kl, data = account_root("rBob...", Balance="50000000")
rt.ledger[kl] = data
result = rt.run(hook)  # hook's util_keylet + slot_set just works
```

20+ keylet functions matching xahaud exactly (verified against rippled).
Quality directories and ordered ledger scans use the same exclusive-low,
inclusive-high semantics as Xahau's `KEYLET_QUALITY` and `ledger_keylet` APIs;
`book_directory` and `offer` provide serialized DEX fixtures. `slot_set` with a
34-byte keylet automatically looks up `rt.ledger`.
`slot_subfield`/`slot_count`/`slot_subarray` parse real serialized data and
preserve the value-level VL prefix returned by Xahau for blob and Vector256
slots.

## Randomness (featureRNG)

`dice` and `util_random` draw from the ledger's RNG state, which on chain comes
from validator reveals. hookz emulates the draw deterministically from a state
the test supplies:

```python
rt.amendments.add("featureRNG")     # not enabled at the 2026-11-07 manifest read (majority since 11-05)
rt.seed_random(b"\x11" * 32)        # this ledger's Random object
result = rt.run(hook)

result.random_data                  # the state the first draw saw (sfRandomData)
result.random_draws                 # every draw: api, state, output block
rt.random.random_data               # the advanced state
```

With no `seed_random` (`rt.random is None`) every draw answers
`TOO_LITTLE_ENTROPY`, as on a ledger no entropy round has seeded. The seed is
pinned to the current `ledger_seq_val`; bump the sequence and draws refuse
again. `seed_random(..., entropy_count=, entropy_denominator=)` models a round
too few validators joined (fewer than 80% refuses). Each draw steps the state
to `sha512Half("RNGI" | state)` whatever the run's outcome — a rolled-back
hook's draws stay drawn — and at most 256 draws succeed per run.

The block hashes the state with the execution: the transaction ID (`otxn_id`,
or `rt.applied_txn_id`), `rt.hook_account`, the hook hash (sha512Half of the
module bytes, or `rt.hook_hash`), `rt.hook_chain_position`, and whether the run
is strong, a callback, and its argument — the last three from
`run(..., export=, arg=)`. The exact byte layout, with a citation per rule, is
in [`handlers/rng.py`](src/hookz/handlers/rng.py).

## Traces

Hooks call `trace`, `trace_num`, and `trace_float` host functions (some hooks wrap these with macros like `TRACEVAR`/`TRACEHEX`). hookz captures these with source line numbers:

```
[hook] tip.c:227  member_count: 3
[hook] tip.c:228  threshold: 2
[hook] tip.c:320  current_ledger: 100
```

Set `HOOKZ_EDITOR=clion` (or `pycharm`, `idea`, any JetBrains IDE) for clickable links that open your editor at the right line. Custom: `HOOKZ_EDITOR='@myscheme://%file:%line'`.



## Coverage

hookz instruments WASM via DWARF debug info, then uses tree-sitter to filter non-executable lines (comments, braces, declarations). You get real coverage of real C code:

```
┌─────────── tip.c coverage ───────────────────────┐
│ 201/201 executable lines covered (100%)           │
└───────────────────────────────────────────────────┘
  tip.c: 100% coverage!

┌─────────── top.c coverage ───────────────────────┐
│ 194/194 executable lines covered (100%)           │
└───────────────────────────────────────────────────┘
  top.c: 100% coverage!
```

## Integration testing with xahaud

hookz also supports a second mode: using xahaud itself as a test runner for your hooks. You write C++ test files (`*_test.cpp`) in your own project, and xahaud builds and runs them — real ledger closes, real transactions, real guard validation.

The key idea: **your tests live outside the xahaud repo**. xahaud becomes a test runner you point at your code, not a repo you fork and modify. This fixes the "touched a header? minutes" pain from the table up top: xahaud compiles once (or comes pre-built), and only your test files compile — about 10 seconds.

### Quick start (Docker)

No local xahaud build required — a public image ships with xahaud pre-compiled and a primed ccache:

```bash
cd examples/tipbot
# Pin lives in .github/workflows/xahaud-integration.yml (DEFAULT_IMAGE).
IMAGE=ghcr.io/sublimator/hookz-xahaud:2026-11-07-hookz-fdbb355
# Mount this repo's entrypoint if the image predates HOOKZ_REF/HOOKZ_SPEC.
docker run --rm \
  -v ./env-tests:/tests \
  -v ./hooks:/hooks/tipbot \
  -v "$(pwd)/../../docker/entrypoint.sh:/entrypoint.sh:ro" \
  -v "$(pwd)/../..:/hookz-src:ro" \
  -e HOOKS_TEST_DIR=/tests \
  -e HOOKS_C_DIR="tipbot=/hooks/tipbot" \
  -e HOOKZ_SPEC="hookz @ /hookz-src" \
  "$IMAGE" \
  "ripple.app.TipBot,ripple.app.TipBotClaude"
```

This compiles your test files (~10s) and runs them against real xahaud. See [examples/tipbot/env-tests](examples/tipbot/env-tests/README.md), and [A guide for AI: how to write Env tests](examples/tipbot/env-tests/A-GUIDE-FOR-AI.md) for the workflow end to end — including why the Python harness is for development and Env tests are the sign-off. CI uses the same pattern: frozen image + **this checkout’s** hookz via `HOOKZ_SPEC` ([xahaud-integration.yml](.github/workflows/xahaud-integration.yml)).

### How it works

You write C++ test files in your own repo using xahaud's `Env` framework, reference your hook source with `"file:domain/path.c"`, and xahaud's CMake calls `hookz build-test-hooks` to compile them. Set `HOOKZ_HOOKS_COMPILER=1` with `HOOKS_FORCE_RECOMPILE=1` when the generated header must contain reference-compiler artifacts rather than local builds; forcing regeneration keeps an older local artifact from satisfying the build. It needs Node on PATH, which the current Docker image lacks. (xahaud's CMake still has the old `HOOKZ_BUILDBOX` switch, which hookz now refuses; see [docs/external-env-tests.md](docs/external-env-tests.md).) Your tests and hooks stay in your repo — xahaud is just the engine.

Inline `[test.tshook]` / `[test.jshook]` blocks and `.ts` / `.js` file
references are compiled by `jshookz compile-hook`. Install `jshookz` on PATH,
or override the command with `JSHOOKZ_HOOK_COMPILER`. The retired
`QJS_HOOK_COMPILER` name remains a compatibility fallback.

On the xahaud side this is a small CMake patch (plus optional coverage and logging support), maintained as the [`external-env-tests`](https://github.com/sublimator/xahaud/tree/external-env-tests) branch and vendored here as [`patches/xahaud-external-env-tests.patch`](patches/xahaud-external-env-tests.patch). The Docker image has it baked in, so you only need it for local, non-Docker runs. The core is just:

```cmake
# cmake/RippledCore.cmake (condensed — see the patch for the full block)
file(GLOB EXTERNAL_HOOK_TESTS CONFIGURE_DEPENDS "${HOOKS_TEST_DIR}/*_test.cpp")

# hookz compiles the hooks each test references → generates <test>_hooks.h
foreach(_test_file ${EXTERNAL_HOOK_TESTS})
  add_custom_command(
    OUTPUT "${_hooks_header}"
    COMMAND hookz build-test-hooks "${_test_file}" ${_hooks_extra_args}
    DEPENDS "${_test_file}" ${_hooks_source_deps})
endforeach()

# your tests compile into rippled like any other unit test
target_sources(rippled PRIVATE ${EXTERNAL_HOOK_TESTS})
set_property(SOURCE ${EXTERNAL_HOOK_TESTS}
  APPEND PROPERTY INCLUDE_DIRECTORIES "${HOOKS_TEST_DIR}")
```

The branch also carries test-writing quality of life ([details](docs/external-env-tests.md)):

- `TestEnv` — `env.account("alice")` auto-creates and reuses named accounts
- Readable logs — r-addresses rewritten to `Account("alice")` in all output; `env.setPrefix("phase")` tags every line
- `TESTENV_LOGGING="HooksTrace=trace,View=debug"` — per-partition log levels at runtime, no recompile
- `HooksTrace` journal — hook `trace()` output on its own log partition instead of drowning in `View` noise
- `HOOKS_COVERAGE` — the same line-level C source coverage, collected from real xahaud execution

See [docs/external-env-tests.md](docs/external-env-tests.md) for setup, CMake vars, coverage wiring, branch status, and test file format.

**Test runtime vars** (read by running test binary):

| Variable | Effect |
|----------|--------|
| `TESTENV_LOGGING` | Per-partition log levels (e.g. `HooksTrace=trace,View=debug`) |

## Developing hookz

### Setup

```bash
cd ~/projects/hookz
uv sync
```

### Run framework tests

```bash
uv run pytest tests/                  # framework tests (570+ tests)
uv run pytest tests/test_handlers/    # handler unit tests
uv run pytest tests/test_wasm.py      # WASM decode/encode/guard/clean tests
```

### Run e2e tests (Xahau genesis hooks + community hooks)

```bash
cd tests/e2e
uv run hookz test                     # 100+ tests across 15 hooks
```

### Run example tests

```bash
cd examples/tipbot
uv sync
uv run hookz test                     # 70 tests, both hooks 100% coverage
```

### Implement a handler

```bash
# See what's unimplemented
uv run hookz show --list | grep "✗"

# Look up the C++ source
uv run hookz show float_multiply

# Add to src/hookz/handlers/float.py — auto-discovered
```

Handlers are plain functions: `def name(rt: HookRuntime, *wasm_args) -> int`. Drop one in `handlers/`, it works.

For AI agents: `/impl-handler float_multiply` runs the full workflow.

### Project layout

```
src/hookz/
  runtime.py              WASM executor + ledger model
  handlers/               70 auto-discovered host functions
  compiler.py             C → WASM via wasi-sdk clang (two-stage for DWARF on -O2)
  config.py               hookz.toml loading + HOOKZ_* env overrides
  wasm/                   WASM binary manipulation:
    types.py                internal Module representation
    decode.py               WASM → Module (via wasm-tob)
    encode.py               Module → WASM (LEB128 writer)
    guard.py                guard checker + WCE analysis
    clean.py                cleaner (strip, rewrite guards, rebuild exports)
    optimize.py             wasm-opt CLI wrapper
    visitor.py              pluggable visitor for clean decisions
    pipeline.py             typed stage outputs for the build pipeline
    whitelist.py            hook API import whitelist (from hook_api.macro)
  coverage/               DWARF rewriter + AST-aware tracker
  xrpl/                   txn parser, xahaud source extraction
  xahaud_files.py         registry of xahaud source paths (backs `hookz show`)
  xahaud_lite/            vendored xahaud headers (fallback when no checkout)
  build_test_hooks.py     generates _hooks.h for external-env-tests
  ledger.py               keylet computation + ledger object builders
  testing/                pytest plugin + fixture generation
  cli/                    hookz CLI
  xfl.py                  XFL <-> float
  account.py              accid <-> r-address
  editor.py               clickable trace links
  hookapi.py              471 auto-generated constants
examples/
  tipbot/                 self-contained example (70 tests, 100% coverage)
tests/
  test_handlers/          handler unit tests (490 tests)
  test_wasm.py            WASM package tests (decode, encode, guard, clean)
  e2e/                    end-to-end hook tests:
    hooks/genesis/          xahaud genesis hooks (govern, mint, nftoken, reward)
    hooks/misc/             custom hooks (balance_gate, treasury)
    hooks/XahauHooks101/    community hook examples (submodule)
```
