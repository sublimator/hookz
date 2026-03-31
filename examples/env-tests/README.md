# Running external Env tests against xahaud

This example shows how to run hook integration tests against xahaud's
C++ test environment (`Env`) — real ledger closes, real transactions,
real guard validation.

**Prerequisites**: a working xahaud build environment (conan, ccache,
cmake, clang — see xahaud's build docs). This is non-trivial to set up
and the CI story is still being worked out.

## Included test files

This directory contains real TipBot integration tests as a reference:

- `TipBot_test.cpp` — basic deposit/withdraw/tip tests
- `TipBotClaude_test.cpp` — extended tests (generated with Claude)

These reference `"file:tipbot/tip.c"` and `"file:tipbot/top.c"` which
need the actual hook source from a tipbot-hooks checkout.

## Running the TipBot tests

```bash
# Env vars for the test run
export TESTENV_LOGGING=HooksTrace=trace
export TIPBOT_CLAUDE_TEST=testE2EDepositTipWithdraw

# hookz build settings
rm -rf ~/.cache/hookz-builds
export HOOKZ_NO_COVERAGE=
export HOOKS_FORCE_RECOMPILE=1
export HOOKS_VALIDATE_FAIL_FAST=1
export HOOKS_GUARDCHECK_FAIL_FAST=1

# Run via xahaud-scripts (x-run-tests)
# Point HOOKS_TEST_DIR at this directory (or your own test dir)
HOOKS_TEST_ONLY=1 \
  HOOKS_COVERAGE=1 \
  HOOKS_TEST_DIR=$(pwd) \
  HOOKS_C_DIR="tipbot=~/projects/tipbot-hooks" \
  HOOKS_COVERAGE_DIR=/tmp/hook_coverage \
  x-run-tests --reconfigure-build -- "ripple.app.TipBotClaude"
```

## What this does

1. `HOOKS_TEST_ONLY=1` — excludes xahaud's built-in `*_test.cpp` files,
   only compiles your external tests
2. `HOOKS_COVERAGE=1` — instruments hooks with `__on_source_line` callbacks
3. `HOOKS_TEST_DIR` — points CMake at the test files in this directory
4. `HOOKS_C_DIR` — maps the `tipbot` domain to your hook source checkout
5. `x-run-tests` — from [xahaud-scripts](https://github.com/nicholasdudfield/xahaud-scripts),
   handles cmake configure + build + test execution
6. `--reconfigure-build` — re-runs cmake configure (needed when changing
   `HOOKS_*` vars)
7. `"ripple.app.TipBotClaude"` — run just the TipBotClaude test suite

## Requirements

- xahaud [`external-env-tests`](https://github.com/Xahau/xahaud) branch
- [xahaud-scripts](https://github.com/nicholasdudfield/xahaud-scripts) (`x-run-tests`)
- hookz on PATH (`uv tool install --editable ~/projects/hookz`)
- conan, ccache, cmake, ninja — see xahaud build docs

## Env var reference

| Variable | Purpose |
|----------|---------|
| `TESTENV_LOGGING` | Per-partition log levels (e.g. `HooksTrace=trace,View=debug`) |
| `HOOKS_TEST_ONLY` | Exclude xahaud's built-in tests |
| `HOOKS_COVERAGE` | Enable coverage instrumentation |
| `HOOKS_TEST_DIR` | Your test directory |
| `HOOKS_C_DIR` | `domain=path` for file refs |
| `HOOKS_COVERAGE_DIR` | Where to write coverage `.dat` files |
| `HOOKS_FORCE_RECOMPILE` | Bypass all caching |
| `HOOKS_VALIDATE_FAIL_FAST` | Abort on first validation failure |
| `HOOKS_GUARDCHECK_FAIL_FAST` | Abort on first guard check failure |
| `HOOKZ_NO_COVERAGE` | Set to disable coverage even when `HOOKS_COVERAGE=1` |
| `HOOKZ_VALIDATE` | Enable hookz output sanity checks |

See [docs/external-env-tests.md](../../docs/external-env-tests.md) for the full picture.
