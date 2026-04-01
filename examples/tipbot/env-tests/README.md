# Running external Env tests against xahaud

This example shows how to run hook integration tests against xahaud's
C++ test environment (`Env`) — real ledger closes, real transactions,
real guard validation.

## Quick start (Docker)

The easiest way to run these tests is with the pre-built Docker image:

```bash
docker run --rm \
  -v ./env-tests:/tests \
  -v ./hooks:/hooks/tipbot \
  -e HOOKS_TEST_DIR=/tests \
  -e HOOKS_C_DIR="tipbot=/hooks/tipbot" \
  gcr.io/hookz-public/hookz-xahaud:latest \
  "ripple.app.TipBot,ripple.app.TipBotClaude"
```

This pulls a public image with xahaud pre-compiled (+ccache primed),
compiles only your test files (~10s), and runs the tests.

The image is built on [Google Cloud Build](../../docker/cloudbuild.yaml)
and published to `gcr.io/hookz-public/hookz-xahaud`.

## CI

The [xahaud integration workflow](../../../.github/workflows/xahaud-integration.yml)
runs these tests automatically on push/PR to main.

## Included test files

- `TipBot_test.cpp` — basic deposit/withdraw/tip tests
- `TipBotClaude_test.cpp` — extended tests (generated with Claude)

These reference `"file:tipbot/tip.c"` and `"file:tipbot/top.c"` which
are resolved via `HOOKS_C_DIR` pointing at the hook source.

## Running locally (without Docker)

Requires a working xahaud build environment (conan, ccache, cmake, gcc/clang).

```bash
# Run via xahaud-scripts (x-run-tests)
HOOKS_TEST_DIR=$(pwd) \
  HOOKS_C_DIR="tipbot=../hooks" \
  x-run-tests --ccache --reconfigure-build -- \
  "ripple.app.TipBot,ripple.app.TipBotClaude"
```

### Requirements

- xahaud [`external-env-tests`](https://github.com/Xahau/xahaud/tree/external-env-tests) branch
- [xahaud-scripts](https://github.com/sublimator/xahaud-scripts) (`x-run-tests`)
- hookz on PATH (`uv tool install hookz`)
- conan, ccache, cmake, ninja

## Env var reference

| Variable | Purpose |
|----------|---------|
| `HOOKS_TEST_DIR` | Directory containing your `*_test.cpp` files |
| `HOOKS_C_DIR` | `domain=path` mapping for `file:domain/name.c` refs |
| `HOOKS_COVERAGE` | Enable coverage instrumentation |
| `HOOKS_TEST_ONLY` | Exclude xahaud's built-in tests |
| `HOOKS_FORCE_RECOMPILE` | Bypass hookz build caching |
| `HOOKS_COVERAGE_DIR` | Where to write coverage `.dat` files |
| `TESTENV_LOGGING` | Per-partition log levels (e.g. `HooksTrace=trace`) |

See [docs/external-env-tests.md](../../docs/external-env-tests.md) for the full picture.
