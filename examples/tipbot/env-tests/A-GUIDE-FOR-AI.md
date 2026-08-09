# A guide for AI: how to write Env tests

You are here because a hook needs integration tests. This file is the
workflow; every command in it was run, and the worked example beside it —
[`TopGuide_test.cpp`](TopGuide_test.cpp) — was written by following this guide
and passes against real xahaud.

## First, the rule that ranks all the evidence

hookz has two test modes, and they are not equals:

- **The Python harness** (`hookz test`, the `tests/` directory here) executes
  the hook's wasm in-process against a *model* of the host, in milliseconds,
  with line-level coverage. It is the development loop: write a test, watch
  coverage, fix the hook, repeat.
- **Env tests** (this directory) hand your C++ test file to xahaud itself:
  real transactions applied to a real ledger, the real amendment set, the
  real guard checker, real fee and reserve accounting, real metadata.

The model is right most of the time and wrong the way models are wrong —
quietly, at edges it did not port. So: **develop against the Python harness;
sign off on Env tests only.** A claim about hook behaviour that matters —
"this rollback fires", "this state is written", "this emit applies" — is not
final until an Env test shows it. Where the two disagree, the Env test is the
answer and the model has a bug worth reporting.

## The loop

### 1. Read the hook's surface

```bash
hookz surface hooks/top.c            # ledger interactions, constants resolved
hookz surface hooks/top.c --all      # plus arithmetic, tracing and exits
hookz surface hooks/top.c --source   # either, with the construct each sits in
```

This is what the hook *does to the ledger*, read out of its compiled binary —
the C source hides constants behind macros; the binary has the numbers. The
default view is the ledger interactions; `--all` adds the arithmetic
(`float_compare` and friends), the traces, and every `accept`/`rollback`
exit, which is the view you want when hunting thresholds and rejection
cases. Each call's family tells you what a test must arrange to reach it: an
originating transaction, installed hook state, slotted ledger objects, an
emit reservation. The surface is your test plan in raw form: every
`rollback` is a rejection case, every `state_set` is something to read back,
every `emit` is a transaction to find applied (or not) after a close.

### 2. Generate the context document

```bash
hookz env-test-context hooks/top.c -o ctx.md          # the full document
hookz env-test-context hooks/top.c --no-impl -o ctx.md  # ~3x smaller
```

One document with everything: the surface, each call site with its line, what
each host function does *inside xahaud* (quoted from the checkout), the
`TestEnv` harness the external-env-tests branch adds, and a compilable test
skeleton. If you read one thing before writing, read this. `--no-impl` drops
the quoted implementations when the document has to share a context window
with other material.

### 3. Write the test file — the names are load-bearing

Three names must line up, and getting any wrong fails silently or confusingly:

| name | rule | what goes wrong otherwise |
|---|---|---|
| `TopGuide_test.cpp` | must end `_test.cpp` | CMake globs `*_test.cpp`; anything else is skipped with **no warning** |
| `#include "TopGuide_test_hooks.h"` | header is named from the file stem | the generated header will not match your include |
| `BEAST_DEFINE_TESTSUITE(TopGuide, app, ripple)` | suite name is the run filter | `ripple.app.TopGuide` finds nothing if they differ |

The map symbol is also derived from the stem: `TopGuide_test.cpp` →
`topguide_test_wasm`, keyed by `"file:<domain>/<file>.c"` where `<domain>` is
whatever you bind in `HOOKS_C_DIR`. Copy the skeleton from the context
document; it has all of this wired.

Things [`TopGuide_test.cpp`](TopGuide_test.cpp) had to know that the skeleton
cannot tell you — the kind of facts you extract from the hook source and the
surface listing:

- A hook `rollback` surfaces to the submitter as `ter(tecHOOK_REJECTED)`.
- Hook state keys shorter than 32 bytes are **right-aligned** by the state
  API. Build the key the way the hook does, then place it at the *end* of the
  32-byte buffer (`apiStateKey` in the tests here), or `env.le()` will hand
  you nothing while the state sits one offset away.
- Read the hook's own thresholds out of `surface --all` — `top.c`'s
  first-deposit floor is `292  float_compare(?, 6107881094714392576, 2)`.
  That second argument is a raw XFL; the source's `/* 10.0 */` comment (and
  the `float_divide` by one million XAH-drops just above it) is what tells
  you the floor is 10 XAH. The binary gives you the line and the exact
  constant; the source gives you its meaning — read both.

### 4. Run it

No local xahaud toolchain is needed — the published image has xahaud
pre-built with the branch applied and a primed ccache, so only your test
files compile:

```bash
cd examples/tipbot        # every path below assumes this directory

# No public :latest — pin a dated tag. This repo pins its own in
# .github/workflows/xahaud-integration.yml (DEFAULT_IMAGE).
IMAGE=gcr.io/hookz-public/hookz-xahaud:2026-07-30-hookz-cc80be0c

docker run --rm --platform linux/amd64 \
  -v ./env-tests:/tests \
  -v ./hooks:/hooks/tipbot \
  -e HOOKS_TEST_DIR=/tests \
  -e HOOKS_C_DIR="tipbot=/hooks/tipbot" \
  "$IMAGE" \
  "ripple.app.TopGuide"
```

What you should see, in order: cmake reconfigure, `Compiling hooks for
TopGuide_test` (that is `hookz build-test-hooks` turning your `file:` refs
into a header), your one `.cpp` compiling, a link, then the suite:

```text
ripple.app.TopGuide guide: a remit carrying value but no param is rejected
ripple.app.TopGuide guide: a first deposit writes user-info and balance state
1.2s, 1 suite, 2 cases, 54 tests total, 0 failures
```

(That transcript is from the `2026-07-28-ddd3c28d8` tag on an arm64 host;
the duration is wall-clock and varies — the counts are what to diff.)

While iterating:

- `-e TESTENV_LOGGING="HooksTrace=trace"` — the hook's own `trace()` output
  on its own partition, without `View` noise drowning it.
- `env.setPrefix("phase")` in the test — tags every subsequent log line, so a
  failure names the phase that produced it.
- Log output shows `Account(alice)` instead of r-addresses — `TestEnv`
  rewrites them, which is why `env.account("alice")` beats a raw `Account`.

### 5. Sign off

Green Env tests are the sign-off artifact. Coverage, if you want it
(`HOOKS_COVERAGE=ON`), is the *test's* job to write out —
`coverageReset`/`coverageLabel`/`coverageDump` in `run()`, as the skeleton
shows; nothing in xahaud writes a file for you, and without those calls the
hits are silently dropped at exit.

## Running on Apple Silicon (or any arm64 host)

The image is amd64. It runs under emulation: expect the first test-file
compile to take minutes instead of ~10 seconds — and know these two failure
modes, both hit while writing this guide:

1. **`HOOKZ_SPEC` refresh segfaults under qemu.** The entrypoint's
   refresh-hookz-from-source mechanism (`HOOKZ_SPEC=` / `HOOKZ_REF=`, used by
   CI, where runners are amd64 and it works) runs `uv tool install`, and uv
   segfaults under qemu. Omit both variables and the baked hookz is used —
   correct unless the change you are testing is hookz itself.
2. **If you *must* run modified hookz code on arm64**, bypass the installer:
   mount the checkout and shadow the baked launcher with a shim, letting the
   baked venv supply the dependencies and `PYTHONPATH` supply the code:

   The committed [`hookz-shim`](hookz-shim) does exactly this — mounted over
   `/root/.local/bin/hookz`, because that path wins PATH and `/usr/local/bin`
   does not:

   ```bash
   cd examples/tipbot        # same directory as the step-4 run
   docker run --rm --platform linux/amd64 \
     -v ./env-tests:/tests \
     -v ./hooks:/hooks/tipbot \
     -v "$PWD/../..:/hookz-src:ro" \
     -v "$PWD/env-tests/hookz-shim:/root/.local/bin/hookz:ro" \
     -e HOOKS_TEST_DIR=/tests \
     -e HOOKS_C_DIR="tipbot=/hooks/tipbot" \
     -e HOOKS_FORCE_RECOMPILE=1 \
     "$IMAGE" "ripple.app.TopGuide"
   ```

   **Verify the override took, and read the path, not the number.**
   `hookz --version` prints where the code came from —
   `hookz 0.1.0… (from /hookz-src/src/hookz)` means the override is live;
   `(from /root/.local/share/uv/tools/…)` means it fell through to the
   baked install. A version line with **no** path at all is old hookz from
   before the path was added — which in this image also means the baked
   install, because your mounted checkout is newer. The number alone can
   never tell you: a mounted tree without git metadata reports the same
   bare `0.1.0` as the baked one, which is how a wrong mount path once
   "verified" successfully against the wrong code.

   This is a workaround, not an interface: it names two image internals (the
   uv tools venv path, and PATH order). The durable fix would be a CMake-level
   `HOOKZ_COMMAND` override in the external-env-tests branch — today the
   CMake invokes bare `hookz` from PATH, which is why shadowing the launcher
   is what works.

## The worked example

[`TopGuide_test.cpp`](TopGuide_test.cpp) was written by following the loop
above against `hooks/top.c`, from the context document's skeleton, not copied
from the larger suites here. Two cases:

- a Remit carrying value but no parameter is rejected (`tecHOOK_REJECTED` —
  the hook demands exactly one param);
- a first deposit of exactly the floor writes the user-info and balance
  state entries, which the test reads back off the closed ledger with
  `env.le(keylet::hookState(...))` and checks byte-by-byte.

The larger suites beside it (`TipBot_test.cpp`, `TipBotClaude_test.cpp`) show
the same patterns at scale — oracle voting rounds, governance, withdrawals.

## See also

- [`README.md`](README.md) — the runbook for this directory, including
  running against a local (non-Docker) xahaud build.
- [`docs/external-env-tests.md`](../../../docs/external-env-tests.md) — what
  the xahaud branch changes, coverage wiring, CMake variables.
- `hookz env-test-context --help` — the options, including `--full-patch`.
