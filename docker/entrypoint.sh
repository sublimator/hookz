#!/bin/bash
set -euo pipefail

echo "=== hookz xahaud test runner ==="

TEST_SUITE="${1:-ripple.app.SetHook}"
if [ "$#" -gt 0 ]; then
  shift
fi

echo "  Test suite: ${TEST_SUITE}"
echo "  CCACHE_DIR: ${CCACHE_DIR:-<not set>}"
[ -n "${HOOKS_TEST_DIR:-}" ]  && echo "  HOOKS_TEST_DIR: $HOOKS_TEST_DIR"
[ -n "${HOOKS_C_DIR:-}" ]     && echo "  HOOKS_C_DIR: $HOOKS_C_DIR"
[ -n "${HOOKS_COVERAGE:-}" ]  && echo "  HOOKS_COVERAGE: $HOOKS_COVERAGE"
[ -n "${HOOKZ_BUILDBOX:-}" ]  && echo "  HOOKZ_BUILDBOX: $HOOKZ_BUILDBOX"

# ---------------------------------------------------------------------------
# Optional runtime hookz refresh (xahaud binary stays frozen).
#
#   HOOKZ_REF / HOOKZ_SPEC unset  → use the hookz baked into the image
#   HOOKZ_REF=main|sha            → uv tool install git+${HOOKZ_REPO}@REF
#   HOOKZ_SPEC=...                → full PEP 508 / path (wins over HOOKZ_REF)
#                                   e.g. HOOKZ_SPEC='hookz @ /hookz-src'
#                                        HOOKZ_SPEC='hookz @ git+https://...@branch'
#   HOOKZ_REPO                    → base URL for HOOKZ_REF (default public hookz)
#
# Needs network for git installs. Path installs (CI) need the source mounted.
# ---------------------------------------------------------------------------
HOOKZ_REPO="${HOOKZ_REPO:-https://github.com/sublimator/hookz.git}"

_normalize_git_repo() {
  # Strip trailing slash first, then optional .git → avoid host.git.git
  local r="${1%/}"
  r="${r%.git}"
  printf '%s' "$r"
}

_refresh_hookz() {
  if [ -n "${HOOKZ_SPEC:-}" ]; then
    echo "  HOOKZ_SPEC: ${HOOKZ_SPEC}"
    echo "  Refreshing hookz from HOOKZ_SPEC..."
    uv tool install --force "${HOOKZ_SPEC}"
  elif [ -n "${HOOKZ_REF:-}" ]; then
    local repo
    repo="$(_normalize_git_repo "${HOOKZ_REPO}")"
    echo "  HOOKZ_REF: ${HOOKZ_REF}"
    echo "  HOOKZ_REPO: ${repo}"
    echo "  Refreshing hookz @ ${HOOKZ_REF}..."
    uv tool install --force "hookz @ git+${repo}.git@${HOOKZ_REF}"
  else
    echo "  hookz: baked (HOOKZ_REF/HOOKZ_SPEC unset)"
    return 0
  fi

  # Drop bytecode cache so a refreshed tip cannot serve stale builds keyed
  # under a generic version string (local long-lived containers).
  rm -rf "${HOME}/.cache/hookz-builds" 2>/dev/null || true

  echo -n "  hookz: "
  hookz --version
  command -v hookz
  hookz build-test-hooks --help >/dev/null
  echo "  hookz build-test-hooks: ok"
}

_refresh_hookz

if [ ! -f "./build/rippled" ]; then
    # Dev image: no pre-built binary, export conan recipes first
    echo "  First run — exporting conan recipes..."
    conan export external/snappy --version 1.1.10 --user xahaud --channel stable 2>/dev/null || true
    conan export external/soci --version 4.0.3 --user xahaud --channel stable 2>/dev/null || true
    conan export external/wasmedge --version 0.11.2 --user xahaud --channel stable 2>/dev/null || true
fi

# x-run-tests: conan + cmake (HOOKS_* / HOOKZ_BUILDBOX) + build + run.
exec x-run-tests --ccache --reconfigure-build -- "$TEST_SUITE" "$@"
