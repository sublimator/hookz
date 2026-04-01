#!/bin/bash
set -e

echo "=== hookz xahaud test runner ==="

TEST_SUITE="${1:-ripple.app.SetHook}"
shift || true

echo "  Test suite: ${TEST_SUITE}"
echo "  CCACHE_DIR: ${CCACHE_DIR:-<not set>}"
[ -n "$HOOKS_TEST_DIR" ]  && echo "  HOOKS_TEST_DIR: $HOOKS_TEST_DIR"
[ -n "$HOOKS_C_DIR" ]     && echo "  HOOKS_C_DIR: $HOOKS_C_DIR"
[ -n "$HOOKS_COVERAGE" ]  && echo "  HOOKS_COVERAGE: $HOOKS_COVERAGE"

if [ ! -f "./build/rippled" ]; then
    # Dev image: no pre-built binary, export conan recipes first
    echo "  First run — exporting conan recipes..."
    conan export external/snappy --version 1.1.10 --user xahaud --channel stable 2>/dev/null || true
    conan export external/soci --version 4.0.3 --user xahaud --channel stable 2>/dev/null || true
    conan export external/wasmedge --version 0.11.2 --user xahaud --channel stable 2>/dev/null || true
fi

# x-run-tests handles everything: conan install, cmake configure (with
# ccache wrapper toolchain), build, and test execution. HOOKS_* env vars
# are read by cmake during configure.
exec x-run-tests --ccache --reconfigure-build -- "$TEST_SUITE" "$@"
