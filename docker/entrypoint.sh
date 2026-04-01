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
    # Dev image: no pre-built binary, do full build from scratch
    echo "  First run — exporting conan recipes..."
    conan export external/snappy --version 1.1.10 --user xahaud --channel stable 2>/dev/null || true
    conan export external/soci --version 4.0.3 --user xahaud --channel stable 2>/dev/null || true
    conan export external/wasmedge --version 0.11.2 --user xahaud --channel stable 2>/dev/null || true
    echo "  Full build (x-run-tests --ccache --reconfigure-build)..."
    x-run-tests --times=0 --ccache --reconfigure-build
else
    # Baked image: binary exists. Only reconfigure if HOOKS_* env vars are set
    # (to add external test files). Pass -D flags explicitly so cmake cache
    # vars are always updated, even if they were set in a previous run.
    CMAKE_ARGS=()
    [ -n "$HOOKS_TEST_DIR" ]         && CMAKE_ARGS+=("-DHOOKS_TEST_DIR=$HOOKS_TEST_DIR")
    [ -n "$HOOKS_C_DIR" ]            && CMAKE_ARGS+=("-DHOOKS_C_DIR=$HOOKS_C_DIR")
    [ -n "$HOOKS_COVERAGE" ]         && CMAKE_ARGS+=("-DHOOKS_COVERAGE=$HOOKS_COVERAGE")
    [ -n "$HOOKS_TEST_ONLY" ]        && CMAKE_ARGS+=("-DHOOKS_TEST_ONLY=$HOOKS_TEST_ONLY")
    [ -n "$HOOKS_FORCE_RECOMPILE" ]  && CMAKE_ARGS+=("-DHOOKS_FORCE_RECOMPILE=$HOOKS_FORCE_RECOMPILE")

    if [ ${#CMAKE_ARGS[@]} -gt 0 ]; then
        # Pass -D flags explicitly to cmake to force cache var updates
        # (CMakeLists.txt only reads env when cache vars are unset)
        echo "  Reconfiguring with: ${CMAKE_ARGS[*]}"
        (cd build && cmake "${CMAKE_ARGS[@]}" .)
        echo "  Building..."
        (cd build && cmake --build . --target rippled -j$(nproc))
        ccache -s 2>/dev/null || true
    else
        echo "  No HOOKS_* vars — skipping reconfigure."
    fi
fi

echo "  Running: ${TEST_SUITE}"
echo "==========================================="
exec ./build/rippled --unittest="${TEST_SUITE}" "$@"
