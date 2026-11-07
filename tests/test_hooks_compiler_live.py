"""Opt-in check of the reference compiler itself: hooks-compiler through npx.

Ordinary local runs skip this, because it needs Node and the first run
downloads the toolchain. CI enables it. The pinned hashes are the point:
hooks-compiler is deterministic, so a different hash at the same version means
the toolchain changed underneath the pin, and a version bump has to update
them on purpose.
"""

from __future__ import annotations

import os

import pytest

from hookz.config import load_config
from hookz.hooks_compiler import SPEC, compile_source, include_dirs
from hookz.wasm.guard import validate_guards

pytestmark = pytest.mark.skipif(
    os.environ.get("HOOKZ_LIVE_HOOKS_COMPILER") != "1",
    reason="set HOOKZ_LIVE_HOOKS_COMPILER=1 to run hooks-compiler through npx",
)

BARE = """\
#include <stdint.h>
extern int32_t _g(uint32_t, uint32_t);
extern int64_t accept(uint32_t, uint32_t, int64_t);
int64_t hook(uint32_t reserved) {
    _g(1, 1);
    return accept(0, 0, 0);
}
"""

# Reaches the configured hook headers (-I): the vendored xahaud-lite tree and
# the pinned release checkout CI clones both build these bytes.
WITH_HEADERS = """\
#include "hookapi.h"
int64_t hook(uint32_t reserved) {
    TRACESTR("hookz reference compiler check");
    for (int i = 0; GUARD(3), i < 3; ++i)
        trace_num(SBUF("i"), i);
    accept(0, 0, 0);
    return 0;
}
"""

PINNED = {
    "bare": (BARE, "512eb2968d91270755c9d777850579180409b54d6baf29c089c8ebbae7780bb7"),
    "with_headers": (
        WITH_HEADERS,
        "386d0da48710630b226c9c1eb1e5a2c2893d23759f6a7bccf346cfb53020c937",
    ),
}


@pytest.mark.parametrize("name", sorted(PINNED))
def test_the_pinned_compiler_builds_the_pinned_bytes(name):
    source, sha256 = PINNED[name]
    result = compile_source(
        source, filename=f"{name}.c", include_dirs=include_dirs(load_config())
    )

    assert result.compiler == SPEC
    assert validate_guards(result.wasm).deployable
    assert result.wasm_sha256 == sha256, (
        f"{SPEC} built {result.wasm_sha256}; if the version was bumped on "
        "purpose, update PINNED"
    )
