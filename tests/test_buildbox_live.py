"""Opt-in sanity test against the canonical service.

Ordinary local runs skip this. CI enables it explicitly so a service outage is
visible, with the CI-aware retry policy in ``hookz.buildbox`` absorbing brief
transient failures.
"""

from __future__ import annotations

import os

import pytest

from hookz.buildbox import compile_source
from hookz.wasm.guard import validate_guards


SOURCE = """\
#include <stdint.h>
extern int32_t _g(uint32_t, uint32_t);
extern int64_t accept(uint32_t, uint32_t, int64_t);
int64_t hook(uint32_t reserved) {
    _g(1, 1);
    return accept(0, 0, 0);
}
"""


@pytest.mark.skipif(
    os.environ.get("HOOKZ_LIVE_BUILDBOX") != "1",
    reason="set HOOKZ_LIVE_BUILDBOX=1 to call the canonical service",
)
def test_canonical_buildbox_returns_deployable_wasm():
    result = compile_source(SOURCE, filename="hookz-sanity.c")

    assert result.endpoint.startswith("https://")
    assert result.wasm.startswith(b"\x00asm\x01\x00\x00\x00")
    assert validate_guards(result.wasm).deployable
