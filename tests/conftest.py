"""Framework test configuration — skip tests when external paths are missing."""

import pytest

from location_consts import WASI_SDK, HOOK_DIR, TIPBOT_DIR, XAHAUD

# e2e tests have their own hookz.toml and must be run from tests/e2e/
collect_ignore = ["e2e"]

needs_wasi_sdk = pytest.mark.skipif(WASI_SDK is None, reason="wasi-sdk not found")
needs_hook_dir = pytest.mark.skipif(HOOK_DIR is None, reason="xahaud hook headers not found")
needs_tipbot = pytest.mark.skipif(TIPBOT_DIR is None, reason="tipbot-hooks not found")
needs_xahaud = pytest.mark.skipif(XAHAUD is None, reason="xahaud source not found")
needs_compile = pytest.mark.skipif(
    WASI_SDK is None or HOOK_DIR is None,
    reason="wasi-sdk or hook headers not found",
)
