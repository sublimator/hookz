"""hookz — WASM hook testing framework.

Execute, instrument, and assert on Xahau hooks from Python.
"""

import logging
import os

from hookz.runtime import HookRuntime, Hook
from hookz.coverage.rewriter import instrument_wasm
from hookz.coverage.tracker import CoverageTracker

__all__ = ["HookRuntime", "Hook", "instrument_wasm", "CoverageTracker"]

# Enable hook trace output: HOOKZ_TRACE=1 or pytest --log-cli-level=INFO
if os.environ.get("HOOKZ_TRACE"):
    _trace_log = logging.getLogger("hookz.trace")
    _trace_log.setLevel(logging.INFO)
    if not _trace_log.handlers:
        _h = logging.StreamHandler()
        _h.setFormatter(logging.Formatter("  [hook] %(message)s"))
        _trace_log.addHandler(_h)
