"""hookz — WASM hook testing framework.

Execute, instrument, and assert on Xahau hooks from Python.
"""

import logging
import os

from hookz.runtime import HookRuntime, Hook, ParamMap
from hookz.coverage.rewriter import instrument_wasm
from hookz.coverage.tracker import CoverageTracker
# The canonical "ctx 0 means applied, not successful" documentation lives on
# these two constants — re-exported so tests reach them without knowing the
# handler layout.
from hookz.handlers.otxn import CALLBACK_APPLIED, CALLBACK_NOT_APPLIED
from hookz.emission import emitted_txn_id

__all__ = [
    "CALLBACK_APPLIED",
    "CALLBACK_NOT_APPLIED",
    "CoverageTracker",
    "Hook",
    "HookRuntime",
    "ParamMap",
    "emitted_txn_id",
    "instrument_wasm",
]

# Enable hook trace output: HOOKZ_TRACE=1 or pytest --log-cli-level=INFO
if os.environ.get("HOOKZ_TRACE"):
    _trace_log = logging.getLogger("hookz.trace")
    _trace_log.setLevel(logging.INFO)
    if not _trace_log.handlers:
        _h = logging.StreamHandler()
        _h.setFormatter(logging.Formatter("  [hook] %(message)s"))
        _trace_log.addHandler(_h)
