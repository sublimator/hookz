"""Guard checker — validates WASM hooks have proper _g() guard calls.

Port of xahaud Guard.h validateGuards() + check_guard().
Uses wasm-tob for section parsing and instruction decoding.
"""

from .checker import validate_guards, GuardError, GuardResult

__all__ = ["validate_guards", "GuardError", "GuardResult"]
