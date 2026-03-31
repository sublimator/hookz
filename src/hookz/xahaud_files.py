"""Registry of xahaud source files used by hookz.

Each entry maps a logical name to its relative path within a xahaud
checkout (or xahaud-lite vendored tree). This is the single source of
truth for all xahaud file references — no string literals elsewhere.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path


class XahaudFile(str, Enum):
    """Relative paths of xahaud files used by hookz."""

    # hook/ — compile-time headers (#include "hookapi.h" etc.)
    HOOKAPI_H = "hook/hookapi.h"
    MACRO_H = "hook/macro.h"
    SFCODES_H = "hook/sfcodes.h"
    TTS_H = "hook/tts.h"
    ERROR_H = "hook/error.h"
    EXTERN_H = "hook/extern.h"

    # include/xrpl/hook/ — build infrastructure & reference
    HOOK_API_MACRO = "include/xrpl/hook/hook_api.macro"
    ENUM_H = "include/xrpl/hook/Enum.h"
    GUARD_H = "include/xrpl/hook/Guard.h"
    INCLUDE_MACRO_H = "include/xrpl/hook/Macro.h"
    MISC_H = "include/xrpl/hook/Misc.h"
    XAHAU_H = "include/xrpl/hook/xahau.h"

    # src/ — C++ implementations for hookz show
    APPLY_HOOK_CPP = "src/xrpld/app/hook/detail/applyHook.cpp"
    HOOK_API_CPP = "src/xrpld/app/hook/detail/HookAPI.cpp"
    APPLY_HOOK_H = "src/xrpld/app/hook/applyHook.h"
    SET_HOOK_TEST_CPP = "src/test/app/SetHook_test.cpp"


# Logical groups
HOOK_HEADERS = {
    XahaudFile.HOOKAPI_H,
    XahaudFile.MACRO_H,
    XahaudFile.SFCODES_H,
    XahaudFile.TTS_H,
    XahaudFile.ERROR_H,
    XahaudFile.EXTERN_H,
}

BUILD_INFRA = {
    XahaudFile.HOOK_API_MACRO,
    XahaudFile.ENUM_H,
}

SHOW_COMMAND = {
    XahaudFile.APPLY_HOOK_CPP,
    XahaudFile.HOOK_API_CPP,
    XahaudFile.APPLY_HOOK_H,
    XahaudFile.SET_HOOK_TEST_CPP,
}


def _vendored_root() -> Path:
    """Path to xahaud-lite vendored tree (ships with hookz package)."""
    return Path(__file__).resolve().parent / "xahaud_lite"


def resolve(file: XahaudFile, xahaud_root: Path | None = None) -> Path:
    """Resolve a xahaud file path, preferring xahaud_root, falling back to vendored.

    Args:
        file: Which file to resolve.
        xahaud_root: Path to a full xahaud checkout (from config). If the
            file exists there, use it. Otherwise fall back to xahaud-lite.

    Returns:
        Absolute path to the file.

    Raises:
        FileNotFoundError: If the file doesn't exist in either location.
    """
    # Try xahaud checkout first
    if xahaud_root and xahaud_root != Path():
        candidate = xahaud_root / file.value
        if candidate.exists():
            return candidate

    # Fall back to vendored
    vendored = _vendored_root() / file.value
    if vendored.exists():
        return vendored

    locations = []
    if xahaud_root and xahaud_root != Path():
        locations.append(str(xahaud_root / file.value))
    locations.append(str(_vendored_root() / file.value))

    raise FileNotFoundError(
        f"{file.name} not found. Searched:\n"
        + "\n".join(f"  - {loc}" for loc in locations)
    )


def resolve_dir(xahaud_root: Path | None = None) -> Path:
    """Resolve the xahaud root directory (for XahaudRepo etc.).

    Prefers a configured xahaud checkout, falls back to xahaud-lite.
    """
    if xahaud_root and xahaud_root != Path() and xahaud_root.exists():
        return xahaud_root
    vendored = _vendored_root()
    if vendored.exists():
        return vendored
    raise FileNotFoundError("No xahaud source available (configure xahaud in hookz.toml or use vendored xahaud-lite)")
