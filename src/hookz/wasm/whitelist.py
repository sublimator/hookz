"""Hook API whitelist — parsed from xahaud hook_api.macro.

Provides the set of allowed import functions for a given set of amendments.
Used by the guard checker to validate imports.

Parses the macro file from the xahaud checkout (path from hookz.toml).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class HookApiFunction:
    """A single hook API function definition."""
    name: str
    return_type: str
    param_types: tuple[str, ...]
    amendment: str  # "" = always available


def parse_hook_api_macro(path: Path | str) -> list[HookApiFunction]:
    """Parse hook_api.macro and return all function definitions."""
    text = Path(path).read_text()
    pattern = re.compile(
        r'HOOK_API_DEFINITION\s*\(\s*'
        r'(\w+)\s*,\s*'           # return type
        r'(\w+)\s*,\s*'           # function name
        r'\(([^)]*)\)\s*,\s*'     # param types
        r'(\w+(?:\{\})?)\s*\)',    # amendment
        re.MULTILINE,
    )
    results = []
    for m in pattern.finditer(text):
        params = tuple(p.strip() for p in m.group(3).split(",") if p.strip())
        amendment = "" if m.group(4) == "uint256{}" else m.group(4)
        results.append(HookApiFunction(
            name=m.group(2), return_type=m.group(1),
            param_types=params, amendment=amendment,
        ))
    return results


def derive_amendments(functions: list[HookApiFunction]) -> set[str]:
    """Extract all unique amendment names from the function list."""
    return {f.amendment for f in functions if f.amendment}


@lru_cache(maxsize=1)
def load_from_config() -> list[HookApiFunction]:
    """Load hook API functions, preferring xahaud checkout, falling back to vendored."""
    from hookz.xahaud_files import XahaudFile, resolve
    from hookz.config import load_config
    config = load_config()
    macro_path = resolve(XahaudFile.HOOK_API_MACRO, config.xahaud_root)
    return parse_hook_api_macro(macro_path)


def get_default_amendments() -> set[str]:
    """Get all amendments derived from hook_api.macro. These are the defaults."""
    return derive_amendments(load_from_config())


def get_whitelist(amendments: set[str] | None = None) -> set[str]:
    """Get allowed import function names for given amendments.

    None = all amendments enabled (current mainnet default).
    """
    functions = load_from_config()
    if amendments is None:
        amendments = derive_amendments(functions)
    return {
        f.name for f in functions
        if not f.amendment or f.amendment in amendments
    }


def get_function_signatures() -> dict[str, HookApiFunction]:
    """Get all function signatures by name."""
    return {f.name: f for f in load_from_config()}
