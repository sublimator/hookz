"""Extract hook API definitions and constants from a xahaud source tree.

Given a path to a xahaud repo, this module can:
1. Parse #define constants from hook/ headers (sfcodes.h, tts.h, error.h, hookapi.h)
2. Find DEFINE_HOOK_FUNCTION wrappers in applyHook.cpp
3. Find HookAPI::method implementations in HookAPI.cpp
4. Generate Python constant modules from the C headers

Usage:
    from hookz.xahaud import XahaudRepo

    repo = XahaudRepo("~/projects/xahaud-worktrees/xahaud-wasm-coverage")

    # Get all sfcodes as Python dict
    sfcodes = repo.parse_defines("hook/sfcodes.h")
    # {'sfTransactionType': 65538, 'sfAccount': 524289, ...}

    # Find a hook function implementation
    code = repo.find_hook_function("float_sto")
    # Returns the full DEFINE_HOOK_FUNCTION block from applyHook.cpp

    # Find the HookAPI method
    code = repo.find_api_method("float_sto")
    # Returns HookAPI::float_sto from HookAPI.cpp

    # Generate Python constants file
    repo.generate_hookapi_py("hookapi_generated.py")
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser

CPP_LANGUAGE = Language(tscpp.language())


def _node_text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode(errors="replace")


@dataclass
class HookFunctionDef:
    """A DEFINE_HOOK_FUNCTION extracted from applyHook.cpp."""
    name: str
    return_type: str
    params: list[tuple[str, str]]  # [(type, name), ...]
    body: str
    start_line: int
    end_line: int


@dataclass
class ApiMethodDef:
    """A HookAPI::method from HookAPI.cpp."""
    name: str
    return_type: str
    params: str
    body: str
    start_line: int
    end_line: int


class XahaudRepo:
    """Interface to a xahaud source tree for extracting hook API definitions."""

    def __init__(self, repo_path: str | Path):
        self.root = Path(repo_path).expanduser().resolve()
        if not self.root.exists():
            raise FileNotFoundError(f"Repo not found: {self.root}")
        self._parser = Parser(CPP_LANGUAGE)

    def _read(self, rel_path: str) -> bytes:
        p = self.root / rel_path
        if not p.exists():
            raise FileNotFoundError(f"Not found: {p}")
        return p.read_bytes()

    # ---- Parse #define constants ----

    def parse_defines(self, rel_path: str) -> dict[str, int]:
        """Parse #define NAME (expr) from a C header into {name: value}."""
        source = self._read(rel_path).decode(errors="replace")
        result: dict[str, int] = {}

        for line in source.splitlines():
            line = line.strip()
            if not line.startswith("#define "):
                continue
            # Skip include guards and macros with args
            parts = line[8:].split(None, 1)
            if len(parts) != 2:
                continue
            name = parts[0]
            if "(" in name:  # macro with args
                continue
            expr = parts[1].split("//")[0].strip()  # strip comments
            # Strip C integer suffixes (U, L, LL, ULL, etc.)
            expr = re.sub(r'\b(\d+)[UuLl]+\b', r'\1', expr)
            try:
                val = eval(expr, {"__builtins__": {}}, {})
                if isinstance(val, (int, float)):
                    result[name] = int(val)
            except Exception:
                continue

        return result

    def parse_all_hook_constants(self) -> dict[str, dict[str, int]]:
        """Parse all hook header constants."""
        headers = {
            "sfcodes": "hook/sfcodes.h",
            "tts": "hook/tts.h",
            "error": "hook/error.h",
            "hookapi": "hook/hookapi.h",
        }
        result = {}
        for key, path in headers.items():
            try:
                result[key] = self.parse_defines(path)
            except FileNotFoundError:
                pass
        return result

    def parse_extern_signatures(self) -> list[tuple[str, str, list[str]]]:
        """Parse function signatures from hook/extern.h.

        Returns [(return_type, name, [param_types]), ...]
        """
        source = self._read("hook/extern.h")
        tree = self._parser.parse(source)

        results: list[tuple[str, str, list[str]]] = []

        # Find all function declarations (extern declarations)
        for node in tree.root_node.children:
            if node.type == "declaration":
                text = _node_text(node, source)
                # Parse: extern return_type name(params);
                m = re.match(
                    r"extern\s+(\w+)\s*\n?\s*(\w+)\s*\(([^)]*)\)\s*;",
                    text, re.DOTALL,
                )
                if m:
                    ret_type = m.group(1)
                    name = m.group(2)
                    params_str = m.group(3)
                    param_types = [
                        p.strip().rsplit(None, 1)[0]
                        for p in params_str.split(",")
                        if p.strip()
                    ]
                    results.append((ret_type, name, param_types))

        return results

    # ---- Find DEFINE_HOOK_FUNCTION blocks ----

    def list_hook_functions(self) -> list[str]:
        """List all hook API function names from DEFINE_HOOK_FUNCTION in applyHook.cpp."""
        source = self._read(
            "src/xrpld/app/hook/detail/applyHook.cpp"
        ).decode(errors="replace")

        pattern = re.compile(
            r"DEFINE_HOOK_FUNCTION\s*\(\s*\w+\s*,\s*(\w+)\s*,",
        )
        return sorted(set(m.group(1) for m in pattern.finditer(source)))

    def find_hook_function(self, name: str) -> str | None:
        """Find a DEFINE_HOOK_FUNCTION(return_type, name, ...) block in applyHook.cpp."""
        source = self._read(
            "src/xrpld/app/hook/detail/applyHook.cpp"
        ).decode(errors="replace")

        # DEFINE_HOOK_FUNCTION blocks can span multiple lines
        # Pattern: DEFINE_HOOK_FUNCTION(\n    return_type,\n    name, ...)\n{...}
        # Find by searching for the name after DEFINE_HOOK_FUNCTION
        pattern = re.compile(
            r"DEFINE_HOOK_FUNCTION\s*\([^)]*\b" + re.escape(name) + r"\b[^)]*\)\s*\{",
            re.DOTALL,
        )
        match = pattern.search(source)
        if not match:
            return None

        # Find the matching closing brace
        start = match.start()
        brace_start = match.end() - 1  # the opening {
        depth = 1
        pos = brace_start + 1
        while pos < len(source) and depth > 0:
            if source[pos] == "{":
                depth += 1
            elif source[pos] == "}":
                depth -= 1
            pos += 1

        return source[start:pos]

    # ---- Find HookAPI::method implementations ----

    def find_api_method(self, name: str) -> str | None:
        """Find HookAPI::name(...) implementation in HookAPI.cpp."""
        source = self._read(
            "src/xrpld/app/hook/detail/HookAPI.cpp"
        ).decode(errors="replace")

        # Pattern: return_type\nHookAPI::name(params) const\n{...}
        pattern = re.compile(
            r"(?:Expected<[^>]+>|[\w:]+)\s*\n\s*HookAPI::" + re.escape(name) + r"\s*\([^{]*\{",
            re.DOTALL,
        )
        match = pattern.search(source)
        if not match:
            # Try simpler pattern for single-line signatures
            pattern = re.compile(
                r"\w[\w:<>, ]*\s+HookAPI::" + re.escape(name) + r"\s*\([^{]*\{",
                re.DOTALL,
            )
            match = pattern.search(source)
            if not match:
                return None

        start = match.start()
        brace_start = match.end() - 1
        depth = 1
        pos = brace_start + 1
        while pos < len(source) and depth > 0:
            if source[pos] == "{":
                depth += 1
            elif source[pos] == "}":
                depth -= 1
            pos += 1

        return source[start:pos]

    # ---- Find both wrapper + implementation for a hook function ----

    def find_macro_definition(self, name: str) -> str | None:
        """Find a #define macro definition from the hook API headers.

        Searches hookapi.h and macro.h for multi-line macro definitions.
        E.g. find_macro_definition("DEFINE_HOOK_FUNCTION") or
             find_macro_definition("HOOK_SETUP")
        """
        for header in ("hook/hookapi.h", "hook/macro.h",
                        "src/xrpld/app/hook/applyHook.h",
                        "include/xrpl/hook/Macro.h"):
            try:
                source = self._read(header).decode(errors="replace")
            except FileNotFoundError:
                continue

            # Find #define NAME with possible line continuations
            pattern = re.compile(
                r"^#define\s+" + re.escape(name) + r"\b.*$",
                re.MULTILINE,
            )
            match = pattern.search(source)
            if not match:
                continue

            # Collect continuation lines (ending with \)
            lines = []
            pos = match.start()
            for line in source[pos:].splitlines():
                lines.append(line)
                if not line.rstrip().endswith("\\"):
                    break

            return "\n".join(lines)

        return None

    # ---- Find test functions in SetHook_test.cpp ----

    _TEST_FILE = "src/test/app/SetHook_test.cpp"

    def find_test_function(self, name: str) -> str | None:
        """Find test_{name} method in SetHook_test.cpp using tree-sitter."""
        try:
            source = self._read(self._TEST_FILE)
        except FileNotFoundError:
            return None

        target = f"test_{name}"
        tree = self._parser.parse(source)

        def _find_method(node) -> bytes | None:
            # Look for function_definition nodes whose declarator name matches
            if node.type == "function_definition":
                declarator = node.child_by_field_name("declarator")
                if declarator and declarator.type == "function_declarator":
                    name_node = declarator.child_by_field_name("declarator")
                    if name_node:
                        fn_name = _node_text(name_node, source)
                        # Could be bare "test_X" or qualified "SetHook0_test::test_X"
                        if fn_name == target or fn_name.endswith("::" + target):
                            return source[node.start_byte:node.end_byte]

            for child in node.children:
                result = _find_method(child)
                if result:
                    return result
            return None

        found = _find_method(tree.root_node)
        return found.decode(errors="replace") if found else None

    def find_hook_function_full(self, name: str) -> dict[str, str | None]:
        """Find the WASM wrapper, API implementation, and relevant macros.

        Returns {
            "wrapper": DEFINE_HOOK_FUNCTION block from applyHook.cpp
                       (shows how WASM memory args map to C++ types),
            "implementation": HookAPI::method from HookAPI.cpp
                              (the actual logic),
            "macro": The DEFINE_HOOK_FUNCTION macro definition itself
                     (shows the host function registration pattern),
        }
        """
        return {
            "wrapper": self.find_hook_function(name),
            "implementation": self.find_api_method(name),
            "macro": self.find_macro_definition("DEFINE_HOOK_FUNCTION"),
        }

    # ---- Generate Python constants ----

    _HEADER_MAP = {
        "error": "hook/error.h",
        "hookapi": "hook/hookapi.h",
        "sfcodes": "hook/sfcodes.h",
        "tts": "hook/tts.h",
    }

    def generate_hookapi_py(self, output_path: str | Path | None = None) -> str:
        """Generate a Python module with all hook API constants.

        Each constant includes hex value and source header as comments.
        If output_path is given, writes to file. Always returns the content.
        """
        all_constants = self.parse_all_hook_constants()

        lines = [
            '"""Auto-generated hook API constants from xahaud source.',
            f'Source: {self.root}',
            '"""',
            '',
        ]

        for section, constants in sorted(all_constants.items()):
            header = self._HEADER_MAP.get(section, section)
            lines.append(f"# ---- {section} ({header}) ----")
            for name, value in sorted(constants.items()):
                if isinstance(value, int) and value >= 0:
                    lines.append(f"{name} = {value}  # 0x{value:X}")
                else:
                    lines.append(f"{name} = {value}  # -0x{abs(value):X}")
            lines.append("")

        content = "\n".join(lines)
        if output_path:
            Path(output_path).write_text(content)
        return content
