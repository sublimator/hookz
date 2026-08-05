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
import subprocess
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
class EnumConstant:
    """One enumerator parsed out of a C++ enum, with its provenance.

    `line` is 1-based in the header it came from, so a generated module can
    cite each constant in the repo's `xahaud:path:line` convention.
    """
    name: str
    value: int
    line: int
    enum: str


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

    # ---- Parse C++ enums (tree-sitter, not regex) ----

    def parse_enum_constants(
        self, rel_path: str, env: dict[str, int] | None = None,
        constexpr_too: bool = False,
    ) -> list[EnumConstant]:
        """Every enumerator in `rel_path`, in declaration order, values resolved.

        Handles the shapes the protocol headers actually use: explicit integer
        and hex literals, implicit increment from the previous enumerator, and
        mask expressions built from earlier enumerators (`~`, `|`, `&`, `+`,
        `-`, `<<`, parentheses, identifier references). Values from enums with
        an unsigned base type are wrapped to 32 bits, matching what the C++
        compiler stores — a `~x` mask must come out as the uint32 the chain
        compares against, not a negative Python int.

        `constexpr_too` also collects file-scope `constexpr <int type> name =
        expr;` declarations, in the same declaration order and environment —
        TxFlags.h defines the AMM flags and every transaction mask that way,
        not as enumerators. Opt-in because other headers use constexpr for
        functions and non-integer values this evaluator has no business
        guessing at.

        `env` seeds identifier resolution and accumulates every constant
        parsed — pass one dict across files when a header references another
        header's constants (TxFlags.h reads lsf* from LedgerFormats.h).
        """
        source = self._read(rel_path)
        tree = self._parser.parse(source)

        constants: list[EnumConstant] = []
        if env is None:
            env = {}

        def evaluate(node) -> int:
            kind = node.type
            if kind == "number_literal":
                text = _node_text(node, source).rstrip("uUlL")
                return int(text, 0)
            if kind == "identifier":
                name = _node_text(node, source)
                if name in env:
                    return env[name]
                raise ValueError(f"unknown identifier {name!r}")
            if kind == "unary_expression":
                op = _node_text(node.children[0], source)
                operand = evaluate(node.children[1])
                if op == "-":
                    return -operand
                if op == "~":
                    return ~operand
                if op == "+":
                    return operand
                raise ValueError(f"unsupported unary {op!r}")
            if kind == "binary_expression":
                left = evaluate(node.child_by_field_name("left"))
                right = evaluate(node.child_by_field_name("right"))
                op = _node_text(node.child_by_field_name("operator"), source)
                ops = {
                    "|": lambda a, b: a | b,
                    "&": lambda a, b: a & b,
                    "^": lambda a, b: a ^ b,
                    "<<": lambda a, b: a << b,
                    ">>": lambda a, b: a >> b,
                    "+": lambda a, b: a + b,
                    "-": lambda a, b: a - b,
                }
                if op not in ops:
                    raise ValueError(f"unsupported operator {op!r}")
                return ops[op](left, right)
            if kind == "parenthesized_expression":
                inner = [c for c in node.children if c.is_named]
                if len(inner) == 1:
                    return evaluate(inner[0])
                raise ValueError("unexpected parenthesized expression shape")
            if kind in ("cast_expression", "call_expression"):
                # e.g. `uint32_t(...)` / `(uint32_t)~x` — evaluate the payload
                for child in reversed(node.children):
                    if child.is_named and child.type != "type_descriptor":
                        return evaluate(child)
            raise ValueError(f"unsupported expression node {kind!r}")

        def constexpr_declaration(node) -> None:
            """`constexpr std::uint32_t [const] name = expr;` at file scope."""
            if not any(c.type == "type_qualifier"
                       and _node_text(c, source) == "constexpr"
                       for c in node.children):
                return
            type_node = node.child_by_field_name("type")
            declarator = node.child_by_field_name("declarator")
            if type_node is None or declarator is None:
                return
            if declarator.type != "init_declarator":
                return                      # a constexpr function, not a value
            name_node = declarator.child_by_field_name("declarator")
            value_node = declarator.child_by_field_name("value")
            if (name_node is None or name_node.type != "identifier"
                    or value_node is None):
                return
            name = _node_text(name_node, source)
            value = evaluate(value_node)
            if "uint" in _node_text(type_node, source):
                value &= 0xFFFFFFFF
            env[name] = value
            constants.append(EnumConstant(
                name=name,
                value=value,
                line=node.start_point[0] + 1,
                enum="constexpr",
            ))

        def walk(node) -> None:
            if constexpr_too and node.type == "declaration":
                constexpr_declaration(node)
                return
            if node.type == "enum_specifier":
                name_node = node.child_by_field_name("name")
                enum_name = (
                    _node_text(name_node, source) if name_node else "<anonymous>"
                )
                base_node = node.child_by_field_name("base")
                unsigned = base_node is not None and "uint" in _node_text(
                    base_node, source
                )
                body = node.child_by_field_name("body")
                if body is None:
                    return
                # A body containing parse errors (LedgerEntryType defines an
                # in-enum macro and populates itself through it) yields
                # error-recovery enumerator nodes whose names and neighbours
                # cannot be trusted. In that mode only explicitly
                # initialized, evaluable entries are kept and nothing is
                # implicit — a name that is absent fails loudly at import
                # time, a name with an invented value fails never. A cleanly
                # parsed body keeps loud failures: an unknown identifier
                # there is a real cross-header reference that needs `env`
                # seeding, not something to skip.
                broken = body.has_error
                next_value = 0
                for entry in body.named_children:
                    if entry.type != "enumerator":
                        continue
                    name_node = entry.child_by_field_name("name")
                    entry_name = _node_text(name_node, source)
                    value_node = entry.child_by_field_name("value")
                    if value_node is not None:
                        try:
                            value = evaluate(value_node)
                        except ValueError:
                            if broken:
                                continue
                            raise
                    else:
                        # An attributed enumerator — `ltNICKNAME
                        # [[deprecated(...)]] = 0x006e,` — parses as a bare
                        # identifier: tree-sitter drops the attribute AND
                        # the initializer from the node. An implicit
                        # increment would silently invent a value, so the
                        # initializer is recovered from the rest of the
                        # source line instead.
                        rest = source[name_node.end_byte:].split(b"\n", 1)[0]
                        if b"=" in rest:
                            literal = rest.rsplit(b"=", 1)[1]
                            literal = literal.split(b",")[0].strip()
                            token = literal.decode(errors="replace")
                            try:
                                value = int(token.rstrip("uUlL"), 0)
                            except ValueError:
                                if token in env:
                                    value = env[token]
                                elif broken:
                                    continue
                                else:
                                    raise ValueError(
                                        f"{rel_path}: enumerator "
                                        f"{entry_name!r} has an initializer "
                                        f"this parser cannot read: {token!r}"
                                    )
                        elif broken:
                            continue
                        else:
                            value = next_value
                    if unsigned:
                        value &= 0xFFFFFFFF
                    env[entry_name] = value
                    constants.append(EnumConstant(
                        name=entry_name,
                        value=value,
                        line=entry.start_point[0] + 1,
                        enum=enum_name,
                    ))
                    next_value = value + 1
                return
            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return constants

    def parse_all_hook_constants(self) -> dict[str, dict[str, int]]:
        """Parse all hook header constants."""
        from hookz.xahaud_files import XahaudFile
        headers = {
            "sfcodes": XahaudFile.SFCODES_H.value,
            "tts": XahaudFile.TTS_H.value,
            "error": XahaudFile.ERROR_H.value,
            "hookapi": XahaudFile.HOOKAPI_H.value,
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
        from hookz.xahaud_files import XahaudFile
        source = self._read(XahaudFile.EXTERN_H.value)
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
        from hookz.xahaud_files import XahaudFile
        source = self._read(
            XahaudFile.APPLY_HOOK_CPP.value
        ).decode(errors="replace")

        pattern = re.compile(
            r"DEFINE_HOOK_FUNCTION\s*\(\s*\w+\s*,\s*(\w+)\s*,",
        )
        return sorted(set(m.group(1) for m in pattern.finditer(source)))

    def find_hook_function(self, name: str) -> str | None:
        """Find a DEFINE_HOOK_FUNCTION(return_type, name, ...) block in applyHook.cpp."""
        from hookz.xahaud_files import XahaudFile
        source = self._read(
            XahaudFile.APPLY_HOOK_CPP.value
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
        from hookz.xahaud_files import XahaudFile
        source = self._read(
            XahaudFile.HOOK_API_CPP.value
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
        from hookz.xahaud_files import XahaudFile
        for header in (XahaudFile.HOOKAPI_H.value, XahaudFile.MACRO_H.value,
                        XahaudFile.APPLY_HOOK_H.value,
                        XahaudFile.INCLUDE_MACRO_H.value):
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

    from hookz.xahaud_files import XahaudFile
    _TEST_FILE = XahaudFile.SET_HOOK_TEST_CPP.value

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
        "error": XahaudFile.ERROR_H.value,
        "hookapi": XahaudFile.HOOKAPI_H.value,
        "sfcodes": XahaudFile.SFCODES_H.value,
        "tts": XahaudFile.TTS_H.value,
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

    # ---- Generate TER and transaction/ledger flag constants ----

    def _source_id(self) -> str:
        """`xahaud @ <commit>` when the tree is a git checkout, else the path."""
        try:
            probe = subprocess.run(
                ["git", "-C", str(self.root), "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, timeout=10,
            )
            if probe.returncode == 0:
                return f"xahaud @ {probe.stdout.strip()}"
        except Exception:                                      # noqa: BLE001
            pass
        return str(self.root)

    def _generated_header(self, title: str, headers: list[str]) -> list[str]:
        cited = ", ".join(headers)
        return [
            f'"""{title}',
            "",
            f"Auto-generated from {cited}.",
            f"Source: {self._source_id()}",
            "Regenerate: python scripts/gen-constants.py <xahaud-root>",
            "",
            "Every constant carries its origin in the repo's citation",
            "convention — `xahaud:<path>:<line>` names the exact line of the",
            "pinned xahaud tree it was read from.",
            '"""',
            "",
        ]

    TER_HEADER = "include/xrpl/protocol/TER.h"
    TX_FLAGS_HEADER = "include/xrpl/protocol/TxFlags.h"
    LEDGER_FORMATS_HEADER = "include/xrpl/protocol/LedgerFormats.h"

    #: The TER enums, in range order. Everything else in TER.h is machinery.
    TER_ENUMS = ("TELcodes", "TEMcodes", "TEFcodes", "TERcodes",
                 "TEScodes", "TECcodes")

    def generate_ter_py(self, output_path: str | Path | None = None) -> str:
        """Generate `hookz/ter.py` — transaction result codes, both directions.

        Declaration order is preserved so the module reads like the header,
        and `name()` resolves a duplicated value to its first (canonical)
        declaration, exactly as the header presents it.
        """
        constants = [
            c for c in self.parse_enum_constants(self.TER_HEADER)
            if c.enum in self.TER_ENUMS
        ]
        wanted = {name: None for name in self.TER_ENUMS}
        lines = self._generated_header(
            "Transaction result (TER) codes from xahaud.", [self.TER_HEADER]
        )
        for enum_name in wanted:
            group = [c for c in constants if c.enum == enum_name]
            if not group:
                continue
            lines.append(f"# ---- {enum_name} ----")
            for c in group:
                lines.append(
                    f"{c.name} = {c.value}"
                    f"  # xahaud:{self.TER_HEADER}:{c.line}"
                )
            lines.append("")

        lines += [
            "_PREFIXES = ('tel', 'tem', 'tef', 'ter', 'tes', 'tec')",
            "",
            "_CODES: dict[str, int] = {",
            "    _n: _v for _n, _v in list(globals().items())",
            "    if _n[:3] in _PREFIXES and isinstance(_v, int)",
            "}",
            "",
            "_NAMES: dict[int, str] = {}",
            "for _n, _v in _CODES.items():   # first declaration wins",
            "    _NAMES.setdefault(_v, _n)",
            "",
            "",
            "def code(name: str) -> int:",
            '    """Numeric TER for a symbolic name, e.g. \'tecDST_TAG_NEEDED\' -> 143."""',
            "    return _CODES[name]",
            "",
            "",
            "def name(code: int) -> str:",
            '    """Symbolic name for a numeric TER, e.g. 143 -> \'tecDST_TAG_NEEDED\'."""',
            "    return _NAMES[code]",
            "",
        ]
        content = "\n".join(lines)
        if output_path:
            Path(output_path).write_text(content)
        return content

    #: The generated surface of flags.py. LedgerFormats.h in particular
    #: contains other enums (LedgerEntryType is built through an in-enum
    #: macro) whose error-recovery parse yields artifact enumerators; the
    #: filter keeps the module to exactly what its title declares.
    FLAG_PREFIXES = ("tf", "asf", "lsf")

    def generate_flags_py(self, output_path: str | Path | None = None) -> str:
        """Generate `hookz/flags.py` — tf*/asf* transaction flags and lsf*
        ledger-object flags, cited per constant. Names outside FLAG_PREFIXES
        are not emitted.
        """
        lines = self._generated_header(
            "Transaction flags (tf*/asf*) and ledger-entry flags (lsf*) "
            "from xahaud.",
            [self.TX_FLAGS_HEADER, self.LEDGER_FORMATS_HEADER],
        )
        # TxFlags.h references lsf* names, so LedgerFormats.h parses first to
        # seed the shared environment; emission order below is tf then lsf.
        # TxFlags.h defines the AMM flags and the transaction masks as
        # constexpr rather than enumerators, so those are collected too.
        env: dict[str, int] = {}
        parsed = {
            self.LEDGER_FORMATS_HEADER: self.parse_enum_constants(
                self.LEDGER_FORMATS_HEADER, env
            ),
        }
        parsed[self.TX_FLAGS_HEADER] = self.parse_enum_constants(
            self.TX_FLAGS_HEADER, env, constexpr_too=True
        )

        seen: dict[str, int] = {}
        for header in (self.TX_FLAGS_HEADER, self.LEDGER_FORMATS_HEADER):
            current_enum = None
            for c in parsed[header]:
                if not c.name.startswith(self.FLAG_PREFIXES):
                    continue
                if c.name in seen:
                    if seen[c.name] != c.value:
                        raise ValueError(
                            f"{c.name} redefined with a different value: "
                            f"{seen[c.name]:#x} vs {c.value:#x}"
                        )
                    continue
                seen[c.name] = c.value
                if c.enum != current_enum:
                    current_enum = c.enum
                    lines.append(f"# ---- {current_enum} ({header}) ----")
                rendered = (
                    f"0x{c.value:08X}" if c.value > 0xFFFF else str(c.value)
                )
                lines.append(
                    f"{c.name} = {rendered}"
                    f"  # xahaud:{header}:{c.line}"
                )
            lines.append("")

        content = "\n".join(lines)
        if output_path:
            Path(output_path).write_text(content)
        return content
