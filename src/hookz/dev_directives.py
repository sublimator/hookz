"""Development-only hook directives embedded in C comments."""

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from pathlib import Path

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

C_LANGUAGE = Language(tsc.language())


_PRELUDE = r"""
#ifndef HOOKZ_DEV_DIRECTIVES_H
#define HOOKZ_DEV_DIRECTIVES_H
#include <stdint.h>

extern int64_t hookz_dev_check(uint32_t tag_ptr, uint32_t tag_len);
extern int64_t hookz_dev_u64(uint32_t name_ptr, uint32_t name_len, uint64_t value);
extern int64_t hookz_dev_i64(uint32_t name_ptr, uint32_t name_len, int64_t value);
extern int64_t hookz_dev_bytes(uint32_t name_ptr, uint32_t name_len, uint32_t data_ptr, uint32_t data_len);

#define HOOKZ_DEV_STRLEN(s) ((uint32_t)(sizeof(s) - 1U))
#define HOOKZ_LEAN4_CHECK(tag) hookz_dev_check((uint32_t)(tag), HOOKZ_DEV_STRLEN(tag))
#define HOOKZ_LEAN4_U64(name, value) hookz_dev_u64((uint32_t)(name), HOOKZ_DEV_STRLEN(name), (uint64_t)(value))
#define HOOKZ_LEAN4_I64(name, value) hookz_dev_i64((uint32_t)(name), HOOKZ_DEV_STRLEN(name), (int64_t)(value))
#define HOOKZ_LEAN4_BYTES(name, ptr, len) hookz_dev_bytes((uint32_t)(name), HOOKZ_DEV_STRLEN(name), (uint32_t)(ptr), (uint32_t)(len))

#endif
"""


@dataclass(frozen=True)
class HookzDirective:
    """A development-only C fragment found in a `hookz:` comment."""

    line: int
    column: int
    start_byte: int
    end_byte: int
    code: str


@dataclass(frozen=True)
class HookzLean4Annotation:
    """A metadata-only Lean4 annotation found in a `hookz:` comment."""

    line: int
    column: int
    start_byte: int
    end_byte: int
    adapter: str
    model: str
    attrs: dict[str, str]


def _walk_comments(node):
    if node.type == "comment":
        yield node
    for child in node.children:
        yield from _walk_comments(child)


def _line_directive(raw: str) -> str | None:
    if not raw.startswith("//"):
        return None
    body = raw[2:].strip()
    if not body.startswith("hookz:"):
        return None
    directive = body[len("hookz:"):].strip()
    if directive.startswith("lean4 "):
        return None
    return directive


def _block_directive(raw: str) -> str | None:
    if not raw.startswith("/*") or not raw.endswith("*/"):
        return None
    body = raw[2:-2]
    stripped = body.lstrip()
    if not stripped.startswith("hookz:"):
        return None
    code = stripped[len("hookz:"):]
    if code.startswith("\n"):
        code = code[1:]
    if code.lstrip().startswith("lean4 "):
        return None
    return textwrap.dedent(code).strip()


def _lean4_annotation(raw: str) -> dict[str, str] | None:
    if not raw.startswith("//"):
        return None
    body = raw[2:].strip()
    if not body.startswith("hookz:"):
        return None
    directive = body[len("hookz:"):].strip()
    if not directive.startswith("lean4 "):
        return None

    attrs: dict[str, str] = {}
    for token in directive[len("lean4 "):].split():
        key, sep, value = token.partition("=")
        if not sep:
            continue
        attrs[key] = value
    if "adapter" not in attrs or "model" not in attrs:
        return None
    return attrs


def extract_hookz_directives(source: str | bytes | Path) -> list[HookzDirective]:
    """Extract `hookz:` comment directives from a C source file or string."""
    if isinstance(source, Path):
        source_bytes = source.read_bytes()
    elif isinstance(source, bytes):
        source_bytes = source
    else:
        source_bytes = source.encode()

    parser = Parser(C_LANGUAGE)
    tree = parser.parse(source_bytes)

    directives: list[HookzDirective] = []
    for node in _walk_comments(tree.root_node):
        raw = source_bytes[node.start_byte:node.end_byte].decode(errors="replace")
        code = _line_directive(raw)
        if code is None:
            code = _block_directive(raw)
        if not code:
            continue
        directives.append(HookzDirective(
            line=node.start_point[0] + 1,
            column=node.start_point[1] + 1,
            start_byte=node.start_byte,
            end_byte=node.end_byte,
            code=code,
        ))
    return directives


def extract_hookz_lean4_annotations(source: str | bytes | Path) -> list[HookzLean4Annotation]:
    """Extract metadata-only `hookz: lean4` annotations from C comments."""
    if isinstance(source, Path):
        source_bytes = source.read_bytes()
    elif isinstance(source, bytes):
        source_bytes = source
    else:
        source_bytes = source.encode()

    parser = Parser(C_LANGUAGE)
    tree = parser.parse(source_bytes)

    annotations: list[HookzLean4Annotation] = []
    for node in _walk_comments(tree.root_node):
        raw = source_bytes[node.start_byte:node.end_byte].decode(errors="replace")
        attrs = _lean4_annotation(raw)
        if attrs is None:
            continue
        annotations.append(HookzLean4Annotation(
            line=node.start_point[0] + 1,
            column=node.start_point[1] + 1,
            start_byte=node.start_byte,
            end_byte=node.end_byte,
            adapter=attrs["adapter"],
            model=attrs["model"],
            attrs=attrs,
        ))
    return annotations


def render_dev_source(source: str | Path) -> str:
    """Unwrap `hookz:` comments into dev-only C and prepend hookz macros."""
    source_text = source.read_text() if isinstance(source, Path) else source
    directives = extract_hookz_directives(source_text)
    if not directives:
        return source_text

    source_bytes = source_text.encode()
    rendered = bytearray(source_bytes)
    for directive in sorted(directives, key=lambda d: d.start_byte, reverse=True):
        replacement = f"\n{directive.code}\n".encode()
        rendered[directive.start_byte:directive.end_byte] = replacement

    return _PRELUDE.strip() + "\n\n" + rendered.decode(errors="replace")
