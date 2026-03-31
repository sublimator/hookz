"""Visitor pattern for WASM hook binary walking.

The walker traverses a WASM module and calls visitor methods at each
decision point. Subclass Visitor to customize behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .types import SectionId, ExportKind


class Action(str, Enum):
    KEEP = "keep"
    STRIP = "strip"
    ENTER = "enter"  # walk into the section/block


@dataclass
class LoopContext:
    """Context passed to on_loop."""
    guard_id: int
    iteration_bound: int
    source_line: int  # extracted from guard_id
    depth: int  # nesting depth (0 = top-level loop)
    parent_bound: int  # containing loop's bound (1 if top-level)


@dataclass
class InstructionContext:
    """Context passed to on_instruction."""
    opcode: int
    offset: int  # byte offset in code section
    mnemonic: str  # e.g. "call", "i32.const"
    loop_depth: int
    current_bound: int  # iteration bound of innermost containing loop


class Visitor:
    """Base visitor — override methods to customize behavior.

    Default behavior matches the hook cleaner:
    - Strip custom sections, tables, start, elements
    - Keep memory, globals, data as-is
    - Keep only function imports
    - Keep only hook/cbak exports and code bodies
    """

    def on_custom_section(self, name: str, size: int) -> Action:
        """Called for each custom section (id=0). Default: strip."""
        return Action.STRIP

    def on_section(self, section_id: int) -> Action:
        """Called for standard sections. Default: keep essential, strip rest."""
        if section_id in (SectionId.TABLE, SectionId.START, SectionId.ELEMENT):
            return Action.STRIP
        return Action.KEEP

    def on_import(self, module: str, name: str, kind: int, type_idx: int) -> Action:
        """Called for each import. Default: keep function imports only."""
        if kind == 0:  # function
            return Action.KEEP
        return Action.STRIP

    def on_export(self, name: str, kind: ExportKind, index: int) -> Action:
        """Called for each export. Default: keep only hook and cbak."""
        if name in ("hook", "cbak") and kind == ExportKind.FUNC:
            return Action.KEEP
        return Action.STRIP

    def on_function_body(self, index: int, is_hook: bool, is_cbak: bool) -> Action:
        """Called for each code body. Default: keep hook/cbak only."""
        if is_hook or is_cbak:
            return Action.KEEP
        return Action.STRIP

    def on_type(self, index: int, params: tuple, results: tuple, is_used: bool) -> Action:
        """Called for each type. Default: keep used types + hook/cbak type."""
        if is_used:
            return Action.KEEP
        return Action.STRIP

    def on_loop(self, ctx: LoopContext) -> None:
        """Called when entering a loop. For analysis, not filtering."""
        pass

    def on_instruction(self, ctx: InstructionContext) -> None:
        """Called for each instruction in kept code bodies. For analysis."""
        pass

    def on_guard_rewrite(self, guard_id: int, bound: int, dirty: bool) -> None:
        """Called when a guard is being rewritten.

        dirty=True means instructions were between the consts and the call.
        """
        pass

    def on_complete(self, original_size: int, cleaned_size: int) -> None:
        """Called after cleaning is complete."""
        pass


class KeepDebugVisitor(Visitor):
    """Keeps .debug_line section for DWARF source mapping."""

    def on_custom_section(self, name: str, size: int) -> Action:
        if name == ".debug_line":
            return Action.KEEP
        return Action.STRIP


class KeepAllVisitor(Visitor):
    """Keeps everything — useful for analysis without modification."""

    def on_custom_section(self, name: str, size: int) -> Action:
        return Action.KEEP

    def on_section(self, section_id: int) -> Action:
        return Action.KEEP

    def on_export(self, name: str, kind: ExportKind, index: int) -> Action:
        return Action.KEEP

    def on_function_body(self, index: int, is_hook: bool, is_cbak: bool) -> Action:
        return Action.KEEP


class WceVisitor(Visitor):
    """Collects WCE analysis data during walking."""

    def __init__(self):
        self.loops: list[LoopContext] = []
        self.instruction_count = 0
        self.guard_rewrites: list[tuple[int, int, bool]] = []

    def on_custom_section(self, name: str, size: int) -> Action:
        if name == ".debug_line":
            return Action.KEEP
        return Action.STRIP

    def on_loop(self, ctx: LoopContext) -> None:
        self.loops.append(ctx)

    def on_instruction(self, ctx: InstructionContext) -> None:
        self.instruction_count += 1

    def on_guard_rewrite(self, guard_id: int, bound: int, dirty: bool) -> None:
        self.guard_rewrites.append((guard_id, bound, dirty))
