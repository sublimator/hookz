"""Guard checker + WCE analysis for WASM hooks.

A port of xahaud's `validateGuards`/`check_guard`/`compute_wce`. `Guard.h:NNN`
citations throughout refer to the revision pinned in `xahaud_ref` — read that
module before changing anything here: it records the pinned commit, the known
deliberate divergences, and the known gaps where hookz still accepts hooks
xahaud rejects.

Three layers:
1. _walk_code() — builds BlockInfo tree from raw bytecode. Best-effort,
   never raises on malformed guards — just records what it finds.
2. validate_guards() — structural validation (canonical guard patterns,
   import whitelist and signatures, type section, call restrictions).
   Raises GuardError on violations.
3. analyze_wce() — computes WCE from a Module. Returns results even if
   guards are non-canonical.

Contract: every rejection leaves this module as a GuardError. Callers catch
only that, so a DecodeError/IndexError/RecursionError escaping here reaches
the user as a traceback instead of a verdict — and in the build pipeline
skips the failure path entirely.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from wasm_tob import (
    OP_UNREACHABLE, OP_NOP, OP_BLOCK, OP_LOOP, OP_IF, OP_ELSE, OP_END,
    OP_BR, OP_BR_IF, OP_BR_TABLE, OP_RETURN, OP_CALL, OP_CALL_INDIRECT,
    OP_DROP, OP_SELECT,
    OP_GET_LOCAL, OP_SET_LOCAL, OP_TEE_LOCAL, OP_GET_GLOBAL, OP_SET_GLOBAL,
    OP_I32_CONST, OP_I64_CONST, OP_F32_CONST, OP_F64_CONST,
    OP_CURRENT_MEMORY, OP_GROW_MEMORY,
)

from .types import Module, ValType
from .decode import decode_module, decode_code_bodies_raw
from .leb128 import LEB128Error, read_signed, read_unsigned

log = logging.getLogger("hookz.guard")

# Limits from xahaud (see xahaud_ref for the pinned revision)
MAX_GUARD_CALLS = 1024        # Guard.h:293
MAX_WCE = 0xFFFF              # Guard.h:814
MAX_NESTING = 16              # Guard.h:795
MAX_NESTING_DEPTH32 = 32      # Guard.h:797
MIN_HOOK_BYTES = 63           # Guard.h:852

# Depth used when the nesting limit is waived for analysis. Not a xahaud
# value: it exists only so _compute_wce cannot recurse into a Python
# RecursionError on a hostile binary. A tree deeper than this still reports
# nesting_exceeded, so the WCE is still flagged as a floor.
ANALYSIS_NESTING_CEILING = 256

# ---------------------------------------------------------------------------
# Waivable limits
#
# A hook that fails these is one xahaud will not install, but that is often
# exactly the hook worth analysing — you cannot audit an over-budget contract
# if the tooling stops at the first limit. Waiving one lets the run continue
# so the *next* problem is visible, at the cost of an artifact that must never
# be treated as deployable. Structural checks (custom sections, import
# whitelist and signatures, type section, call targets) are NOT waivable:
# those say the binary is malformed, not that it is too big.
# ---------------------------------------------------------------------------
IGNORE_DEPTH = "depth"
IGNORE_WCE = "wce-overage"
IGNORE_GUARD_CALLS = "guard-calls"
IGNORABLE = frozenset({IGNORE_DEPTH, IGNORE_WCE, IGNORE_GUARD_CALLS})

# void_t in the API whitelist — encodes "no result", not a value type (Enum.h:420)
VOID_TYPE = 0x00
# Value types xahaud accepts in a function type (Guard.h:1333, :1405)
VALID_VALUE_TYPES = frozenset(
    {ValType.I32, ValType.I64, ValType.F32, ValType.F64}
)

# Opcodes not in wasm-tob
OP_SELECT_T = 0x1C
OP_TABLE_GET = 0x25
OP_TABLE_SET = 0x26
OP_REF_NULL = 0xD0
OP_REF_IS_NULL = 0xD1
OP_REF_FUNC = 0xD2
OP_PREFIX_FC = 0xFC
OP_PREFIX_FD = 0xFD

BLOCK_TYPE_VOID = 0x40
BLOCK_TYPE_BYTES = {
    ValType.I32, ValType.I64, ValType.F32, ValType.F64,
    ValType.V128, ValType.FUNCREF, ValType.EXTERNREF,
    BLOCK_TYPE_VOID,
}

MEMOP_FIRST = 0x28
MEMOP_LAST = 0x3E
NUMOP_FIRST = 0x45
NUMOP_LAST = 0xC4

GUARD_RULE_FIX_20250131 = 0x01
# fixGuardDepth32 (xahaud PR #653, Enum.h:447) raises the nesting limit 16 -> 32.
# Shipped in dev and release, but VoteBehavior::DefaultNo — so it is off
# unless the network has voted it in. hookz defaults to the stricter limit.
GUARD_RULE_DEPTH_32 = 0x02


def nesting_limit(rules_version: int = 0, ignore: frozenset[str] = frozenset()) -> int:
    """Block depth xahaud allows, given the active amendments.

    Guard.h:795-797 computes `int max_level = 16; if (rulesVersion &
    GuardRuleDepth32) max_level = 32;` just before calling compute_wce.
    """
    if IGNORE_DEPTH in ignore:
        return ANALYSIS_NESTING_CEILING
    if rules_version & GUARD_RULE_DEPTH_32:
        return MAX_NESTING_DEPTH32
    return MAX_NESTING


class GuardError(Exception):
    def __init__(self, message: str, codesec: int = -1, offset: int = -1,
                 key: str | None = None):
        self.codesec = codesec
        self.offset = offset
        # Waiver key when this is a limit breach (see IGNORABLE), else None.
        # Structural failures are not waivable and must not be advertised as
        # though passing a flag could get past them.
        self.key = key
        super().__init__(message)


def _raise_limit(message: str, key: str, codesec: int = -1, offset: int = -1) -> None:
    """Default limit handler: no waivers configured, so every breach raises.

    validate_guards_module substitutes a closure that records waived limits
    instead of raising, for the keys in its `ignore` set.
    """
    raise GuardError(message, codesec, offset, key)


@dataclass
class BlockInfo:
    """Block/loop info node in the WCE tree."""
    iteration_bound: int
    instruction_count: int = 0
    parent: BlockInfo | None = None
    children: list[BlockInfo] = field(default_factory=list)
    start_byte: int = 0
    is_loop: bool = False
    guard_id: int = 0
    guard_canonical: bool = False  # True if loop had proper _g pattern

    def add_child(self, iteration_bound: int, start_byte: int,
                  is_loop: bool = False, guard_id: int = 0,
                  guard_canonical: bool = False) -> BlockInfo:
        child = BlockInfo(
            iteration_bound=iteration_bound, parent=self,
            start_byte=start_byte, is_loop=is_loop,
            guard_id=guard_id, guard_canonical=guard_canonical,
        )
        self.children.append(child)
        return child

    @property
    def wce(self) -> int:
        """WCE of this subtree. Use compute_wce() when the nesting verdict matters."""
        return _compute_wce(self)

    @property
    def depth(self) -> int:
        """Deepest block nesting below this node — the quantity MAX_NESTING bounds.

        Counts the same way _compute_wce's `level` does: the root is 0, so a
        tree of depth D trips the limit exactly when D > nesting_limit().
        Reported unconditionally, unlike `nesting_exceeded`, because "how deep
        is it" is the first thing you want when the answer is "too deep".
        """
        return max((c.depth for c in self.children), default=-1) + 1


@dataclass
class GuardResult:
    hook_wce: int
    cbak_wce: int
    import_count: int
    guard_func_idx: int
    hook_func_idx: int
    cbak_func_idx: int | None
    hook_tree: BlockInfo | None = None
    cbak_tree: BlockInfo | None = None
    errors: list[str] = field(default_factory=list)
    nesting_exceeded: bool = False
    # Limits that failed but were waived. Non-empty means xahaud would REJECT
    # this hook — the binary is analysable, not deployable.
    waived: list[str] = field(default_factory=list)

    @property
    def deployable(self) -> bool:
        return not self.waived

    @property
    def max_depth(self) -> int:
        """Deepest block nesting across both entry points."""
        return max((t.depth for t in (self.hook_tree, self.cbak_tree)
                    if t is not None), default=0)


# ---------------------------------------------------------------------------
# WCE computation
# ---------------------------------------------------------------------------

def nesting_limit_msg(max_level: int) -> str:
    """xahaud's wording, so hookz output matches what SetHook logs."""
    return (
        f"Maximum allowable depth of blocks reached ({max_level} levels). "
        "Flatten your loops and conditions!"
    )


NESTING_LIMIT_MSG = nesting_limit_msg(MAX_NESTING)


@dataclass
class _WceState:
    """Mirrors xahaud's `bool* recursion_limit_reached` out-param."""
    nesting_exceeded: bool = False


def _compute_wce(blk: BlockInfo, level: int = 0,
                 max_level: int = MAX_NESTING,
                 state: _WceState | None = None) -> int:
    if state is None:
        state = _WceState()
    if level > max_level:
        state.nesting_exceeded = True
        return 0
    wce = blk.instruction_count
    for child in blk.children:
        wce += _compute_wce(child, level + 1, max_level, state)
    if blk.parent is None or blk.parent.iteration_bound == 0:
        return wce
    multiplier = blk.iteration_bound / blk.parent.iteration_bound
    return max(int(wce * multiplier), 1)


def compute_wce(
    blk: BlockInfo, max_level: int = MAX_NESTING
) -> tuple[int, bool]:
    """Return (wce, nesting_exceeded) for a block tree.

    xahaud's check_guard rejects the entire hook when compute_wce trips the
    depth limit (Guard.h:207-215, `recursion_limit_reached`), *before*
    testing the WCE budget. The WCE returned alongside a tripped flag is a
    floor, not a total — over-depth subtrees contribute 0 to it, so raising
    max_level is what turns that floor into a real number.
    """
    state = _WceState()
    wce = _compute_wce(blk, 0, max_level, state)
    return wce, state.nesting_exceeded


# ---------------------------------------------------------------------------
# _walk_code — builds block tree, best-effort, never raises on bad guards
# ---------------------------------------------------------------------------

def _walk_code(
    wasm: bytes,
    codesec: int,
    start_offset: int,
    end_offset: int,
    guard_func_idx: int,
) -> tuple[BlockInfo, list[str]]:
    """Walk bytecode, build BlockInfo tree. Returns (root, errors).

    Best-effort: records errors but keeps going. Always returns a tree.
    """
    errors: list[str] = []
    block_depth = 0
    root = BlockInfo(iteration_bound=1, start_byte=start_offset)
    current = root

    i = start_offset
    while i < end_offset:
        if i >= len(wasm):
            errors.append(f"Code section {codesec} truncated at offset {i}")
            break

        instr = wasm[i]
        i += 1
        current.instruction_count += 1

        if instr in (OP_UNREACHABLE, OP_NOP, OP_ELSE):
            continue

        if instr in (OP_BLOCK, OP_LOOP, OP_IF):
            if i >= len(wasm):
                errors.append(f"Truncated after block/loop/if at {i}")
                break
            block_type = wasm[i]
            if block_type in BLOCK_TYPE_BYTES:
                i += 1
            else:
                try:
                    _, i = read_signed(wasm, i)
                except LEB128Error:
                    errors.append(f"Truncated block type at {i}")
                    break

            iteration_bound = current.iteration_bound if current.parent else 1
            loop_guard_id = 0
            canonical = False

            if instr == OP_LOOP:
                # Try to parse canonical guard pattern
                try:
                    saved_i = i
                    if i < len(wasm) and wasm[i] == OP_I32_CONST:
                        i += 1
                        loop_guard_id, i = read_signed(wasm, i)
                        if i < len(wasm) and wasm[i] == OP_I32_CONST:
                            i += 1
                            iteration_bound, i = read_unsigned(wasm, i)
                            if i < len(wasm) and wasm[i] == OP_CALL:
                                i += 1
                                call_idx, i = read_unsigned(wasm, i)
                                if call_idx == guard_func_idx and iteration_bound > 0:
                                    canonical = True
                                else:
                                    errors.append(
                                        f"Loop at {saved_i}: call target {call_idx} != guard {guard_func_idx}")
                                    i = saved_i  # rewind
                            else:
                                errors.append(f"Loop at {saved_i}: missing call after i32.const pair")
                                i = saved_i
                        else:
                            errors.append(f"Loop at {saved_i}: missing second i32.const")
                            i = saved_i
                    else:
                        errors.append(f"Loop at {saved_i}: missing first i32.const")
                        i = saved_i
                except (GuardError, LEB128Error, IndexError):
                    errors.append(f"Loop at {saved_i}: parse error")
                    i = saved_i

            current = current.add_child(
                iteration_bound, i,
                is_loop=(instr == OP_LOOP),
                guard_id=loop_guard_id,
                guard_canonical=canonical,
            )
            block_depth += 1
            continue

        if instr == OP_END:
            block_depth -= 1
            if current.parent is not None:
                current = current.parent
            elif block_depth == -1 and i >= end_offset:
                break
            else:
                errors.append(f"Illegal block end at {i}")
                break
            continue

        # All remaining instructions — just advance past operands
        try:
            i = _skip_operands(wasm, instr, i)
        except (GuardError, LEB128Error, IndexError):
            errors.append(f"Failed to skip instruction 0x{instr:02X} at {i}")
            break

    return root, errors


def _skip_operands(wasm: bytes, instr: int, i: int) -> int:
    """Advance past an instruction's operands."""
    if instr in (OP_BR, OP_BR_IF):
        _, i = read_unsigned(wasm, i)
        return i
    if instr == OP_BR_TABLE:
        vc, i = read_unsigned(wasm, i)
        for _ in range(vc):
            _, i = read_unsigned(wasm, i)
        _, i = read_unsigned(wasm, i)
        return i
    if instr == OP_RETURN:
        return i
    if instr == OP_CALL:
        _, i = read_unsigned(wasm, i)
        return i
    if instr == OP_CALL_INDIRECT:
        _, i = read_unsigned(wasm, i)
        _, i = read_unsigned(wasm, i)
        return i
    if OP_REF_NULL <= instr <= OP_REF_FUNC:
        if instr == OP_REF_NULL:
            i += 1
        elif instr == OP_REF_FUNC:
            _, i = read_unsigned(wasm, i)
        return i
    if instr in (OP_DROP, OP_SELECT):
        return i
    if instr == OP_SELECT_T:
        vc, i = read_unsigned(wasm, i)
        i += vc
        return i
    if OP_GET_LOCAL <= instr <= OP_SET_GLOBAL:
        _, i = read_unsigned(wasm, i)
        return i
    if instr in (OP_TABLE_GET, OP_TABLE_SET):
        _, i = read_unsigned(wasm, i)
        return i
    if instr == OP_PREFIX_FC:
        fc, i = read_unsigned(wasm, i)
        if 12 <= fc <= 17:
            _, i = read_unsigned(wasm, i)
            if fc in (12, 14):
                _, i = read_unsigned(wasm, i)
        elif fc == 8:
            _, i = read_unsigned(wasm, i)
            i += 1
        elif fc == 9:
            _, i = read_unsigned(wasm, i)
        elif fc == 10:
            i += 2
        elif fc == 11:
            i += 1
        return i
    if MEMOP_FIRST <= instr <= MEMOP_LAST:
        _, i = read_unsigned(wasm, i)
        _, i = read_unsigned(wasm, i)
        return i
    if instr == OP_CURRENT_MEMORY:
        i += 1
        return i
    if instr == OP_GROW_MEMORY:
        i += 1
        return i
    if instr in (OP_I32_CONST, OP_I64_CONST):
        _, i = read_signed(wasm, i)
        return i
    if instr == OP_F32_CONST:
        return i + 4
    if instr == OP_F64_CONST:
        return i + 8
    if NUMOP_FIRST <= instr <= NUMOP_LAST:
        return i
    if instr == OP_PREFIX_FD:
        v, i = read_unsigned(wasm, i)
        if v <= 11:
            _, i = read_unsigned(wasm, i)
            _, i = read_unsigned(wasm, i)
        elif 84 <= v <= 91:
            _, i = read_unsigned(wasm, i)
            _, i = read_unsigned(wasm, i)
            i += 1
        elif 21 <= v <= 34:
            i += 1
        elif v in (12, 13):
            i += 16
        return i
    return i  # unknown — assume no operands


# ---------------------------------------------------------------------------
# validate_guards — strict validation, raises on violations
# ---------------------------------------------------------------------------

def _check_guard_strict(
    wasm: bytes,
    codesec: int,
    start_offset: int,
    end_offset: int,
    guard_func_idx: int,
    last_import_idx: int,
    rules_version: int = 0,
    limit=_raise_limit,
) -> BlockInfo:
    """Strict guard validation. Raises GuardError on any violation."""
    tree, errors = _walk_code(wasm, codesec, start_offset, end_offset, guard_func_idx)

    # Walk errors are fatal in strict mode
    if errors:
        raise GuardError(errors[0], codesec, start_offset)

    # Check all loops have canonical guards.
    # Iterative: the tree is as deep as the wasm nests, and a hostile binary
    # can nest thousands of blocks. Recursing here would raise RecursionError
    # instead of GuardError, which callers do not catch — they would see a
    # traceback rather than a rejection. xahaud validates guards inline during
    # its walk and never recurses over the tree at all.
    stack = [tree]
    while stack:
        node = stack.pop()
        if node.is_loop and not node.guard_canonical:
            raise GuardError(
                f"Loop at offset {node.start_byte} does not have canonical guard pattern",
                codesec, node.start_byte)
        stack.extend(node.children)

    # Check no calls to non-imported functions and no call_indirect
    # (This requires a second walk since _walk_code doesn't check these)
    _validate_calls(wasm, codesec, start_offset, end_offset,
                    guard_func_idx, last_import_idx, rules_version, limit)

    return tree


def _bump_guard_count(
    guard_count: int, codesec: int, offset: int,
    limit=_raise_limit,
) -> int:
    """Count one _g call, enforcing xahaud's limit.

    Guard.h:421 and :515 both write `if (guard_count++ > MAX_GUARD_CALLS)` —
    post-increment, so the limit trips on the 1026th call rather than the
    1025th. Mirrored exactly so hookz neither accepts nor rejects a hook the
    real checker would treat differently.
    """
    if guard_count > MAX_GUARD_CALLS:
        limit(
            f"Too many guard calls! Limit is {MAX_GUARD_CALLS}",
            IGNORE_GUARD_CALLS, codesec, offset,
        )
    return guard_count + 1


def _validate_calls(
    wasm: bytes, codesec: int, start: int, end: int,
    guard_func_idx: int, last_import_idx: int, rules_version: int,
    limit=_raise_limit,
) -> None:
    """Validate call targets and disallowed instructions."""
    i = start
    guard_count = 0
    while i < end:
        if i >= len(wasm):
            break
        instr = wasm[i]
        i += 1

        if instr in (OP_BLOCK, OP_LOOP, OP_IF):
            bt = wasm[i] if i < len(wasm) else BLOCK_TYPE_VOID
            if bt in BLOCK_TYPE_BYTES:
                i += 1
            else:
                _, i = read_signed(wasm, i)
            if instr == OP_LOOP:
                # Skip the guard pattern (already validated by _check_loops)
                if i < len(wasm) and wasm[i] == OP_I32_CONST:
                    i += 1
                    _, i = read_signed(wasm, i)
                    if i < len(wasm) and wasm[i] == OP_I32_CONST:
                        i += 1
                        _, i = read_unsigned(wasm, i)
                        if i < len(wasm) and wasm[i] == OP_CALL:
                            i += 1
                            call_idx, i = read_unsigned(wasm, i)
                            # Guard.h:421 counts the loop-header _g too.
                            # Missing this let a hook carry unlimited guarded
                            # loops: 2000 of them stay far under the WCE
                            # budget, so nothing else would catch it.
                            if call_idx == guard_func_idx:
                                guard_count = _bump_guard_count(
                                    guard_count, codesec, i, limit)
            continue

        if instr == OP_CALL:
            callee, i = read_unsigned(wasm, i)
            if callee > last_import_idx:
                raise GuardError(
                    f"Call to function {callee} outside imports (last={last_import_idx})",
                    codesec, i)
            if callee == guard_func_idx:
                guard_count = _bump_guard_count(guard_count, codesec, i, limit)
            continue

        if instr == OP_CALL_INDIRECT:
            raise GuardError("call_indirect disallowed", codesec, i)

        if instr == OP_GROW_MEMORY:
            raise GuardError("memory.grow disallowed", codesec, i)

        if instr == OP_PREFIX_FC:
            fc, i = read_unsigned(wasm, i)
            if fc == 10 and (rules_version & GUARD_RULE_FIX_20250131):
                raise GuardError("memory.copy not allowed", codesec, i)
            if fc == 11 and (rules_version & GUARD_RULE_FIX_20250131):
                raise GuardError("memory.fill not allowed", codesec, i)
            # Skip remaining 0xFC operands
            if 12 <= fc <= 17:
                _, i = read_unsigned(wasm, i)
                if fc in (12, 14):
                    _, i = read_unsigned(wasm, i)
            elif fc == 8:
                _, i = read_unsigned(wasm, i)
                i += 1
            elif fc == 9:
                _, i = read_unsigned(wasm, i)
            elif fc == 10:
                i += 2
            elif fc == 11:
                i += 1
            continue

        try:
            i = _skip_operands(wasm, instr, i)
        except (GuardError, LEB128Error, IndexError):
            break


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_guards(
    wasm: bytes,
    import_whitelist: set[str] | dict[str, tuple[int, ...]] | None = None,
    rules_version: int = GUARD_RULE_FIX_20250131,
    ignore: frozenset[str] | None = None,
) -> GuardResult:
    """Strict guard validation. Raises GuardError on any violation.

    import_whitelist may be:
      - None: load names *and* signatures from hook_api.macro (what xahaud does)
      - a dict of name -> (return, *params) wasm type codes: check both
      - a set of names: check names only, skipping the signature checks

    ignore waives limit checks (see IGNORABLE) instead of raising, recording
    each in GuardResult.waived. A result with anything waived describes a hook
    xahaud will refuse to install.
    """
    # Before decoding: xahaud rejects on size first, and decode_module would
    # otherwise raise DecodeError, which callers catching GuardError miss.
    _check_min_size(wasm)
    if import_whitelist is None:
        from .whitelist import get_import_signatures
        import_whitelist = get_import_signatures()
    mod = _decode_or_reject(wasm)
    return validate_guards_module(
        mod, wasm, import_whitelist, rules_version, ignore
    )


def _decode_or_reject(wasm: bytes) -> Module:
    """decode_module, with every failure mode expressed as a GuardError.

    A malformed binary is a rejection, not a hookz bug: the decoders raise
    DecodeError, and wasm-tob raises bare IndexError on some inputs. Neither
    is a GuardError, so both reach the CLI as a traceback instead of a verdict.
    """
    try:
        return decode_module(wasm)
    except GuardError:
        raise
    except Exception as e:
        raise GuardError(
            f"Hook was not valid webassembly binary: "
            f"{type(e).__name__}: {e}"
        ) from e


def _entry_type_idx(mod: Module, exp, name: str) -> int:
    """Type index of an exported entry point, or GuardError if it has none.

    Module.func_type_idx indexes the function section directly, so an export
    pointing past it raises IndexError — which escapes callers that catch only
    GuardError, surfacing as a traceback. xahaud rejects the same module with
    "hook or cbak functions did not have a corresponding type in WASM binary"
    (Guard.h log code 21).
    """
    code_idx = exp.index - mod.import_count
    if code_idx < 0 or code_idx >= len(mod.functions):
        raise GuardError(
            f"{name} function did not have a corresponding type in WASM binary "
            f"(export points at function {exp.index}, "
            f"module has {mod.import_count} imports + {len(mod.functions)} functions)"
        )
    return mod.func_type_idx(exp.index)


def _check_min_size(wasm: bytes) -> None:
    """Guard.h:852: "63 bytes is the smallest possible valid hook wasm".

    Rejecting on size first means short or garbage input is a clean GuardError
    rather than a DecodeError/IndexError out of the decoders — which callers
    catching GuardError would not handle.
    """
    if len(wasm) < MIN_HOOK_BYTES:
        raise GuardError(
            f"Hook is {len(wasm)} bytes; the smallest valid hook wasm "
            f"is {MIN_HOOK_BYTES}"
        )


def _validate_types(
    mod: Module,
    signatures: dict[str, tuple[int, ...]],
    hook_type_idx: int,
) -> None:
    """Check the type section against the hook API signatures.

    Mirrors Guard.h:1250-1455. Every type entry
    must belong to something: an import whose API signature it matches, or the
    hook/cbak entry point. A type entry used by nothing at all is rejected, as
    are mismatched parameter counts, parameter types, result counts and result
    types. hookz previously checked only that import *names* were whitelisted.
    """
    # type index -> [(import index, api name)]
    usage: dict[int, list[tuple[int, str]]] = {}
    for idx, imp in enumerate(mod.imports):
        usage.setdefault(imp.type_idx, []).append((idx, imp.name))

    for j, ftype in enumerate(mod.types):
        sharers = usage.get(j)

        if sharers:
            # Every API sharing a type index must have the same signature.
            first_name, first_sig = sharers[0][1], signatures[sharers[0][1]]
            for _, api_name in sharers[1:]:
                if signatures[api_name] != first_sig:
                    raise GuardError(
                        "Function type is inconsistent across referenced apis "
                        f"(either: {first_name}, or: {api_name}) at type {j}"
                    )
            expected_params = first_sig[1:]
            expected_results = () if first_sig[0] == VOID_TYPE else (first_sig[0],)
            label = f"Hook API: {first_name}"
        elif j == hook_type_idx:
            expected_params = (ValType.I32,)
            expected_results = (ValType.I64,)
            label = "hook/cbak"
        else:
            raise GuardError(
                f"Invalid function type at type {j}. "
                "Not used by any import or hook/cbak func."
            )

        for t in (*ftype.params, *ftype.results):
            if t not in VALID_VALUE_TYPES:
                raise GuardError(f"Invalid value type 0x{t:02X} in type {j}")

        if len(ftype.params) != len(expected_params):
            raise GuardError(f"{label} has the wrong number of parameters")
        if tuple(ftype.params) != tuple(expected_params):
            raise GuardError(f"{label} definition parameters incorrect")
        if len(ftype.results) != len(expected_results):
            raise GuardError(
                f"{label} has wrong return count "
                f"(expected {len(expected_results)}, got {len(ftype.results)})"
            )
        if tuple(ftype.results) != tuple(expected_results):
            raise GuardError(f"{label} definition return type incorrect")


def validate_guards_module(
    mod: Module,
    wasm: bytes,
    import_whitelist: set[str] | dict[str, tuple[int, ...]] | None = None,
    rules_version: int = 0,
    ignore: frozenset[str] | None = None,
) -> GuardResult:
    """Strict validation using a pre-decoded Module."""
    ignore = frozenset(ignore or ())
    unknown = ignore - IGNORABLE
    if unknown:
        raise ValueError(
            f"not waivable: {sorted(unknown)}; valid: {sorted(IGNORABLE)}"
        )
    waived: list[str] = []

    def _limit(message: str, key: str, codesec: int = -1, offset: int = -1) -> None:
        if key not in ignore:
            raise GuardError(message, codesec, offset, key)
        # Deduped: the guard-call limit is tested once per _g call, so a
        # waived breach would otherwise record hundreds of identical lines.
        if message not in waived:
            waived.append(message)

    _check_min_size(wasm)

    if mod.custom_sections:
        raise GuardError("Hook contains custom sections (use cleaner to strip)")

    if mod.other_imports:
        raise GuardError("Non-function import detected")

    guard_idx = mod.guard_func_idx
    if guard_idx is None:
        raise GuardError("Hook did not import _g")

    if import_whitelist is not None:
        for imp in mod.imports:
            if imp.module != "env":
                raise GuardError(f"Import module must be 'env', got '{imp.module}'")
            if imp.name not in import_whitelist:
                raise GuardError(f"Import '{imp.name}' not in whitelist")

    last_import_idx = mod.import_count - 1

    hook_exp = mod.hook_export
    if hook_exp is None:
        raise GuardError("Hook did not export 'hook'")
    cbak_exp = mod.cbak_export

    hook_type_idx = _entry_type_idx(mod, hook_exp, "hook")
    if hook_type_idx < len(mod.types) and not mod.types[hook_type_idx].is_hook_type:
        raise GuardError("hook() must be int64_t(uint32_t)")
    if cbak_exp is not None:
        cbak_type_idx = _entry_type_idx(mod, cbak_exp, "cbak")
        if cbak_type_idx != hook_type_idx:
            raise GuardError("hook and cbak must have the same type signature")

    # Signature checking needs the type codes; a bare set of names cannot
    # supply them, so callers passing one get name-only validation. That is a
    # weaker check than xahaud's — say so, because silently downgrading is how
    # a hook with a wrong import signature reads as clean.
    if isinstance(import_whitelist, dict):
        _validate_types(mod, import_whitelist, hook_type_idx)
    else:
        log.warning(
            "import whitelist is a set of names, so import signatures and the "
            "type section were NOT validated; pass whitelist.get_import_signatures() "
            "for the checks xahaud actually performs"
        )

    hook_code_idx = hook_exp.index - mod.import_count
    cbak_code_idx = cbak_exp.index - mod.import_count if cbak_exp else None

    code_bodies = decode_code_bodies_raw(wasm)
    hook_wce = 0
    cbak_wce = 0
    hook_tree = None
    cbak_tree = None
    any_nesting_exceeded = False

    # The limit xahaud would apply, unless depth is being waived — in which
    # case go deep enough that the WCE below is a real total rather than the
    # floor you get when over-depth subtrees are counted as 0.
    max_level = nesting_limit(rules_version, ignore)
    real_limit = nesting_limit(rules_version)

    for j, (body_start, body_end) in enumerate(code_bodies):
        try:
            tree = _check_guard_strict(
                wasm, j, body_start, body_end,
                guard_idx, last_import_idx, rules_version, _limit,
            )
        except LEB128Error as e:
            raise GuardError(f"Malformed LEB128 in code section {j}: {e}") from e

        # Depth is judged at the real limit; the WCE is computed at max_level.
        _, over_real_limit = compute_wce(tree, real_limit)
        wce, nesting_exceeded = compute_wce(tree, max_level)
        any_nesting_exceeded = any_nesting_exceeded or nesting_exceeded

        # xahaud tests nesting first and returns {} — the WCE alongside a
        # tripped flag is understated, so never report it as a budget figure.
        if over_real_limit:
            _limit(nesting_limit_msg(real_limit), IGNORE_DEPTH, j, body_start)
        if wce >= MAX_WCE:
            _limit(
                f"WCE {wce} exceeds limit {MAX_WCE} in code section {j}",
                IGNORE_WCE, j, body_start,
            )
        if j == hook_code_idx:
            hook_wce = wce
            hook_tree = tree
        elif cbak_code_idx is not None and j == cbak_code_idx:
            cbak_wce = wce
            cbak_tree = tree

    return GuardResult(
        hook_wce=hook_wce, cbak_wce=cbak_wce,
        import_count=mod.import_count, guard_func_idx=guard_idx,
        hook_func_idx=hook_exp.index,
        cbak_func_idx=cbak_exp.index if cbak_exp else None,
        hook_tree=hook_tree, cbak_tree=cbak_tree,
        nesting_exceeded=any_nesting_exceeded,
        waived=waived,
    )


def analyze_wce(
    wasm: bytes,
) -> GuardResult:
    """Best-effort WCE analysis. Never raises — returns results + errors.

    Works on debug builds, dirty guards, whatever. Always returns a tree.

    "Never raises" has to include the decode. Callers reach this *after* strict
    validation already rejected the bytes, so a module that will not decode is
    the ordinary case here, not an exotic one — and a truncated or
    partially-written artifact used to die inside the rejection handler, with
    the DecodeError replacing the verdict that sent it there.
    """
    try:
        mod = decode_module(wasm)
    except Exception as e:                                     # noqa: BLE001
        return GuardResult(
            hook_wce=0, cbak_wce=0, import_count=0,
            guard_func_idx=-1, hook_func_idx=-1, cbak_func_idx=None,
            errors=[f"Failed to decode module: {type(e).__name__}: {e}"],
        )
    return analyze_wce_module(mod, wasm)


def analyze_wce_module(
    mod: Module,
    wasm: bytes,
) -> GuardResult:
    """Best-effort WCE analysis on a pre-decoded Module."""
    all_errors: list[str] = []

    guard_idx = mod.guard_func_idx
    if guard_idx is None:
        all_errors.append("No _g import found — WCE estimates will be inaccurate")
        guard_idx = -1  # won't match any call

    hook_exp = mod.hook_export
    cbak_exp = mod.cbak_export

    if hook_exp is None:
        all_errors.append("No hook() export found")
        # cbak may well be exported — reporting it absent because hook is
        # absent states something about the binary that is not true.
        return GuardResult(
            hook_wce=0, cbak_wce=0, import_count=mod.import_count,
            guard_func_idx=guard_idx, hook_func_idx=-1,
            cbak_func_idx=cbak_exp.index if cbak_exp else None,
            errors=all_errors,
        )

    hook_code_idx = hook_exp.index - mod.import_count
    cbak_code_idx = cbak_exp.index - mod.import_count if cbak_exp else None

    try:
        code_bodies = decode_code_bodies_raw(wasm)
    except Exception as e:
        all_errors.append(f"Failed to decode code section: {e}")
        return GuardResult(
            hook_wce=0, cbak_wce=0, import_count=mod.import_count,
            guard_func_idx=guard_idx, hook_func_idx=hook_exp.index,
            cbak_func_idx=cbak_exp.index if cbak_exp else None,
            errors=all_errors,
        )

    hook_wce = 0
    cbak_wce = 0
    hook_tree = None
    cbak_tree = None
    any_nesting_exceeded = False

    for j, (body_start, body_end) in enumerate(code_bodies):
        try:
            tree, errors = _walk_code(wasm, j, body_start, body_end, guard_idx)
        except (GuardError, LEB128Error, IndexError) as e:
            all_errors.append(f"Failed to analyze code section {j}: {e}")
            continue
        all_errors.extend(errors)
        wce, nesting_exceeded = compute_wce(tree)
        if nesting_exceeded:
            # Best-effort mode reports rather than raises, but this is not a
            # nit: xahaud rejects such a hook outright, and the WCE we report
            # for it is a floor (over-depth subtrees counted as 0).
            any_nesting_exceeded = True
            all_errors.append(
                f"Code section {j}: {NESTING_LIMIT_MSG} "
                f"xahaud would REJECT this hook; WCE {wce:,} is understated."
            )
        if j == hook_code_idx:
            hook_wce = wce
            hook_tree = tree
        elif cbak_code_idx is not None and j == cbak_code_idx:
            cbak_wce = wce
            cbak_tree = tree

    return GuardResult(
        hook_wce=hook_wce, cbak_wce=cbak_wce,
        import_count=mod.import_count, guard_func_idx=guard_idx,
        hook_func_idx=hook_exp.index,
        cbak_func_idx=cbak_exp.index if cbak_exp else None,
        hook_tree=hook_tree, cbak_tree=cbak_tree,
        errors=all_errors,
        nesting_exceeded=any_nesting_exceeded,
    )
