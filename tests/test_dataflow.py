"""The instruction decoder, checked against an independent implementation."""

from __future__ import annotations

import pytest
from wasm_tob import OP_CALL, OP_GET_LOCAL, OP_I32_CONST, decode_bytecode

from hookz.compiler import compile_hook
from hookz.wasm.dataflow import (
    Const, DecodeDesync, Instr, UnmodelledOpcode, call_sites,
    call_sites_over, decode_body,
)
from hookz.wasm.decode import decode_code_bodies_raw

SOURCE = """
    #include "hookapi.h"
    int64_t hook(uint32_t r) {
        int64_t n = 0;
        for (int i = 0; GUARD(4), i < 4; ++i) n += i;
        uint8_t buf[8];
        otxn_field(SBUF(buf), sfAccount);
        accept(SBUF("ok"), n);
        _g(1,1);
        return 0;
    }
"""


@pytest.fixture(scope="module")
def hook_wasm(tmp_path_factory):
    src = tmp_path_factory.mktemp("df") / "h.c"
    src.write_text(SOURCE)
    return compile_hook(src)


def bodies(wasm):
    return [decode_body(wasm, s, e) for s, e in decode_code_bodies_raw(wasm)]


class TestItAgreesWithAnIndependentDecoder:
    """The check that matters: a decoder one byte out still produces plausible
    instructions, so self-consistency proves nothing. `wasm_tob` is a separate
    implementation of the same spec.
    """

    def test_the_same_instructions_in_the_same_order(self, hook_wasm):
        for start, end in decode_code_bodies_raw(hook_wasm):
            theirs = list(decode_bytecode(hook_wasm[start:end]))
            mine = decode_body(hook_wasm, start, end)

            assert len(mine) == len(theirs)
            assert [m.opcode for m in mine] == [t.op.id for t in theirs]

    def test_it_consumes_the_body_exactly(self, hook_wasm):
        """Landing on the boundary is the end-to-end proof of staying in step."""
        for start, end in decode_code_bodies_raw(hook_wasm):
            instrs = decode_body(hook_wasm, start, end)
            assert instrs[0].offset == start
            assert instrs[-1].offset < end


class TestItKeepsTheImmediates:
    """The whole reason this exists — guard.py reads them and drops them."""

    def test_a_call_carries_its_target(self, hook_wasm):
        calls = [i for b in bodies(hook_wasm) for i in b if i.is_call]

        assert calls, "the hook calls otxn_field and accept"
        assert all(len(i.imm) == 1 for i in calls)
        assert all(isinstance(i.imm[0], int) for i in calls)

    def test_a_const_carries_its_value(self, hook_wasm):
        """sfAccount is 0x80001 — a constant the source only names via a macro."""
        consts = {i.imm[0] for b in bodies(hook_wasm) for i in b if i.is_const}

        assert 0x80001 in consts, "the sfAccount field id is in the binary"

    def test_a_local_carries_its_index(self, hook_wasm):
        locals_ = [i for b in bodies(hook_wasm) for i in b if i.is_local]

        assert locals_
        assert all(len(i.imm) == 1 and i.imm[0] >= 0 for i in locals_)

    def test_a_memory_op_carries_align_and_offset(self, hook_wasm):
        mem = [i for b in bodies(hook_wasm) for i in b if i.is_memory]

        assert mem
        assert all(len(i.imm) == 2 for i in mem)


class TestDesyncIsRaisedNotReturned:
    """Ending inside an immediate means the walk was never in step.

    Written against bytes rather than a truncated hook: chopping the last byte
    off a real body removes the one-byte `end`, and the walk then lands on the
    new boundary quite correctly. The failure worth catching is finishing
    *past* the end, which is what reading a partial immediate does.
    """

    # i32.const 0x80001 — opcode plus a three-byte LEB128
    CONST_80001 = bytes([0x41, 0x81, 0x80, 0x20])

    def test_ending_inside_an_immediate_raises(self):
        with pytest.raises(DecodeDesync):
            decode_body(self.CONST_80001, 0, len(self.CONST_80001) - 1)

    def test_the_message_says_where_it_ended_up(self):
        with pytest.raises(DecodeDesync, match="lost sync"):
            decode_body(self.CONST_80001, 0, 2)

    def test_the_whole_instruction_decodes(self):
        """The control — the same bytes, given their real length."""
        (instr,) = decode_body(self.CONST_80001, 0, len(self.CONST_80001))

        assert instr.is_const
        assert instr.imm == (0x80001,)

    def test_a_body_ending_on_a_one_byte_opcode_is_fine(self, hook_wasm):
        """Not every short read is a desync, which is why the check is
        `i != end` rather than a length comparison."""
        start, end = decode_code_bodies_raw(hook_wasm)[0]
        full = decode_body(hook_wasm, start, end)

        assert full[-1].imm == (), "bodies end on `end`, which takes no immediate"


def test_instr_is_hashable_and_frozen():
    """It is used as a dict key when indexing call sites by instruction."""
    i = Instr(offset=0, opcode=OP_I32_CONST, imm=(7,))
    assert {i: "x"}[i] == "x"
    with pytest.raises(Exception):
        i.offset = 1  # type: ignore[misc]


def test_opcode_predicates_do_not_overlap():
    assert Instr(0, OP_CALL, (0,)).is_call
    assert not Instr(0, OP_CALL, (0,)).is_const
    assert Instr(0, OP_GET_LOCAL, (0,)).is_local
    assert not Instr(0, OP_GET_LOCAL, (0,)).is_memory


# ---------------------------------------------------------------------------
# Recovering call arguments
# ---------------------------------------------------------------------------

CALLS = """
    #include "hookapi.h"
    int64_t hook(uint32_t r) {
        uint8_t buf[32];
        otxn_field(SBUF(buf), sfAccount);
        otxn_slot(7);
        slot_subfield(7, sfAmount, 9);
        accept(SBUF("ok"), 0);
        _g(1,1);
        return 0;
    }
"""


@pytest.fixture(scope="module")
def calls_wasm(tmp_path_factory):
    src = tmp_path_factory.mktemp("df2") / "c.c"
    src.write_text(CALLS)
    return compile_hook(src)


def sites_by_name(wasm):
    from hookz.wasm.decode import decode_module
    module = decode_module(wasm)
    names = {i: imp.name for i, imp in enumerate(module.imports)}
    out: dict[str, list] = {}
    for site in call_sites(wasm, module):
        out.setdefault(names.get(site.func_index, "<local>"), []).append(site)
    return out


class TestArgumentsComeOutOfTheBinary:
    """The point of the exercise: the source says `sfAccount`, a macro, and
    the C tools have to expand it to know what was asked for. The binary
    already has the number."""

    def test_a_field_id_is_recovered(self, calls_wasm):
        from hookz import hookapi

        (site,) = sites_by_name(calls_wasm)["otxn_field"]

        assert site.args[-1] == Const(hookapi.sfAccount)

    def test_a_slot_number_is_recovered(self, calls_wasm):
        (site,) = sites_by_name(calls_wasm)["otxn_slot"]

        assert site.args == (Const(7),)

    def test_every_argument_of_a_three_arg_call(self, calls_wasm):
        from hookz import hookapi

        (site,) = sites_by_name(calls_wasm)["slot_subfield"]

        assert site.args == (Const(7), Const(hookapi.sfAmount), Const(9))

    def test_arity_comes_from_the_type_section(self, calls_wasm):
        """Not from a table of API names — a call's argument count is a
        property of the module, and reading it anywhere else would drift."""
        for name, sites in sites_by_name(calls_wasm).items():
            for site in sites:
                assert isinstance(site.args, tuple), name


class TestItRefusesRatherThanDrifts:
    """A stack model that mis-handles one opcode misattributes every argument
    after it, and reports the wrong constant with full confidence."""

    def test_an_unmodelled_opcode_raises(self):
        # 0xE0 is not a wasm opcode and has no entry in the effects table
        body = bytes([0xE0])

        with pytest.raises(UnmodelledOpcode, match="no stack effect"):
            call_sites_over(body)

    def test_the_table_covers_a_real_hook(self, hook_wasm, calls_wasm):
        """Totality for the input at hand, which is the claim that can be
        checked. Any opcode outside the table would have raised above."""
        for wasm in (hook_wasm, calls_wasm):
            assert call_sites(wasm), "decoded without hitting an unmodelled op"

    def test_a_value_pushed_before_a_branch_is_not_guessed(self):
        """Control flow abandons the model rather than merging it — an
        argument whose value depends on which way a branch went comes back
        Unknown, never as whatever was last on the modelled stack."""
        from hookz.wasm.dataflow import BARRIERS

        assert 0x0D in BARRIERS, "br_if"
        assert 0x0B in BARRIERS, "end"
        assert 0x04 in BARRIERS, "if"


# ---------------------------------------------------------------------------
# Locals that only ever hold one constant
# ---------------------------------------------------------------------------

VIA_LOCAL = """
    #include "hookapi.h"
    int64_t hook(uint32_t r) {
        uint8_t kl[34];
        int slot_no = 11;
        util_keylet(SBUF(kl), KEYLET_LINE, kl, 20, kl, 20, kl, 20);
        slot_set(SBUF(kl), slot_no);
        slot_subfield(slot_no, sfBalance, slot_no);
        accept(SBUF("ok"), 0);
        _g(1,1);
        return 0;
    }
"""


class TestConstantsReachedThroughALocal:
    """The compiler puts a slot number in a local; the call site then reads
    `local.get`, and the constant is one step away rather than on the stack."""

    @staticmethod
    @pytest.fixture(scope="class")
    def wasm(tmp_path_factory):
        src = tmp_path_factory.mktemp("df3") / "l.c"
        src.write_text(VIA_LOCAL)
        return compile_hook(src)

    def test_a_slot_number_in_a_local_is_resolved(self, wasm):
        from hookz.wasm.dataflow import api_calls

        (call,) = [c for c in api_calls(wasm) if c.name == "slot_subfield"]

        assert call.const(0) == 11
        assert call.const(2) == 11

    def test_it_is_marked_as_inferred_not_read(self, wasm):
        """Two strengths of evidence, kept apart. A value on the modelled
        stack was there; one from a local was deduced, and its blind spot is
        a branch that skips every assignment."""
        from hookz.wasm.dataflow import ConstFromLocal, api_calls

        (call,) = [c for c in api_calls(wasm) if c.name == "slot_subfield"]

        assert isinstance(call.args[0], ConstFromLocal)
        assert call.args[0].defs, "the assignment offsets are kept for checking"

    def test_a_parameter_is_never_inferred(self, wasm):
        """Its initial value comes from the caller, so an assignment inside
        the function says nothing about what an earlier read saw."""
        from hookz.wasm.dataflow import constant_locals
        from hookz.wasm.decode import decode_code_bodies_raw

        start, end = decode_code_bodies_raw(wasm)[0]
        consts = constant_locals(wasm, start, end, param_count=4)

        assert all(i >= 4 for i in consts)

    def test_a_local_written_twice_with_different_values_is_not_resolved(self):
        """Soundness floor — two constants means neither is *the* value."""
        from hookz.wasm.dataflow import constant_locals

        # i32.const 1, local.set 0, i32.const 2, local.set 0, end
        body = bytes([0x41, 0x01, 0x21, 0x00, 0x41, 0x02, 0x21, 0x00, 0x0B])
        assert constant_locals(body, 0, len(body), param_count=0) == {}

    def test_a_local_written_once_is_resolved(self):
        from hookz.wasm.dataflow import constant_locals

        body = bytes([0x41, 0x07, 0x21, 0x00, 0x0B])
        consts = constant_locals(body, 0, len(body), param_count=0)

        assert consts[0].value == 7

    def test_a_read_before_the_assignment_is_left_alone(self):
        """A declared local starts at zero, so a read that could precede every
        assignment did not see the constant."""
        from hookz.wasm.dataflow import Local, constant_locals, resolve_locals

        body = bytes([0x41, 0x07, 0x21, 0x00, 0x0B])
        consts = constant_locals(body, 0, len(body), param_count=0)

        assert resolve_locals((Local(0),), consts, at_offset=0) == (Local(0),)
        assert resolve_locals((Local(0),), consts, at_offset=99)[0].value == 7


class TestConstantNamingIsPositionAware:
    """A small integer means whatever its argument says it means.

    Naming by value alone read `hook_account(buf, 20)` as
    `hook_account(buf, KEYLET_ESCROW)` — the constant genuinely is 20, and the
    reading is nonsense. Field ids are safe on value alone because an sfCode is
    `type << 16 | field` and cannot collide with a length; keylet types are
    small and collide with everything.
    """

    def test_a_field_id_is_named_anywhere(self):
        from hookz import hookapi
        from hookz.cli.main import _name_for

        assert _name_for(hookapi.sfRewardTime) == "sfRewardTime"

    def test_a_length_is_not_named_as_a_keylet(self):
        from hookz.cli.main import _name_for

        # KEYLET_ESCROW is 20; so is the width of an account id
        assert _name_for(20, api="hook_account", position=1) is None

    def test_a_keylet_type_is_named_in_its_own_argument(self):
        from hookz import hookapi
        from hookz.cli.main import _name_for

        assert _name_for(hookapi.KEYLET_ACCOUNT,
                         api="util_keylet", position=2) == "KEYLET_ACCOUNT"

    def test_the_same_value_elsewhere_in_that_call_is_left_alone(self):
        """`util_keylet(buf, 34, KEYLET_ACCOUNT, acct, 20, ...)` — position 4
        is a length that happens to equal a keylet constant."""
        from hookz.cli.main import _name_for

        assert _name_for(20, api="util_keylet", position=4) is None

    def test_inferred_constants_are_marked(self):
        from hookz.cli.main import _pretty
        from hookz.wasm.dataflow import Const, ConstFromLocal

        assert _pretty(Const(7)) == "7"
        assert _pretty(ConstFromLocal(7, local=3, defs=(1,))) == "7*"
