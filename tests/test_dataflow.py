"""The instruction decoder, checked against an independent implementation."""

from __future__ import annotations

import pytest
from wasm_tob import OP_CALL, OP_GET_LOCAL, OP_I32_CONST, decode_bytecode

from hookz.compiler import compile_hook
from hookz.wasm.dataflow import DecodeDesync, Instr, decode_body
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
