"""Tests for HookResult.return_msg_str."""

from hookz.runtime import HookResult


class TestReturnMsgStr:
    def test_decodes_the_rollback_message(self):
        assert HookResult(return_msg=b"pool: dust below minimum").return_msg_str == \
            "pool: dust below minimum"

    def test_empty_when_there_was_no_message(self):
        assert HookResult().return_msg_str == ""

    def test_substring_checks_work(self):
        """The whole reason it exists: `in` against bytes raises TypeError."""
        result = HookResult(return_msg=b"vault: no listed signers.")
        assert "no listed signers" in result.return_msg_str

    def test_arbitrary_bytes_are_still_visible(self):
        assert HookResult(return_msg=b"\xff\xfe ok").return_msg_str.endswith(" ok")

    def test_strips_the_trailing_nul_sbuf_adds(self):
        """`SBUF("vault: emit.")` sizes the literal including its terminator."""
        assert HookResult(return_msg=b"vault: emit.\x00").return_msg_str == \
            "vault: emit."

    def test_strips_padding_from_a_fixed_size_buffer(self):
        assert HookResult(return_msg=b"ok\x00\x00\x00").return_msg_str == "ok"

    def test_leaves_interior_nuls_alone(self):
        """Only trailing padding goes; the message itself is not edited."""
        assert HookResult(return_msg=b"a\x00b\x00").return_msg_str == "a\x00b"

    def test_return_msg_still_has_the_raw_bytes(self):
        r = HookResult(return_msg=b"vault: emit.\x00")
        assert r.return_msg.endswith(b"\x00")
