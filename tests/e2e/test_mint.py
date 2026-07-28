"""E2E tests for mint.c — GenesisMint emission hook."""

import pytest

from hookz import hookapi
from hookz.runtime import HookRuntime


GENESIS_ACCID = bytes.fromhex("b5f762798a53d543a014caf8b297cff8f2f937e8")
SENDER_ACCID = bytes.fromhex("01" * 20)


@pytest.fixture
def hook(mint_hook):
    return mint_hook


@pytest.fixture
def rt():
    r = HookRuntime()
    r.hook_account = GENESIS_ACCID
    r.otxn_account = SENDER_ACCID
    r.otxn_type = hookapi.ttINVOKE
    return r


class TestMint:
    """mint.c reads a blob from the transaction and emits a GenesisMint."""

    def test_missing_blob_rejects(self, hook, rt):
        """No sfBlob in slot → assertion failure."""
        # otxn_slot(1) puts nothing useful in slot 1,
        # slot_subfield(1, sfBlob, 2) will fail
        result = rt.run(hook)
        assert result.rejected

    def test_with_blob_emits(self, hook, rt):
        """Provide a blob via slot override → hook emits a GenesisMint."""
        # The hook does: otxn_slot(1), slot_subfield(1, sfBlob, 2), slot(buf, size, 2)
        # We need to provide the blob data in slot 2 after subfield navigation
        # Simplest: override slot_subfield to return 2, and populate slot_data:2
        # with a minimal GenesisMints array

        # Minimal GenMints array: one entry (34 bytes) + F1 tail
        # E060 61 <8 byte amount> 8114 <20 byte account> E1 F1
        entry = (
            b"\xE0\x60"            # obj start
            b"\x61"                # amount header
            b"\x40\x00\x00\x00\x00\x0F\x42\x40"  # 1M drops
            b"\x83\x14"           # account header
            + SENDER_ACCID +       # account
            b"\xE1"               # obj end
        )
        array = b"\xF0\x60" + entry + b"\xF1"

        # `slot()` on a Blob serializes it with `STBlob::add`, which is
        # `s.addVL(...)` — so the hook is handed the length prefix as well as
        # the payload, and the `0x99` overwrites at mint.c:78-85 exist to
        # blank exactly that prefix. Serving the array without one makes those
        # overwrites land on the array's own header instead, and the hook then
        # emits an object followed by a stray end-of-array marker.
        assert len(array) <= 192, "a longer blob needs a multi-byte VL prefix"
        rt._slot_overrides[f"slot_subfield:1:{hookapi.sfBlob}"] = 2
        rt._slot_overrides["slot_data:2"] = bytes([len(array)]) + array

        result = rt.run(hook)
        assert result.accepted
        assert b"Emitted txn" in result.return_msg
        assert len(rt.emitted_txns) == 1
