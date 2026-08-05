"""Tests for reusable serialized ledger-object fixtures."""

import pytest

from hookz.ledger import (
    LT,
    book_directory,
    book_directory_keylet,
    offer,
    offer_keylet,
    quality_keylet,
)
from hookz.xrpl.xrpl_patch import patch_xahau_definitions

patch_xahau_definitions()

from xrpl.core.binarycodec import decode


ACCOUNT = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
ISSUER = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"


def test_quality_keylet_matches_book_directory_keylet():
    base = bytes(range(32))
    raw = LT.DIR_NODE.to_bytes(2, "big") + base

    assert book_directory_keylet(base, 0x0123456789ABCDEF) == quality_keylet(
        raw, 0x0123456789ABCDEF
    )
    assert book_directory_keylet(base, 0x0123456789ABCDEF)[-8:] == bytes.fromhex(
        "0123456789ABCDEF"
    )


@pytest.mark.parametrize(
    "keylet,quality",
    [
        (b"\x00\x64" + b"\x00" * 31, 0),
        (b"\x00\x6f" + b"\x00" * 32, 0),
        (b"\x00\x64" + b"\x00" * 32, -1),
        (b"\x00\x64" + b"\x00" * 32, 1 << 64),
    ],
)
def test_quality_keylet_rejects_invalid_inputs(keylet, quality):
    with pytest.raises(ValueError):
        quality_keylet(keylet, quality)


def test_book_directory_serializes_offer_indexes():
    base = b"\x42" * 32
    indexes = [b"\x11" * 32, b"\x22" * 32]

    keylet, data = book_directory(base, 7, indexes)

    assert keylet == book_directory_keylet(base, 7)
    assert decode(data.hex())["Indexes"] == [index.hex().upper() for index in indexes]


def test_offer_serializes_native_and_issued_amounts():
    keylet, data = offer(
        ACCOUNT,
        7,
        "5000000",
        {"currency": "USD", "issuer": ISSUER, "value": "7.5"},
    )
    decoded = decode(data.hex())

    assert keylet == offer_keylet(ACCOUNT, 7)
    assert decoded["Sequence"] == 7
    assert decoded["TakerPays"] == "5000000"
    assert decoded["TakerGets"] == {
        "currency": "USD",
        "issuer": ISSUER,
        "value": "7.5",
    }
