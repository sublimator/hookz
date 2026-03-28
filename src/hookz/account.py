"""Account ID ↔ r-address conversion.

Hooks use 20-byte "accid" (account ID) everywhere. XRPL JSON uses
base58 "raddr" (r-address) strings. This module converts between them.

Mirrors the hook API functions util_raddr and util_accid.
"""

from xrpl.core.addresscodec import encode_classic_address, decode_classic_address


def to_raddr(accid: bytes) -> str:
    """20-byte account ID → r-address string."""
    if len(accid) != 20:
        raise ValueError(f"accid must be exactly 20 bytes, got {len(accid)}")
    return encode_classic_address(accid)


def to_accid(raddr: str) -> bytes:
    """r-address string → 20-byte account ID."""
    return decode_classic_address(raddr)
