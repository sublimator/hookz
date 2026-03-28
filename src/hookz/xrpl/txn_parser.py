"""Tolerant object/transaction deserializer for hook-emitted bytes.

Hooks build transactions by manual byte manipulation — they're often
partial, malformed, or contain trailing template bytes. This parser
returns everything it can, plus detailed info about where and why
parsing stopped.

Usage:
    result = parse_object(rt.emitted_txns[0])
    assert result.fields["TransactionType"] == "Remit"
    assert result.complete  # or check result.error for partial parses

    # Strict mode — raises on any parse failure
    fields = parse_object(data, strict=True).fields
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hookz.xrpl.xrpl_patch import patch_xahau_definitions

# Ensure Xahau definitions are loaded before any binarycodec use
patch_xahau_definitions()

from xrpl.core.binarycodec.binary_wrappers import BinaryParser


def _resolve_tx_type(raw: Any) -> Any:
    """Convert raw hex TransactionType to name, e.g. '005F' → 'Remit'."""
    from xrpl.core.binarycodec.definitions import definitions
    try:
        code = int(str(raw), 16) if isinstance(raw, str) else raw
        name = definitions.get_transaction_type_name(code)
        return name if name else raw
    except Exception:
        return raw


@dataclass
class ParseResult:
    """Result of parsing serialized XRPL object bytes."""

    fields: dict[str, Any] = field(default_factory=dict)
    """Successfully parsed fields as {name: json_value}."""

    complete: bool = False
    """True if the entire input was consumed without errors."""

    error: Exception | None = None
    """The exception that stopped parsing, if any."""

    error_field: str | None = None
    """Name of the field being parsed when the error occurred, if known."""

    bytes_consumed: int = 0
    """Number of input bytes successfully parsed."""

    remaining: bytes = b""
    """Unparsed bytes after the last successful field."""

    raw: bytes = b""
    """Original input bytes."""

    @property
    def ok(self) -> bool:
        """Alias for complete — did everything parse?"""
        return self.complete

    def __getitem__(self, key: str) -> Any:
        """Convenience: result["TransactionType"] instead of result.fields[...]."""
        return self.fields[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)


class ParseError(Exception):
    """Raised in strict mode when parsing fails."""
    def __init__(self, result: ParseResult):
        self.result = result
        consumed = result.bytes_consumed
        total = len(result.raw)
        field_info = f" (parsing {result.error_field})" if result.error_field else ""
        super().__init__(
            f"Parse failed at byte {consumed}/{total}{field_info}: {result.error}"
        )


def parse_object(data: bytes, *, strict: bool = True) -> ParseResult:
    """Parse serialized XRPL object bytes into structured fields.

    Returns a ParseResult with all successfully parsed fields, plus
    error details if parsing stopped early. Handles the messy reality
    of hook-emitted transactions: partial objects, unknown fields,
    malformed amounts, trailing template bytes.

    Args:
        data: raw serialized bytes
        strict: if True, raise ParseError on any parse failure

    Returns:
        ParseResult with fields, completion status, and error details
    """
    result = ParseResult(raw=data)
    total_bytes = len(data)
    parser = BinaryParser(data.hex())

    while not parser.is_end():
        field_name = None
        try:
            field_obj = parser.read_field()
            field_name = field_obj.name
            value = parser.read_field_value(field_obj)
            json_value = value.to_json()

            if field_name == "TransactionType":
                json_value = _resolve_tx_type(json_value)

            result.fields[field_name] = json_value
        except Exception as e:
            result.error = e
            result.error_field = field_name
            break

    result.bytes_consumed = total_bytes - len(parser)
    result.remaining = data[result.bytes_consumed:]
    result.complete = result.error is None and len(result.remaining) == 0

    if strict and not result.complete:
        raise ParseError(result)

    return result


# Backwards compat alias
def parse_txn(txn_bytes: bytes) -> dict[str, Any]:
    """Parse a transaction, returning just the fields dict. Legacy API."""
    return parse_object(txn_bytes).fields
