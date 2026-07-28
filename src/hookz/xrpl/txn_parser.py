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

    illegal: bool = False
    """True when parsing stopped on a rule xahaud's own deserialiser enforces.

    The distinction matters downstream: an incomplete parse is usually *this*
    parser being weaker than xahaud's, which is a gap in hookz and not grounds
    to accuse a hook. But some failures are upstream's rule — more than 64 NOPs
    throws in STObject::set, and a blob from which not one field can be read is
    not a transaction by anyone's reading. Those the network would refuse too.
    """

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


# A field header of type 9 / field 9, which xahaud treats as a no-op: it skips
# the byte and keeps deserialising rather than failing
# (xahaud:src/libxrpl/protocol/STObject.cpp:221). Hooks use it to blank out
# template bytes they do not want — genesis/mint.c writes it over unwanted VL
# length prefixes.
#
# This is a **Xahau** extension. The parsing underneath is xrpl-py's XRPL
# codec, which knows nothing about it and stops dead on the unknown header, so
# the skip has to happen here. Do not carry this into an XRPL context: there,
# a (9,9) header is simply malformed.
NOP_FIELD_HEADER = 0x99   # BinaryParser.peek() returns an int, despite its type hint
MAX_NOPS = 64          # xahaud:src/libxrpl/protocol/STObject.cpp:223

# Field type codes this parser has to recognise structurally, as `STObject::set`
# does, rather than by name.
_STI_OBJECT = 14
_STI_ARRAY = 15
_NOP = (9, 9)
_OBJECT_END = (_STI_OBJECT, 1)
_ARRAY_END = (_STI_ARRAY, 1)




def _unwrap(consumed: bytes, type_code: int) -> bytes:
    """The contents of a nested object or array, without its terminator."""
    if type_code == _STI_OBJECT:
        return consumed[:-1] if consumed[-1:] == b"\xe1" else consumed
    return consumed[:-1] if consumed[-1:] == b"\xf1" else consumed

def _nested_problem(contents: bytes, depth: int = 1) -> str | None:
    """The same rules, applied inside an object or array. None if clean.

    `STObject::set` is recursive — it constructs each nested field with
    `v_.emplace_back(sit, fn, depth + 1)`
    (xahaud:src/libxrpl/protocol/STObject.cpp:264) — so the unknown-field,
    duplicate and end-of-array checks run at every level, not just the
    transaction's own. xrpl-py's reader instead consumes a nested object
    wholesale and folds repeats into a dict, where the last one wins, so a
    malformation one level down leaves the outer parse looking clean.
    """
    from xrpl.core.binarycodec.definitions import get_field_name_from_header
    from xrpl.core.binarycodec.definitions.field_header import FieldHeader

    from hookz.handlers.sto import _walk_fields

    if depth > 64:
        return "object nesting is deeper than any transaction shape"

    seen: set[int] = set()
    try:
        fields = list(_walk_fields(contents))
    except Exception:                                          # noqa: BLE001
        # the reader could not get through it; the top-level classifier
        # already decides what an unreadable blob means
        return None

    for fid, type_code, field_code, _off, _tlen, pay_off, pay_len in fields:
        if (type_code, field_code) == _ARRAY_END:
            return "illegal end-of-array marker in object"
        try:
            get_field_name_from_header(FieldHeader(type_code, field_code))
        except KeyError:
            return f"unknown field in object t={type_code} f={field_code}"
        if fid in seen:
            return f"duplicate field detected at depth {depth}"
        seen.add(fid)

        payload = contents[pay_off:pay_off + pay_len]
        if type_code == _STI_OBJECT:
            inner = payload[:-1] if payload[-1:] == bytes([_OBJECT_END[0] << 4
                                                          | _OBJECT_END[1]]) else payload
            problem = _nested_problem(inner, depth + 1)
            if problem:
                return problem
        elif type_code == _STI_ARRAY:
            problem = _array_problem(
                payload[:-1] if payload[-1:] == b"\xf1" else payload, depth + 1)
            if problem:
                return problem
    return None


def _array_problem(body: bytes, depth: int) -> str | None:
    """The rules as they apply inside an array, where repetition is the point.

    An array holds many elements of one named type — `SignerEntry` appears
    once per signer — so the duplicate-field check that governs an object
    would reject every array with more than one entry. `STObject::set` runs
    that check per object (`getSortedFields` over one object's own fields,
    xahaud:src/libxrpl/protocol/STObject.cpp:270), and each element is its own
    object. So: recurse into the elements, do not compare them to each other.
    """
    for element in _array_elements(body):
        problem = _nested_problem(element, depth + 1)
        if problem:
            return problem
    return None


def _array_elements(payload: bytes):
    """Each element of a serialized array, as its object contents."""
    from hookz.handlers.sto import _walk_fields

    body = payload
    try:
        for _fid, tc, _fc, _off, _tl, pay_off, pay_len in _walk_fields(body):
            if tc != _STI_OBJECT:
                continue
            inner = body[pay_off:pay_off + pay_len]
            yield inner[:-1] if inner[-1:] == b"\xe1" else inner
    except Exception:                                          # noqa: BLE001
        return

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
    from xrpl.core.binarycodec.definitions import (
        get_field_instance, get_field_name_from_header,
    )

    result = ParseResult(raw=data)
    total_bytes = len(data)
    parser = BinaryParser(data.hex())
    nops = 0

    # The loop below follows `STObject::set`
    # (xahaud:src/libxrpl/protocol/STObject.cpp:212) in order: read the field
    # id, then decide what it means. Reading the header first is what makes the
    # NOP and the two terminators distinguishable from a field, since none of
    # them names one — and it is why the checks can sit in the same sequence
    # upstream applies them in rather than being recovered from an exception.
    while not parser.is_end():
        field_name = None
        try:
            header = parser.read_field_header()      # sit.getFieldID(type, field)
        except Exception as e:                       # noqa: BLE001
            # A type or field code outside the encodable range. `getFieldID`
            # throws on the same input.
            result.error = e
            result.illegal = True
            break
        ident = (header.type_code, header.field_code)

        # A NOP is skipped and deserialising continues, up to 64 of them
        # (xahaud:src/libxrpl/protocol/STObject.cpp:221). Hooks use it to blank
        # out template bytes they do not want — genesis/mint.c writes it over
        # unwanted VL length prefixes — so a parser that stops here disagrees
        # with the network about a transaction the network accepts.
        if ident == _NOP:
            nops += 1
            if nops >= MAX_NOPS:
                # xahaud:src/libxrpl/protocol/STObject.cpp:226 throws here, so
                # this is the network's rule rather than a limit of this parser
                result.error = ValueError(f"too many NOPs (>= {MAX_NOPS})")
                result.illegal = True
                break
            continue

        # Both terminators end a *nested* object. Reaching one while reading a
        # transaction is an error: an object terminator makes `STObject::set`
        # return true, which `STTx` throws on
        # (xahaud:src/libxrpl/protocol/STTx.cpp:76), and an end-of-array marker
        # throws in place (xahaud:src/libxrpl/protocol/STObject.cpp:243).
        # xrpl-py's codec instead stores them as ordinary fields called
        # ObjectEndMarker / ArrayEndMarker, which is how a blob the network
        # refuses parses cleanly here.
        if ident == _OBJECT_END:
            result.error = ValueError("transaction contains an object terminator")
            result.illegal = True
            break
        if ident == _ARRAY_END:
            result.error = ValueError("illegal end-of-array marker in object")
            result.illegal = True
            break

        try:
            field_name = get_field_name_from_header(header)
        except KeyError:
            # `SField::getField(type, field).isInvalid()`
            # (xahaud:src/libxrpl/protocol/STObject.cpp:253). The two agree
            # only while the loaded definitions match xahaud's SField table,
            # which is why `patch_xahau_definitions()` runs at import.
            result.error = ValueError(
                f"unknown field in object t={header.type_code} "
                f"f={header.field_code}")
            result.illegal = True
            break

        if field_name in result.fields:
            # xahaud:src/libxrpl/protocol/STObject.cpp:276. xrpl-py's codec
            # collapses repeats into a dict, where the last one silently wins.
            result.error = ValueError(f"duplicate field detected: {field_name}")
            result.illegal = True
            break

        try:
            payload_start = total_bytes - len(parser)
            value = parser.read_field_value(get_field_instance(field_name))
            json_value = value.to_json()

            # The rules apply at every level, and xrpl-py consumed this whole
            # field in one step — so anything malformed inside it has to be
            # checked here rather than by the loop, which will never see those
            # headers.
            if ident[0] in (_STI_OBJECT, _STI_ARRAY):
                consumed = data[payload_start:total_bytes - len(parser)]
                body = _unwrap(consumed, ident[0])
                problem = (_array_problem(body, 1) if ident[0] == _STI_ARRAY
                           else _nested_problem(body, 1))
                if problem is not None:
                    result.error = ValueError(problem)
                    result.error_field = field_name
                    result.illegal = True
                    break

            if field_name == "TransactionType":
                json_value = _resolve_tx_type(json_value)

            result.fields[field_name] = json_value
        except Exception as e:                       # noqa: BLE001
            result.error = e
            result.error_field = field_name
            break

    result.bytes_consumed = total_bytes - len(parser)
    result.remaining = data[result.bytes_consumed:]
    result.complete = result.error is None and len(result.remaining) == 0
    # Not one field recovered means this is not a transaction by anyone's
    # reading, so xahaud's STTx construction would throw too. Counting bytes
    # instead would never fire: the parser consumes the field header it chokes
    # on before it knows it cannot read it.
    if result.error is not None and not result.fields:
        result.illegal = True

    if strict and not result.complete:
        raise ParseError(result)

    return result


# Backwards compat alias
def parse_txn(txn_bytes: bytes) -> dict[str, Any]:
    """Parse a transaction, returning just the fields dict. Legacy API."""
    return parse_object(txn_bytes).fields
