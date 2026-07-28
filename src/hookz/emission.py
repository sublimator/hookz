"""Validate an emitted transaction the way xahaud does before accepting it.

`emit()` on chain is not a store. `HookAPI::emit`
(xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:498) parses the blob, applies
fourteen rules to it, and then runs the transactor's own `preflight`. Any of
those failing returns EMISSION_FAILURE, and the hook sees `emit() < 0` — which
is a branch real hooks take and roll back on.

hookz used to append the bytes and return 32 unconditionally, which made every
emit succeed in the harness regardless of what was in it. That is the worst
failure mode this project has: a false green light. A hook whose emit template
has a wrong offset, whose ledger sequence is out of range, or whose signer list
cannot reach quorum passed here and is refused on chain, and the test suite said
it was fine.

WHAT IS AND IS NOT COVERED
--------------------------
The fourteen emission rules are implemented here. They are generic — they
depend on the transaction's common fields, not on what kind of transaction it
is — so they port faithfully.

`ripple::preflight` (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:794) does not
port: it dispatches into per-transaction-type transactor code, which is most of
rippled. `TYPE_VALIDATORS` below covers the types hooks in practice emit, and
`PREFLIGHT_UNPORTED` records the rest as a known gap in the same spirit as the
Guard.h gaps in `wasm/xahaud_ref` — hookz accepting what xahaud would refuse is
worth stating out loud rather than discovering later.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hookz import hookapi

# xahaud refuses a generation of this value or above
_EMIT_GENERATION_MAX = 10

# sfEmitDetails is required to be present *and valid*: all five of these must
# be there. xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:632
_EMIT_DETAIL_FIELDS = ("EmitGeneration", "EmitBurden", "EmitParentTxnID",
                       "EmitNonce", "EmitHookHash")

# A hook may not emit a pseudo-transaction.
# xahaud:src/libxrpl/protocol/STTx.cpp:686
PSEUDO_TX_TYPES = frozenset({
    "EnableAmendment", "SetFee", "UNLModify", "EmitFailure", "UNLReport",
    "Cron",
})

# Signer count bounds. 8 unless featureExpandedSignerList is active, then 32 —
# xahaud:include/xrpl/protocol/STTx.h:56. hookz hardcoded 32, which accepts a
# list of 9 that the network refuses on an unamended chain.
MAX_SIGNERS_BASE = 8
MAX_SIGNERS_EXPANDED = 32

# The rule numbering is xahaud's, kept so a reader can put the two side by side.
# Each entry is (rule label, citation) — see `wasm/xahaud_ref.check_citations`.
RULES = {
    "parse": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:511",
    "pseudo": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:524",
    "0-account": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:553",
    "1-sequence": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:562",
    "2-signingpubkey": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:571",
    "2a-signers": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:595",
    "2b-ticket": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:603",
    "2c-accounttxnid": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:611",
    "3-emitdetails": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:619",
    "8-generation": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:643",
    "4-txnsignature": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:714",
    "5-lastledgerseq": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:722",
    "6-firstledgerseq": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:748",
    "7-fee": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:758",
    "preflight": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:794",
}

# KNOWN GAPS — hookz ACCEPTS what xahaud REJECTS
# ----------------------------------------------
# Stated rather than discovered, in the same spirit as wasm/xahaud_ref's list.
# Each is an emit that passes here and may be refused on chain.
KNOWN_GAPS = (
    # xahaud binds the EmitDetails values to the running hook: burden against
    # the parent's, parent txn id against the originating transaction, nonce
    # against those etxn_nonce actually issued, hook hash against the emitting
    # hook. All of it needs execution context this function is not given.
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:660
    "EmitDetails values (burden, parent txn, nonce, hook hash) are not bound "
    "to the emitting context — only their presence is checked",
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:531
    "canEmit / the hook's own allow-list of emittable transaction types is "
    "not consulted",
    # handlers/emit.py passes min_fee=None because the mock's etxn_fee_base is
    # a constant, not xahaud's calculation. Rule 7 therefore only checks that a
    # fee is present in a live emit; the floor is reachable via the unit API.
    "the fee floor is not enforced in a live emit, only fee presence",
    # TYPE_VALIDATORS covers SignerListSet. Everything else — Payment, Remit,
    # ClaimReward, URIToken, OfferCreate — gets the fourteen rules and no
    # transactor preflight at all.
    "ripple::preflight is ported for SignerListSet only",
    # prepare() is a copy-stub: it does not inject Sequence, FirstLedgerSequence,
    # LastLedgerSequence, SigningPubKey, Fee or EmitDetails. A hook that relies
    # on it emits a transaction missing all six.
    "prepare() does not build the fields it documents",
)

PREFLIGHT_UNPORTED = (
    "every type except those in TYPE_VALIDATORS — see KNOWN_GAPS")


@dataclass
class Rejection:
    """Why xahaud would have refused this emit."""
    rule: str
    detail: str
    citation: str = ""

    def __str__(self) -> str:
        where = f"  [{self.citation}]" if self.citation else ""
        return f"{self.rule}: {self.detail}{where}"


@dataclass
class EmissionCheck:
    rejections: list[Rejection] = field(default_factory=list)
    # Set when hookz could not fully decode the blob. Not a rejection: it says
    # this tool could not judge, which is different from xahaud refusing.
    undecodable: str = ""

    @property
    def ok(self) -> bool:
        return not self.rejections

    def refuse(self, rule: str, detail: str) -> None:
        self.rejections.append(Rejection(rule, detail, RULES.get(rule, "")))

    def __str__(self) -> str:
        return "; ".join(str(r) for r in self.rejections)


# ---------------------------------------------------------------------------
# Per-type validators — the sliver of preflight that is worth porting
# ---------------------------------------------------------------------------

def _validate_signer_list_set(fields: dict, account: bytes | None,
                              check: EmissionCheck,
                              expanded_signer_list: bool = False) -> None:
    """`SetSignerList::validateQuorumAndSignerEntries`.

    xahaud:src/xrpld/app/tx/detail/SetSignerList.cpp:262

    Ported because a signer list that cannot reach its own quorum installs
    nothing, and the hook that emitted it cannot tell without this check —
    the emit simply succeeds here and is refused on chain.
    """
    entries = fields.get("SignerEntries")
    quorum = fields.get("SignerQuorum")
    if entries is None or quorum is None:
        return                                  # a destroy, or not our shape

    signers = []
    for item in entries:
        entry = item.get("SignerEntry", item) if isinstance(item, dict) else {}
        signers.append((entry.get("Account"), entry.get("SignerWeight", 0)))

    # xahaud:src/xrpld/app/tx/detail/SetSignerList.cpp:271 — count bounds
    ceiling = MAX_SIGNERS_EXPANDED if expanded_signer_list else MAX_SIGNERS_BASE
    if not 1 <= len(signers) <= ceiling:
        check.refuse("preflight",
                     f"temMALFORMED: {len(signers)} signers is outside "
                     f"1..{ceiling}"
                     + ("" if expanded_signer_list else
                        " (featureExpandedSignerList inactive)"))

    accounts = [a for a, _ in signers]
    if len(accounts) != len(set(accounts)):
        # xahaud:src/xrpld/app/tx/detail/SetSignerList.cpp:287
        check.refuse("preflight", "temBAD_SIGNER: duplicate signers")

    for acct, weight in signers:
        if weight <= 0:
            # xahaud:src/xrpld/app/tx/detail/SetSignerList.cpp:302
            check.refuse("preflight", "temBAD_WEIGHT: a signer has weight <= 0")
        if account is not None and acct is not None and _same_account(acct, account):
            # xahaud:src/xrpld/app/tx/detail/SetSignerList.cpp:310
            check.refuse("preflight",
                         "temBAD_SIGNER: a signer may not be the account itself")

    total = sum(w for _, w in signers)
    if quorum <= 0 or total < quorum:
        # xahaud:src/xrpld/app/tx/detail/SetSignerList.cpp:325
        check.refuse("preflight",
                     f"temBAD_QUORUM: quorum {quorum} unreachable, "
                     f"weights sum to {total}")


def _same_account(parsed, raw: bytes) -> bool:
    """The parser hands back r-addresses; the runtime holds 20-byte ids."""
    from hookz.account import to_raddr
    try:
        return parsed == to_raddr(raw)
    except Exception:                                    # noqa: BLE001
        return False


TYPE_VALIDATORS = {
    "SignerListSet": _validate_signer_list_set,
}


# ---------------------------------------------------------------------------
# The fourteen rules
# ---------------------------------------------------------------------------

def check_emission(txn: bytes, *, hook_account: bytes | None = None,
                   ledger_seq: int | None = None,
                   min_fee: int | None = None,
                   has_callback: bool | None = None,
                   expanded_signer_list: bool = False) -> EmissionCheck:
    """Would xahaud accept this emitted transaction?

    Returns every reason it would not, rather than the first — a hook that gets
    two things wrong should learn both at once.
    """
    from hookz.xrpl.txn_parser import parse_object

    check = EmissionCheck()
    parsed = parse_object(txn, strict=False)
    fields = parsed.fields

    if parsed.illegal:
        # A rule xahaud enforces itself, so this is a refusal and not a shrug.
        check.refuse("parse", f"not a deserialisable transaction: {parsed.error}")
        return check

    if not parsed.complete:
        # hookz's parser is not xahaud's deserialiser. When it stops early,
        # every field after that point looks absent — and reporting those as
        # rule violations blames the hook for a limitation of this tool. Two
        # of xahaud's own genesis hooks deliberately write 0x99 padding that
        # this parser cannot decode and the network plainly accepts.
        #
        # So: say what is true. The blob could not be fully read, so the
        # field rules are not applied and nothing is claimed about them. It is
        # recorded, not raised, because an unreadable emit is a gap in hookz.
        check.undecodable = (
            f"hookz parsed {parsed.bytes_consumed}/{len(txn)} bytes"
            + (f", stopped at {parsed.error}" if parsed.error else "")
            + " — emission rules not applied")
        return check

    # pseudo-transactions may not be emitted at all
    if fields.get("TransactionType") in PSEUDO_TX_TYPES:
        check.refuse("pseudo",
                     f"{fields['TransactionType']} is a pseudo-transaction")

    # rule 0 — the emitting account must be the hook's own. Absent is a
    # refusal in its own right; skipping the rule when the field is missing
    # meant a transaction with no Account passed.
    account = fields.get("Account")
    if account is None:
        check.refuse("0-account", "sfAccount is missing")
    elif hook_account is not None and not _same_account(account, hook_account):
        check.refuse("0-account", f"Account is {account}, not the hook account")

    # rule 1 — sfSequence present and zero
    if fields.get("Sequence") is None:
        check.refuse("1-sequence", "sfSequence is missing")
    elif fields["Sequence"] != 0:
        check.refuse("1-sequence", f"sfSequence is {fields['Sequence']}, must be 0")

    # rule 2 — sfSigningPubKey present and all zero
    spk = fields.get("SigningPubKey")
    if spk is None:
        check.refuse("2-signingpubkey", "sfSigningPubKey is missing")
    else:
        raw = bytes.fromhex(spk) if isinstance(spk, str) else bytes(spk)
        # size must be 0 or 33, *and* every byte zero — two separate checks
        # upstream, and only the second was ported
        if len(raw) not in (0, 33):
            check.refuse("2-signingpubkey",
                         f"sfSigningPubKey is {len(raw)} bytes, must be 0 or 33")
        elif any(raw):
            check.refuse("2-signingpubkey", "sfSigningPubKey must be all zero")

    # rules 2a–2c — nothing that would make it independently signable
    if fields.get("Signers") is not None:
        check.refuse("2a-signers", "sfSigners is present")
    if fields.get("TicketSequence") is not None:
        check.refuse("2b-ticket", "sfTicketSequence may not be used")
    if fields.get("AccountTxnID") is not None:
        check.refuse("2c-accounttxnid", "sfAccountTxnID is not allowed")

    # rule 4 — sfTxnSignature absent
    if fields.get("TxnSignature") is not None:
        check.refuse("4-txnsignature", "sfTxnSignature is present")

    # rule 3 — sfEmitDetails present
    details = fields.get("EmitDetails")
    if details is None:
        check.refuse("3-emitdetails", "sfEmitDetails is missing")
    else:
        missing = [f for f in _EMIT_DETAIL_FIELDS if details.get(f) is None]
        if missing:
            check.refuse("3-emitdetails",
                         f"sfEmitDetails malformed: missing {', '.join(missing)}")

        # rule 8 — generation cannot exceed 10
        generation = details.get("EmitGeneration")
        # >=, not >. The comment upstream says "cannot exceed 10" and the
        # predicate under it refuses 10 itself.
        if generation is not None and generation >= _EMIT_GENERATION_MAX:
            check.refuse("8-generation",
                         f"EmitGeneration {generation} is {_EMIT_GENERATION_MAX} or more")
        # a hook exporting cbak gets sfEmitCallback; one that does not, must not
        # sfEmitCallback is present exactly when the emitting hook exports
        # cbak. `has_callback=None` means the caller cannot tell, and an
        # unknown must not become an accusation — guessing here rejected every
        # valid emit from every hook that has a callback.
        callback = details.get("EmitCallback")
        if has_callback is True and callback is None:
            check.refuse("3-emitdetails",
                         "sfEmitCallback is missing though the hook exports cbak")
        elif has_callback is False and callback is not None:
            check.refuse("3-emitdetails",
                         "sfEmitCallback is present though the hook exports no cbak")
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:698 — whose callback
        if (callback is not None and hook_account is not None
                and not _same_account(callback, hook_account)):
            check.refuse("3-emitdetails",
                         f"sfEmitCallback is {callback}, must be the emitting "
                         "hook's account")

    # rules 5 and 6 — the ledger window
    lls = fields.get("LastLedgerSequence")
    fls = fields.get("FirstLedgerSequence")
    if lls is None:
        check.refuse("5-lastledgerseq", "sfLastLedgerSequence is missing")
    elif ledger_seq is not None:
        if lls < ledger_seq + 1:
            check.refuse("5-lastledgerseq",
                         f"LastLedgerSequence {lls} is not after ledger {ledger_seq}")
        elif lls > ledger_seq + 5:
            check.refuse("5-lastledgerseq",
                         f"LastLedgerSequence {lls} exceeds ledger {ledger_seq} + 5")
    if fls is None:
        check.refuse("6-firstledgerseq", "sfFirstLedgerSequence is missing")
    elif lls is not None and fls > lls:
        check.refuse("6-firstledgerseq",
                     f"FirstLedgerSequence {fls} is after LastLedgerSequence {lls}")

    # rule 7 — the fee
    fee = fields.get("Fee")
    if fee is None:
        check.refuse("7-fee", "sfFee is missing")
    elif min_fee is not None:
        try:
            paid = int(fee)
        except (TypeError, ValueError):
            paid = None
        if paid is not None and paid < min_fee:
            check.refuse("7-fee", f"fee {paid} is below the required {min_fee}")

    # the sliver of preflight we reproduce
    validator = TYPE_VALIDATORS.get(fields.get("TransactionType"))
    if validator is not None:
        validator(fields, hook_account, check,
                  expanded_signer_list=expanded_signer_list)

    return check


def emission_error(check: EmissionCheck) -> int:
    """The code `emit()` returns when a rule fails."""
    return hookapi.EMISSION_FAILURE
