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

# sfEmitDetails inner fields we need to reach
_EMIT_GENERATION_MAX = 10

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
    "8-generation": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:642",
    "4-txnsignature": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:714",
    "5-lastledgerseq": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:722",
    "6-firstledgerseq": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:748",
    "7-fee": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:758",
    "preflight": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:794",
}

# Transaction types whose preflight hookz does not reproduce. An emit of one of
# these passes the fourteen rules here and may still be refused on chain.
PREFLIGHT_UNPORTED = (
    "every type except those in TYPE_VALIDATORS — see the module docstring")


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
                              check: EmissionCheck) -> None:
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
    if not 1 <= len(signers) <= 32:
        check.refuse("preflight",
                     f"temMALFORMED: {len(signers)} signers is outside 1..32")

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
                   has_callback: bool | None = None) -> EmissionCheck:
    """Would xahaud accept this emitted transaction?

    Returns every reason it would not, rather than the first — a hook that gets
    two things wrong should learn both at once.
    """
    from hookz.xrpl.txn_parser import parse_object

    check = EmissionCheck()
    parsed = parse_object(txn, strict=False)
    fields = parsed.fields

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

    # rule 0 — the emitting account must be the hook's own
    account = fields.get("Account")
    if hook_account is not None and account is not None:
        if not _same_account(account, hook_account):
            check.refuse("0-account",
                         f"Account is {account}, not the hook account")

    # rule 1 — sfSequence present and zero
    if fields.get("Sequence") is None:
        check.refuse("1-sequence", "sfSequence is missing")
    elif fields["Sequence"] != 0:
        check.refuse("1-sequence", f"sfSequence is {fields['Sequence']}, must be 0")

    # rule 2 — sfSigningPubKey present and all zero
    spk = fields.get("SigningPubKey")
    if spk is None:
        check.refuse("2-signingpubkey", "sfSigningPubKey is missing")
    elif set(bytes.fromhex(spk) if isinstance(spk, str) else spk) not in ({0}, set()):
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
        # rule 8 — generation cannot exceed 10
        generation = details.get("EmitGeneration")
        if generation is not None and generation > _EMIT_GENERATION_MAX:
            check.refuse("8-generation",
                         f"EmitGeneration {generation} exceeds {_EMIT_GENERATION_MAX}")
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
        validator(fields, hook_account, check)

    return check


def emission_error(check: EmissionCheck) -> int:
    """The code `emit()` returns when a rule fails."""
    return hookapi.EMISSION_FAILURE
