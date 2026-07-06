"""Development-only hookz comment directives."""

from dataclasses import replace
from pathlib import Path

import pytest

from hookz import hookapi
from hookz.compiler import compile_hook_dev
from hookz.config import ConfigError, load_config
from hookz.coverage.rewriter import parse_dwarf_locations
from hookz.dev_directives import (
    extract_hookz_directives,
    render_dev_source,
)
from hookz.dev_lean import (
    DevCheckContext,
    DevLeanError,
    capture_u64,
    dispatch_dev_lean_checks,
    import_module,
    lean_available,
    register_dev_lean_adapter,
    render_dev_lean_checks,
)
from hookz.ledger import account_root
from hookz.runtime import Hook, HookRuntime
from hookz.xfl import float_to_xfl
from e2e.lean_adapters import register_lean_adapters
from location_consts import WASI_SDK


E2E_ROOT = Path(__file__).parent / "e2e"
BALANCE_GATE_SOURCE = E2E_ROOT / "hooks" / "misc" / "balance_gate.c"
MINT_SOURCE = E2E_ROOT / "hooks" / "genesis" / "mint.c"
HOOKZ_TOML = E2E_ROOT / "hookz.toml"

ALICE_ACCID = bytes.fromhex("b5f762798a53d543a014caf8b297cff8f2f937e8")
BOB = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"
BOB_ACCID = bytes.fromhex("f667b0ca50cc7709a220b0561b85e53a48461fa8")
SENDER_ACCID = bytes.fromhex("01" * 20)


def _state_counter_after_increment(
    captures: dict[str, dict],
    context: DevCheckContext,
) -> str:
    before = capture_u64(captures, "before_count")
    after = capture_u64(captures, "count")
    lean_import = import_module(context, "Hookz.Contracts.StateCounter")
    model_module = "Hookz.Contracts.StateCounter"
    return f"""import {lean_import}

open Hookz.Contracts

-- generated from hookz dev checkpoint: state_counter.after_increment
example :
    {model_module}.expected {{
      txKind := .payment,
      owner := false,
      counterState := some {before},
      counterParam := none
    }} = {{ verdict := .accept, counterState := some {after} }} := by
  native_decide
"""


register_dev_lean_adapter(
    "state_counter.after_increment",
    _state_counter_after_increment,
)
register_lean_adapters()


DEV_DIRECTIVE_SOURCE = r"""
#include <stdint.h>
extern int64_t accept(uint32_t, uint32_t, int64_t);

int64_t hook(uint32_t reserved)
{
    uint64_t count = 40;
    uint64_t before_count = count;
    count++;
    uint8_t buf[2] = {0xAA, 0xBB};

    /* hookz:
    HOOKZ_LEAN4_U64("before_count", before_count);
    HOOKZ_LEAN4_U64("count", count);
    HOOKZ_LEAN4_BYTES("buf", buf, 2);
    HOOKZ_LEAN4_CHECK("state_counter.after_increment");
    */

    return accept(0, 0, (int64_t)count);
}
"""

DEV_DIRECTIVE_FAILING_SOURCE = r"""
#include <stdint.h>
extern int64_t accept(uint32_t, uint32_t, int64_t);

int64_t hook(uint32_t reserved)
{
    uint64_t before_count = 40;
    uint64_t count = 42;

    /* hookz:
    HOOKZ_LEAN4_U64("before_count", before_count);
    HOOKZ_LEAN4_U64("count", count);
    HOOKZ_LEAN4_CHECK("state_counter.after_increment");
    */

    return accept(0, 0, (int64_t)count);
}
"""

BUGGY_BALANCE_GATE_SOURCE = f"""
#include <stdint.h>
extern int64_t accept(uint32_t, uint32_t, int64_t);

int64_t hook(uint32_t reserved)
{{
    /* hookz:
    HOOKZ_LEAN4_U64("outgoing", 0);
    HOOKZ_LEAN4_I64("sender_balance_xfl", {float_to_xfl(5_000_000.0)});
    HOOKZ_LEAN4_I64("min_balance_xfl", {float_to_xfl(10_000_000.0)});
    HOOKZ_LEAN4_U64("verdict_accept", 1);
    HOOKZ_LEAN4_CHECK("balance_gate.after_decision");
    */

    return accept(0, 0, 1);
}}
"""

BUGGY_MINT_SOURCE = r"""
#include <stdint.h>
extern int64_t accept(uint32_t, uint32_t, int64_t);

int64_t hook(uint32_t reserved)
{
    /* hookz:
    HOOKZ_LEAN4_U64("has_blob", 0);
    HOOKZ_LEAN4_U64("emitted_count", 1);
    HOOKZ_LEAN4_U64("verdict_accept", 1);
    HOOKZ_LEAN4_CHECK("mint.after_decision");
    */

    return accept(0, 0, 1);
}
"""

LEGACY_LEAN4_METADATA_SOURCE = r"""
// hookz: lean4 adapter=state_counter model=Hookz.Contracts.StateCounter.expected
int64_t hook(uint32_t reserved)
{
    return 0;
}
"""


def test_extracts_block_directive():
    directives = extract_hookz_directives(DEV_DIRECTIVE_SOURCE)

    assert len(directives) == 1
    assert "HOOKZ_LEAN4_U64" in directives[0].code
    assert directives[0].line > 0
    assert directives[0].end_line >= directives[0].line


def test_renders_dev_source_with_prelude_and_unwrapped_code():
    rendered = render_dev_source(DEV_DIRECTIVE_SOURCE)

    assert "extern int64_t hookz_dev_check" in rendered
    assert "HOOKZ_LEAN4_U64(\"count\", count);" in rendered
    assert "#line 1 \"<hookz-dev-source>\"" in rendered
    assert "hookz:" not in rendered


def test_legacy_lean4_metadata_is_not_unwrapped():
    directives = extract_hookz_directives(LEGACY_LEAN4_METADATA_SOURCE)
    rendered = render_dev_source(LEGACY_LEAN4_METADATA_SOURCE)

    assert directives == []
    assert "hookz: lean4 adapter=state_counter" in rendered
    assert "extern int64_t hookz_dev_check" not in rendered


@pytest.mark.skipif(WASI_SDK is None, reason="wasi-sdk not found")
def test_dev_compile_dwarf_lines_stay_in_original_source_range(tmp_path):
    source = tmp_path / "dev_directive_hook.c"
    source.write_text(DEV_DIRECTIVE_SOURCE)
    config = replace(load_config(source_file=source), exports=["hook"])

    wasm = compile_hook_dev(source, config=config)
    locs = parse_dwarf_locations(wasm)
    source_lines = DEV_DIRECTIVE_SOURCE.splitlines()
    post_directive_line = next(
        index
        for index, line in enumerate(source_lines, start=1)
        if "return accept" in line
    )
    dwarf_lines = {loc.line for loc in locs}

    assert locs
    assert post_directive_line in dwarf_lines
    assert max(dwarf_lines) <= len(source_lines)


@pytest.mark.skipif(WASI_SDK is None or not lean_available(), reason="wasi-sdk/lake not found")
def test_dev_compile_records_unwrapped_hook_events(tmp_path, monkeypatch):
    source = tmp_path / "dev_directive_hook.c"
    source.write_text(DEV_DIRECTIVE_SOURCE)
    config = replace(load_config(source_file=source), exports=["hook"])

    lean_out = tmp_path / "lean"
    monkeypatch.setenv("HOOKZ_LEAN_DEV_DIR", str(lean_out))
    wasm = compile_hook_dev(source, config=config)
    rt = HookRuntime()
    result = rt.run(wasm)

    assert result.accepted
    assert result.return_code == 41
    assert result.dev_events == [
        {"kind": "u64", "name": "before_count", "value": 40, "line": None},
        {"kind": "u64", "name": "count", "value": 41, "line": None},
        {"kind": "bytes", "name": "buf", "value": b"\xAA\xBB", "line": None},
        {"kind": "check", "tag": "state_counter.after_increment", "line": None},
    ]
    assert list(lean_out.glob("*.lean"))


@pytest.mark.skipif(WASI_SDK is None or not lean_available(), reason="wasi-sdk/lake not found")
def test_dev_compile_fails_fast_when_lean_checkpoint_fails(tmp_path, monkeypatch):
    source = tmp_path / "dev_directive_hook_fails.c"
    source.write_text(DEV_DIRECTIVE_FAILING_SOURCE)
    config = replace(load_config(source_file=source), exports=["hook"])

    monkeypatch.setenv("HOOKZ_LEAN_DEV_DIR", str(tmp_path / "lean"))
    wasm = compile_hook_dev(source, config=config)
    rt = HookRuntime()
    result = rt.run(wasm)

    assert not result.accepted
    assert isinstance(result.error, DevLeanError)
    assert "state_counter.after_increment" in str(result.error)


@pytest.mark.skipif(WASI_SDK is None or not lean_available(), reason="wasi-sdk/lake not found")
def test_buggy_balance_gate_checkpoint_is_caught_by_lean(tmp_path, monkeypatch):
    source = tmp_path / "buggy_balance_gate_hook.c"
    source.write_text(BUGGY_BALANCE_GATE_SOURCE)
    config = replace(load_config(source_file=source), exports=["hook"])

    monkeypatch.setenv("HOOKZ_LEAN_DEV_DIR", str(tmp_path / "lean"))
    wasm = compile_hook_dev(source, config=config)
    rt = HookRuntime()
    result = rt.run(wasm)

    assert not result.accepted
    assert isinstance(result.error, DevLeanError)
    assert "balance_gate.after_decision" in str(result.error)


@pytest.mark.skipif(WASI_SDK is None or not lean_available(), reason="wasi-sdk/lake not found")
def test_buggy_mint_checkpoint_is_caught_by_lean(tmp_path, monkeypatch):
    source = tmp_path / "buggy_mint_hook.c"
    source.write_text(BUGGY_MINT_SOURCE)
    config = replace(load_config(source_file=source), exports=["hook"])

    monkeypatch.setenv("HOOKZ_LEAN_DEV_DIR", str(tmp_path / "lean"))
    wasm = compile_hook_dev(source, config=config)
    rt = HookRuntime()
    result = rt.run(wasm)

    assert not result.accepted
    assert isinstance(result.error, DevLeanError)
    assert "mint.after_decision" in str(result.error)


def test_renders_dev_events_to_lean_check():
    events = [
        {"kind": "u64", "name": "before_count", "value": 40},
        {"kind": "u64", "name": "count", "value": 41},
        {"kind": "check", "tag": "state_counter.after_increment"},
    ]

    rendered = render_dev_lean_checks(events)

    assert len(rendered) == 1
    tag, lean_source = rendered[0]
    assert tag == "state_counter.after_increment"
    assert "Hookz.Contracts.StateCounter.expected" in lean_source
    assert "counterState := some 40" in lean_source
    assert "counterState := some 41" in lean_source


def test_renders_hook_local_balance_gate_checkpoint():
    events = [
        {"kind": "u64", "name": "outgoing", "value": 0},
        {
            "kind": "i64",
            "name": "sender_balance_xfl",
            "value": float_to_xfl(50_000_000.0),
        },
        {
            "kind": "i64",
            "name": "min_balance_xfl",
            "value": float_to_xfl(10_000_000.0),
        },
        {"kind": "u64", "name": "verdict_accept", "value": 1},
        {"kind": "check", "tag": "after_decision"},
    ]

    rendered = render_dev_lean_checks(events, source_path=BALANCE_GATE_SOURCE)

    assert len(rendered) == 1
    tag, lean_source = rendered[0]
    assert tag == "balance_gate.after_decision"
    assert "import HookzDevSidecar_balance_gate" in lean_source
    assert "Hookz.Contracts.BalanceGate.expected" in lean_source
    assert "senderBalanceDrops := some 50000000" in lean_source
    assert "minBalanceDrops := 10000000" in lean_source


def test_renders_hook_local_mint_checkpoint():
    events = [
        {"kind": "u64", "name": "has_blob", "value": 1},
        {"kind": "u64", "name": "emitted_count", "value": 1},
        {"kind": "u64", "name": "verdict_accept", "value": 1},
        {"kind": "check", "tag": "after_decision"},
    ]

    rendered = render_dev_lean_checks(events, source_path=MINT_SOURCE)

    assert len(rendered) == 1
    tag, lean_source = rendered[0]
    assert tag == "mint.after_decision"
    assert "import HookzDevSidecar_mint" in lean_source
    assert "Hookz.Contracts.Mint.expected" in lean_source
    assert "hasBlob := true" in lean_source
    assert "emittedCount := 1" in lean_source


def test_hook_local_checkpoint_surfaces_bad_config(tmp_path):
    source = tmp_path / "bad.c"
    source.write_text("int64_t hook(uint32_t reserved) { return 0; }")
    (tmp_path / "hookz.toml").write_text(
        """
[hooks.bad]
source = "bad.c"
status = "todo"
""",
        encoding="utf-8",
    )

    events = [
        {"kind": "u64", "name": "outgoing", "value": 0},
        {"kind": "u64", "name": "verdict_accept", "value": 1},
        {"kind": "check", "tag": "after_decision"},
    ]

    with pytest.raises(ConfigError, match="unknown keys: status"):
        render_dev_lean_checks(events, source_path=source)


@pytest.mark.skipif(not lean_available(), reason="lake not found")
def test_dispatches_dev_events_to_lean(tmp_path):
    events = [
        {"kind": "u64", "name": "before_count", "value": 40},
        {"kind": "u64", "name": "count", "value": 41},
        {"kind": "check", "tag": "state_counter.after_increment"},
    ]

    results = dispatch_dev_lean_checks(events, out_dir=tmp_path)

    assert len(results) == 1
    assert results[0].tag == "state_counter.after_increment"
    assert results[0].lean_file.exists()


@pytest.mark.skipif(not lean_available(), reason="lake not found")
def test_dispatch_keeps_repeated_witness_files(tmp_path):
    events = [
        {"kind": "u64", "name": "before_count", "value": 40},
        {"kind": "u64", "name": "count", "value": 41},
        {"kind": "check", "tag": "state_counter.after_increment"},
    ]

    first = dispatch_dev_lean_checks(events, out_dir=tmp_path)
    second = dispatch_dev_lean_checks(events, out_dir=tmp_path)

    assert first[0].lean_file.exists()
    assert second[0].lean_file.exists()
    assert first[0].lean_file != second[0].lean_file


def _balance_gate_runtime() -> HookRuntime:
    rt = HookRuntime()
    rt.hook_account = ALICE_ACCID
    rt.otxn_account = BOB_ACCID
    rt.otxn_type = hookapi.ttPAYMENT
    return rt


def _mint_runtime() -> HookRuntime:
    rt = HookRuntime()
    rt.hook_account = ALICE_ACCID
    rt.otxn_account = SENDER_ACCID
    rt.otxn_type = hookapi.ttINVOKE
    return rt


def _mint_blob_data() -> bytes:
    entry = (
        b"\xE0\x60"
        b"\x61"
        b"\x40\x00\x00\x00\x00\x0F\x42\x40"
        b"\x83\x14"
        + SENDER_ACCID
        + b"\xE1"
    )
    return b"\xF0\x60" + entry + b"\xF1"


@pytest.mark.skipif(WASI_SDK is None or not lean_available(), reason="wasi-sdk/lake not found")
def test_balance_gate_dev_checkpoint_dispatches_to_lean(tmp_path, monkeypatch):
    config = load_config(toml_path=HOOKZ_TOML)
    wasm = compile_hook_dev(BALANCE_GATE_SOURCE, config=config)
    hook = Hook(wasm=wasm, label=BALANCE_GATE_SOURCE.name, source=BALANCE_GATE_SOURCE)

    monkeypatch.setenv("HOOKZ_LEAN_DEV_DIR", str(tmp_path / "lean"))
    rt = _balance_gate_runtime()
    keylet, data = account_root(BOB, Balance="50000000")
    rt.ledger[keylet] = data

    result = rt.run(hook)

    assert result.accepted
    assert {"kind": "check", "tag": "after_decision", "line": None} in result.dev_events
    assert list((tmp_path / "lean").glob("*balance_gate_after_decision.lean"))
    assert list((tmp_path / "lean" / "_sidecars").glob("HookzDevSidecar_balance_gate.olean"))


@pytest.mark.skipif(WASI_SDK is None or not lean_available(), reason="wasi-sdk/lake not found")
def test_mint_dev_checkpoint_dispatches_to_lean(tmp_path, monkeypatch):
    config = load_config(toml_path=HOOKZ_TOML)
    wasm = compile_hook_dev(MINT_SOURCE, config=config)
    hook = Hook(wasm=wasm, label=MINT_SOURCE.name, source=MINT_SOURCE)

    monkeypatch.setenv("HOOKZ_LEAN_DEV_DIR", str(tmp_path / "lean"))

    missing_blob_rt = _mint_runtime()
    missing_blob = missing_blob_rt.run(hook)

    assert missing_blob.rejected
    assert {"kind": "check", "tag": "after_decision", "line": None} in missing_blob.dev_events

    with_blob_rt = _mint_runtime()
    with_blob_rt._slot_overrides[f"slot_subfield:1:{hookapi.sfBlob}"] = 2
    with_blob_rt._slot_overrides["slot_data:2"] = _mint_blob_data()
    with_blob = with_blob_rt.run(hook)

    assert with_blob.accepted
    assert len(with_blob_rt.emitted_txns) == 1
    assert {"kind": "check", "tag": "after_decision", "line": None} in with_blob.dev_events
    assert len(list((tmp_path / "lean").glob("*mint_after_decision*.lean"))) == 2
    assert list((tmp_path / "lean" / "_sidecars").glob("HookzDevSidecar_mint.olean"))
