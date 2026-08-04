"""Tests for hookz.amendments — the set of amendments a test runs against.

An amendment changes what the network does, so the enabled set *is* the chain
a hook is tested on. The hand-curated list this replaced was wrong in both
directions at once — three amendments mainnet does not have, thirty-three it
does — and a curated list looks equally plausible whichever way it is wrong.
"""

import pytest

from hookz import amendments as amd


class TestNaming:
    """The manifest records what the network reports; hookz names things its
    own way. The mapping is derived from features.macro, not assumed."""

    def test_a_feature_gains_its_prefix(self):
        """xahaud registers XRPL_FEATURE(Hooks) as the bare name "Hooks"."""
        assert amd.to_symbol("Hooks") == "featureHooks"
        assert amd.to_symbol("ExpandedSignerList") == "featureExpandedSignerList"

    def test_a_fix_is_reported_already_prefixed(self):
        """XRPL_FIX(FloatDivide) registers as "fixFloatDivide"."""
        assert amd.to_symbol("fixFloatDivide") == "fixFloatDivide"

    def test_the_index_is_built_from_the_macro(self):
        index = amd.symbol_index()
        assert index, "features.macro is vendored, so this cannot be empty"
        assert index["Hooks"] == "featureHooks"
        assert index["fixFloatDivide"] == "fixFloatDivide"

    def test_an_unknown_name_falls_back_to_the_convention(self):
        """A node newer than the pin reports amendments the macro lacks.

        Dropping those silently would be worse than naming them by rule.
        """
        assert amd.to_symbol("SomethingNew2099") == "featureSomethingNew2099"
        assert amd.to_symbol("fixSomethingNew2099") == "fixSomethingNew2099"

    def test_layout_does_not_change_the_answer(self):
        """The regex this replaced demanded `(` immediately after the name.

        features.macro writes `XRPL_FIX    (Name` with alignment padding, so
        every fix went missing and the fallback rule silently covered for it.
        tree-sitter does not care where the whitespace is; this asserts that.
        """
        from hookz.amendments import _iter_macro_calls, _normalise
        import tree_sitter_c as tsc
        from tree_sitter import Language, Parser

        def names(text: str) -> set[str]:
            tree = Parser(Language(tsc.language())).parse(_normalise(text).encode())
            return {
                c.child_by_field_name("arguments").children[1].text.decode()
                for c in _iter_macro_calls(tree.root_node)
            }

        tight = ("XRPL_FEATURE(Alpha, Supported::yes, VoteBehavior::DefaultNo)\n"
                 "XRPL_FIX(Beta, Supported::yes, VoteBehavior::DefaultYes)\n")
        padded = ("XRPL_FEATURE (Alpha,   Supported::yes,  VoteBehavior::DefaultNo)\n"
                  "XRPL_FIX     (Beta,    Supported::yes,  VoteBehavior::DefaultYes)\n")
        assert names(tight) == names(padded) == {"Alpha", "Beta"}

    def test_retired_amendments_are_not_in_the_index(self):
        """XRPL_RETIRE names things that no longer exist."""
        index = amd.symbol_index()
        assert not any(k.startswith("retired") for k in index)

    def test_every_declared_macro_is_accounted_for(self):
        """Counts, so a parse that silently drops a category fails here.

        Counted a different way than the parser does it, on purpose — a
        cross-check that agrees with the implementation by construction checks
        nothing. Invocations start the line; `#if !defined(XRPL_FEATURE)` and
        its `#error` mention the name without being one, which is why a bare
        substring count says 108 for 104 amendments.
        """
        from hookz.wasm.xahaud_ref import vendored_root

        text = (vendored_root()
                / "include/xrpl/protocol/detail/features.macro").read_text()
        declared = sum(
            1 for line in text.splitlines()
            if line.startswith(("XRPL_FEATURE", "XRPL_FIX"))
        )
        assert declared == 104, "the vendored macro changed; re-check the index"
        assert len(amd.symbol_index()) == declared

    def test_no_feature_is_named_like_a_fix(self):
        """The fallback rule assumes this; the macro is where it is true."""
        for reported, symbol in amd.symbol_index().items():
            if reported.startswith("fix"):
                assert symbol == reported, reported
            else:
                assert symbol == f"feature{reported}", reported


class TestManifest:
    def test_mainnet_is_vendored(self):
        assert amd.manifest("mainnet")

    def test_it_carries_its_own_provenance(self):
        m = amd.manifest("mainnet")
        assert m["network_id"] == 21337
        assert m["ledger_seq"] > 0
        assert m["queried_at"]

    def test_provenance_reads_as_a_sentence(self):
        line = amd.provenance("mainnet")
        assert "mainnet" in line and "ledger" in line

    def test_an_absent_network_is_empty_not_an_error(self):
        assert amd.manifest("no-such-net") == {}
        assert amd.enabled_on("no-such-net") == set()
        assert "no manifest" in amd.provenance("no-such-net")


class TestTheDefaultSet:
    """What a HookRuntime runs on, unless a test says otherwise."""

    def test_defaults_come_from_the_manifest(self):
        from hookz.runtime import HookRuntime

        assert HookRuntime().amendments == amd.enabled_on("mainnet")

    @pytest.mark.parametrize("name", [
        "featureHooks",
        "featureExpandedSignerList",   # was missing: refused 9-signer lists
        "fixFloatDivide",              # changes division results
        "featureHookCanEmit",
    ])
    def test_mainnet_amendments_are_enabled(self, name):
        from hookz.runtime import HookRuntime

        assert name in HookRuntime().amendments

    @pytest.mark.parametrize("name", [
        "featureHookAPISerializedType240",  # vetoed on mainnet
        "featureHooksUpdate2",              # vetoed on mainnet
        "fixGuardDepth32",                  # vetoed — the nesting limit is 16
    ])
    def test_amendments_mainnet_lacks_are_not_enabled(self, name):
        """Enabling one of these tests a network nobody is running."""
        from hookz.runtime import HookRuntime

        assert name not in HookRuntime().amendments

    def test_the_guard_depth_limit_follows_from_that(self):
        """fixGuardDepth32 is vetoed, so the nesting limit is 16, not 32.

        This used to assert `nesting_limit() == 16` and call that a
        consequence. It was not one: the 16 came from a `rules_version=0`
        default, so the day mainnet voted the amendment in, the test would
        still have passed and hookz would still have said 16 — wrongly. The
        limit has to move when the manifest does, which is what is asserted
        here.
        """
        import hookz.amendments as amd
        from hookz.wasm.guard import (
            MAX_NESTING, MAX_NESTING_DEPTH32, nesting_limit,
        )

        assert "fixGuardDepth32" not in amd.enabled_on("mainnet")
        assert nesting_limit() == MAX_NESTING == 16

        # and it is a consequence: same code, a network that has it
        assert nesting_limit(amd.GUARD_RULE_AMENDMENTS[1][1]) == \
            MAX_NESTING_DEPTH32 == 32

    def test_the_rules_version_is_derived_from_the_manifest(self):
        """Not a constant. xahaud recomputes it per-ledger from the amendments
        in force (xahaud:include/xrpl/hook/Enum.h:451)."""
        import hookz.amendments as amd
        from hookz.wasm.guard import (
            GUARD_RULE_DEPTH_32, GUARD_RULE_FIX_20250131,
        )

        enabled = amd.enabled_on("mainnet")
        version = amd.guard_rules_version("mainnet")

        assert bool(version & GUARD_RULE_FIX_20250131) == \
            ("fix20250131" in enabled)
        assert bool(version & GUARD_RULE_DEPTH_32) == \
            ("fixGuardDepth32" in enabled)

    def test_the_rules_follow_the_manifest_rather_than_a_constant(
        self, monkeypatch
    ):
        """mainnet runs 0x01, so hardcoding 0x01 passes every test that only
        ever looks at mainnet. That is precisely how the constant survived.
        The question is whether the answer MOVES.
        """
        import hookz.amendments as amd
        from hookz.wasm.guard import nesting_limit, resolve_rules

        monkeypatch.setattr(
            amd, "enabled_on",
            lambda network=amd.DEFAULT_NETWORK: {"fix20250131",
                                                 "fixGuardDepth32"},
        )
        assert resolve_rules(None) == 0x03
        assert nesting_limit(None) == 32

        monkeypatch.setattr(
            amd, "enabled_on", lambda network=amd.DEFAULT_NETWORK: set()
        )
        assert resolve_rules(None) == 0x00
        assert nesting_limit(None) == 16

    def test_an_unreadable_manifest_falls_back_to_the_stricter_reading(
        self, monkeypatch
    ):
        """Refusing a hook the network would accept is a visible failure.
        Accepting one it would reject is not."""
        import hookz.amendments as amd
        from hookz.wasm.guard import nesting_limit, resolve_rules

        def boom(*a, **k):
            raise RuntimeError("no manifest vendored")

        monkeypatch.setattr(amd, "enabled_on", boom)

        assert resolve_rules(None) == 0
        assert nesting_limit(None) == 16

    def test_an_explicit_rules_version_still_wins(self):
        """Asking what a hook would do under other rules is legitimate."""
        from hookz.wasm.guard import GUARD_RULE_DEPTH_32, resolve_rules

        assert resolve_rules(0) == 0
        assert resolve_rules(GUARD_RULE_DEPTH_32) == GUARD_RULE_DEPTH_32

    def test_the_bit_values_are_upstreams(self):
        """The bits are a wire format shared with xahaud, not our numbering."""
        import hookz.amendments as amd
        from hookz.wasm.guard import (
            GUARD_RULE_DEPTH_32, GUARD_RULE_FIX_20250131,
        )

        assert dict(amd.GUARD_RULE_AMENDMENTS) == {
            "fix20250131": GUARD_RULE_FIX_20250131,
            "fixGuardDepth32": GUARD_RULE_DEPTH_32,
        }

    def test_every_guard_rule_amendment_is_a_real_one(self):
        """A typo here would silently clear a bit forever: the name would
        never appear in any manifest, so the rule would never be in force."""
        import hookz.amendments as amd

        known = set(amd.symbol_index())
        for name, _ in amd.GUARD_RULE_AMENDMENTS:
            assert name in known, f"{name} is not in features.macro"

    def test_the_strict_and_best_effort_paths_agree_on_the_rules(self):
        """validate_guards defaulted to fix20250131 set and
        validate_guards_module to nothing set, so the same bytes got different
        verdicts about whether memory.copy is legal."""
        import inspect

        from hookz.wasm import guard

        defaults = {
            fn: inspect.signature(getattr(guard, fn))
            .parameters["rules_version"].default
            for fn in ("validate_guards", "validate_guards_module",
                       "analyze_wce", "analyze_wce_module", "nesting_limit")
        }
        assert set(defaults.values()) == {None}, defaults

    def test_a_test_can_still_override(self):
        from hookz.runtime import HookRuntime

        rt = HookRuntime()
        rt.amendments.discard("fixFloatDivide")
        assert "fixFloatDivide" not in rt.amendments
        assert "fixFloatDivide" in HookRuntime().amendments, "not shared state"
