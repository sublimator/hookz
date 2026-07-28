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
        """fixGuardDepth32 is vetoed, so the nesting limit is 16, not 32."""
        from hookz.wasm.guard import MAX_NESTING, nesting_limit

        assert nesting_limit() == MAX_NESTING == 16

    def test_a_test_can_still_override(self):
        from hookz.runtime import HookRuntime

        rt = HookRuntime()
        rt.amendments.discard("fixFloatDivide")
        assert "fixFloatDivide" not in rt.amendments
        assert "fixFloatDivide" in HookRuntime().amendments, "not shared state"
