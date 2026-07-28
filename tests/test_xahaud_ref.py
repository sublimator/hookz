"""Tests for the xahaud provenance pin and its citation system.

A citation that cannot be checked is a comment. These pin the property that
makes `xahaud:path:line` worth writing: it resolves to a file hookz ships, at
a line that exists, at the commit the port was made against.
"""

from pathlib import Path

import pytest

from hookz.wasm import xahaud_ref as ref

SRC = Path(ref.__file__).parent.parent


class TestCitations:
    def test_every_citation_in_the_port_resolves(self):
        """Cite a file hookz has not vendored and this fails until it does.

        That is the whole enforcement mechanism — it is how SetSignerList.cpp
        came to be vendored.
        """
        assert ref.check_citations(SRC) == []

    def test_a_citation_reads_the_line_it_names(self):
        c = ref.cite("src/xrpld/app/tx/detail/SetSignerList.cpp", 325)
        assert "allSignersWeight < quorum" in c.snippet()

    def test_the_emit_preflight_citation_is_the_preflight_call(self):
        """emission.py's central claim: emit() preflights."""
        c = ref.cite("src/xrpld/app/hook/detail/HookAPI.cpp", 794)
        assert "ripple::preflight" in c.snippet()

    def test_a_citation_builds_a_permalink_at_the_pin(self):
        c = ref.cite("src/xrpld/app/hook/detail/HookAPI.cpp", 794)
        assert ref.XAHAUD_COMMIT in c.url
        assert c.url.endswith("HookAPI.cpp#L794")

    def test_parsing_finds_citations_in_text(self):
        found = ref.parse_citations(
            "see xahaud:include/xrpl/hook/Guard.h:293 and nothing else")
        assert [str(c) for c in found] == ["xahaud:include/xrpl/hook/Guard.h:293"]

    def test_an_unvendored_file_is_reported(self, tmp_path):
        (tmp_path / "m.py").write_text("# xahaud:src/nope/Missing.cpp:1\n")
        problems = ref.check_citations(tmp_path)
        assert problems and "not vendored" in problems[0]

    def test_a_line_past_the_end_is_reported(self, tmp_path):
        (tmp_path / "m.py").write_text(
            "# xahaud:include/xrpl/hook/Guard.h:999999\n")
        problems = ref.check_citations(tmp_path)
        assert problems and "outside" in problems[0]


class TestVendoredTree:
    @pytest.mark.parametrize("rel", ref.PORTED_FILES + ref.CITED_FILES)
    def test_every_declared_file_is_actually_vendored(self, rel):
        assert (ref.vendored_root() / rel).exists(), rel

    def test_ported_and_cited_do_not_overlap(self):
        """Different meanings: one tracks behaviour, the other tracks lines."""
        assert not set(ref.PORTED_FILES) & set(ref.CITED_FILES)


class TestCheckoutPinning:
    """Declaring a commit is optional, and the choice changes the semantics."""

    def test_no_declared_commit_asserts_nothing(self):
        import dataclasses
        from hookz.config import load_config
        cfg = dataclasses.replace(load_config(), xahaud_commit=None)
        assert not cfg.xahaud_pinned
        assert ref.check_checkout(cfg) == []

    def test_a_matching_declared_commit_passes(self):
        import dataclasses
        from hookz.config import load_config
        cfg = dataclasses.replace(load_config(), xahaud_commit=ref.XAHAUD_COMMIT)
        if ref.checkout_commit(cfg.xahaud_root) is None:
            pytest.skip("configured xahaud_root is not a git checkout")
        assert ref.check_checkout(cfg) == []

    def test_a_mismatched_declared_commit_is_an_error(self):
        """A revision that resolves, to something else."""
        import dataclasses
        from hookz.config import load_config
        cfg = dataclasses.replace(load_config(), xahaud_commit="HEAD~2")
        if ref.checkout_commit(cfg.xahaud_root) is None:
            pytest.skip("configured xahaud_root is not a git checkout")
        problems = ref.check_checkout(cfg)
        assert problems and "declares" in problems[0]

    def test_an_unresolvable_commit_is_a_different_error(self):
        """Distinguished from a mismatch: one is a typo, the other is drift."""
        import dataclasses
        from hookz.config import load_config
        cfg = dataclasses.replace(load_config(), xahaud_commit="0" * 40)
        if ref.checkout_commit(cfg.xahaud_root) is None:
            pytest.skip("configured xahaud_root is not a git checkout")
        problems = ref.check_checkout(cfg)
        assert problems and "does not name a commit" in problems[0]

    def test_drift_is_advisory_when_unpinned(self, tmp_path):
        """A developer's checkout may sit anywhere; that is not a failure."""
        (tmp_path / "m.py").write_text(
            "# xahaud:include/xrpl/hook/Guard.h:1\n")
        stale = tmp_path / "fake_xahaud" / "include" / "xrpl" / "hook"
        stale.mkdir(parents=True)
        (stale / "Guard.h").write_text("something else entirely\n")
        # opt-in: comparing against a working tree is a deliberate query,
        # not something a routine check should trip over
        assert ref.check_citations(tmp_path, xahaud_root=tmp_path / "fake_xahaud") == []
        problems = ref.check_citations(tmp_path, xahaud_root=tmp_path / "fake_xahaud",
                                       compare_upstream=True)
        assert problems and problems[0].startswith("drift: ")


class TestVendorCheckIsUnambiguous:
    """`[]` used to mean both "all clean" and "nothing checked"."""

    def test_a_real_checkout_verifies_files(self):
        from hookz.config import load_config
        v = ref.verify_vendored(load_config().xahaud_root)
        if not v.verified and not v.problems:
            pytest.skip("configured checkout does not contain the pin")
        assert v.ok and v.verified

    def test_the_vendored_tree_cannot_verify_itself(self):
        """Config falls back to it, and it lives inside hookz's own repo — so
        `git show` there answers about hookz, not xahaud."""
        v = ref.verify_vendored(ref.vendored_root())
        assert not v.ok
        assert not v.verified
        assert "cannot verify itself" in v.reason

    def test_a_checkout_without_the_pin_says_so(self, tmp_path):
        v = ref.verify_vendored(tmp_path)
        assert not v.ok and not v.verified and v.reason

    def test_falsiness_tracks_ok_not_emptiness(self):
        assert not ref.verify_vendored("/nonexistent-path")


class TestCommitResolution:
    """A revision names a commit; a string is not the comparison."""

    @pytest.fixture
    def cfg(self):
        from hookz.config import load_config
        c = load_config()
        if ref.checkout_commit(c.xahaud_root) is None:
            pytest.skip("configured xahaud_root is not a git checkout")
        return c

    @pytest.mark.parametrize("rev_of", [
        lambda: ref.XAHAUD_COMMIT,          # full sha
        lambda: ref.XAHAUD_COMMIT[:12],     # short sha
    ])
    def test_any_spelling_of_the_right_commit_passes(self, cfg, rev_of):
        import dataclasses
        assert ref.check_checkout(
            dataclasses.replace(cfg, xahaud_commit=rev_of())) == []

    def test_a_revision_that_names_nothing_is_reported(self, cfg):
        import dataclasses
        problems = ref.check_checkout(
            dataclasses.replace(cfg, xahaud_commit="not-a-revision"))
        assert problems and "does not name a commit" in problems[0]

    def test_a_different_commit_is_still_caught(self, cfg):
        import dataclasses
        problems = ref.check_checkout(
            dataclasses.replace(cfg, xahaud_commit="HEAD~1"))
        assert problems and "is at" in problems[0]

    def test_resolve_commit_returns_a_full_sha(self, cfg):
        got = ref.resolve_commit(cfg.xahaud_root, ref.XAHAUD_COMMIT[:12])
        assert got == ref.XAHAUD_COMMIT
