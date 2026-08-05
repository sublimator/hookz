"""The external-env-tests branch pin.

The patch is vendored, so it can drift from what any module says about it
without anything failing. These are the checks that make that noisy: a
regenerated patch whose hash nobody updated, a file appearing in it with no
description, or a description of a file no longer in it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hookz import env_tests_ref as ref


class TestThePinDescribesTheVendoredPatch:
    def test_the_patch_is_where_the_module_looks(self):
        assert ref.patch_path().is_file(), ref.patch_path()

    def test_nothing_has_drifted(self):
        """Fails on a regenerated patch until env_tests_ref is updated.

        Deliberately noisy. A patch nobody can identify is worse than a stale
        one nobody has noticed, because the document still prints a branch,
        a commit and a hash beside it and they would all be wrong.
        """
        assert ref.check_pin() == []

    def test_the_registry_describes_every_file_in_the_patch(self):
        """Totality, not a spot check: an undescribed file renders in the
        manifest as a path with no explanation of what it is for."""
        in_patch = {p for p, _, _, _ in ref.files_in_patch()}

        assert in_patch == set(ref.FILES), {
            "undescribed": sorted(in_patch - set(ref.FILES)),
            "stale": sorted(set(ref.FILES) - in_patch),
        }

    def test_the_recorded_hash_is_the_file_on_disk(self):
        import hashlib

        actual = hashlib.sha256(ref.patch_path().read_bytes()).hexdigest()
        assert actual == ref.PATCH_SHA256


class TestReconstructingAnAddedFile:
    """The patch adds exactly one file outright, and that is the one worth
    handing to a reader as source rather than as a diff.
    """

    def test_the_harness_header_comes_back_as_the_file(self):
        text = ref.new_file(ref.HARNESS_HEADER)

        assert text is not None
        assert text.splitlines()[0] == "#ifndef TEST_JTX_TESTENV_H_INCLUDED"
        assert "class TestEnv : public Env" in text
        assert "TESTENV_LOGGING" in text
        # No diff markers survived the strip.
        assert not any(ln.startswith(("+", "-", "@@"))
                       for ln in text.splitlines())

    def test_it_matches_the_branch_byte_for_byte(self):
        """The evidence the pinned commit rests on.

        Skipped rather than failed when the checkout is absent: the pin is a
        claim about the patch, and the patch is vendored. A machine without
        that worktree cannot check the claim, but it has not broken it.
        """
        root = Path("/Users/nicholasdudfield/projects/xahaud-worktrees"
                    "/xahaud-external-env-tests-wd")
        if not (root / ref.HARNESS_HEADER).is_file():
            pytest.skip("no external-env-tests checkout on this machine")

        assert ref.check_branch(root) == []

    def test_a_modified_file_is_not_reconstructed(self):
        """Stripping `+` off a modified file's hunk yields the added lines
        with the surrounding code missing — something that reads like source
        and is not. Returning None is the honest answer.
        """
        modified = [p for p, _, _, is_new in ref.files_in_patch() if not is_new]
        assert modified, "premise: the patch modifies existing files"

        for path in modified:
            assert ref.new_file(path) is None, path

    def test_only_one_file_is_added_outright(self):
        """If the branch grows another, the section should offer it too —
        this is the reminder rather than a silent omission."""
        added = [p for p, _, _, is_new in ref.files_in_patch() if is_new]
        assert added == [ref.HARNESS_HEADER], added


class TestCheckBranch:
    def test_a_checkout_without_the_header_is_reported(self, tmp_path):
        findings = ref.check_branch(tmp_path)

        assert len(findings) == 1
        assert "does not carry" in findings[0]
        assert ref.BRANCH in findings[0]

    def test_a_modified_header_is_reported(self, tmp_path):
        header = tmp_path / ref.HARNESS_HEADER
        header.parent.mkdir(parents=True)
        header.write_text((ref.new_file(ref.HARNESS_HEADER) or "") + "// local\n")

        findings = ref.check_branch(tmp_path)

        assert len(findings) == 1
        assert "differs from the pinned" in findings[0]

    def test_a_matching_header_is_silent(self, tmp_path):
        header = tmp_path / ref.HARNESS_HEADER
        header.parent.mkdir(parents=True)
        header.write_text(ref.new_file(ref.HARNESS_HEADER) or "")

        assert ref.check_branch(tmp_path) == []


class TestItIsPinnedSeparatelyFromTheXahaudPort:
    def test_it_does_not_reuse_the_port_pin(self):
        """`xahaud_ref` pins a point on dev and says in as many words not to
        re-pin it to a feature branch. Sharing one commit between them is the
        mistake that module documents having already been made once."""
        from hookz.wasm import xahaud_ref

        assert ref.BRANCH_COMMIT != xahaud_ref.XAHAUD_COMMIT
        assert ref.BRANCH != xahaud_ref.XAHAUD_REF
