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


class TestCheckPinIsTheFunctionTheDocumentAsks:
    """The totality property was tested against `files_in_patch()` and `FILES`
    directly, never through `check_pin()` — which is what `_patch_section`
    actually calls to decide whether to print the drift banner.

    So `check_pin()` could stop reporting undescribed files entirely and the
    document would render `_not described in env_tests_ref.FILES_` rows with
    no banner above them, suite green. Testing a property against the data
    instead of against the function that reports it is the same gap one level
    down.
    """

    def test_it_reports_a_file_with_no_description(self, monkeypatch):
        trimmed = dict(ref.FILES)
        dropped = trimmed.pop("src/libxrpl/basics/Log.cpp")
        assert dropped
        monkeypatch.setattr(ref, "FILES", trimmed)

        findings = ref.check_pin()

        assert any("src/libxrpl/basics/Log.cpp" in f and "no entry" in f
                   for f in findings), findings

    def test_it_reports_a_description_of_a_file_that_is_gone(self, monkeypatch):
        monkeypatch.setattr(
            ref, "FILES", {**ref.FILES, "src/never/existed.cpp": "invented"})

        findings = ref.check_pin()

        assert any("src/never/existed.cpp" in f and "not in the patch" in f
                   for f in findings), findings

    def test_it_reports_a_hash_that_does_not_match(self, monkeypatch):
        monkeypatch.setattr(ref, "PATCH_SHA256", "0" * 64)

        findings = ref.check_pin()

        assert any("sha256" in f for f in findings), findings

    def test_a_clean_registry_reports_nothing(self):
        assert ref.check_pin() == []


class TestTheChurnNumbersAreReal:
    """`+142` and `+114` are what tell a reader the manifest is hiding
    something substantial, and nothing asserted them: swapping the added and
    removed columns, or replacing the whole column with a dash, left the suite
    green.
    """

    def test_the_counts_match_git(self):
        """Against `git apply --numstat`, which is the authority on a diff."""
        import subprocess

        out = subprocess.run(
            ["git", "apply", "--numstat", str(ref.patch_path())],
            capture_output=True, text=True,
            cwd=Path(__file__).parents[1])
        if out.returncode != 0:
            pytest.skip(f"git apply --numstat unavailable: {out.stderr[:80]}")

        expected = {}
        for line in out.stdout.splitlines():
            added, removed, path = line.split("\t")
            expected[path] = (int(added), int(removed))

        actual = {p: (a, r) for p, a, r, _ in ref.files_in_patch()}
        assert actual == expected

    def test_added_and_removed_are_not_interchangeable(self):
        """A swap is invisible on a file with equal counts, so pin one where
        they differ sharply."""
        rows = {p: (a, r) for p, a, r, _ in ref.files_in_patch()}

        assert rows["src/xrpld/app/hook/applyHook.h"] == (142, 0)
        assert rows["include/xrpl/hook/Guard.h"] == (42, 12)


class TestEachDescriptionIsBoundToTheHunkItWasReadAgainst:
    """Correctness of a description cannot be machine-checked — two reviewers
    independently tried and both rules were anti-correlated with quality,
    because a good description of a small hunk has to reach outside it: to the
    enclosing class, to the macro that supplies a symbol, to the thing the
    change is *not*.

    What can be checked is whether the hunk still says what it said when
    someone read it. `PATCH_SHA256` fires on any regeneration as one
    undifferentiated event, which in practice gets bumped; these say which
    files moved, so the re-read after a dev merge is proportionate.
    """

    def test_every_described_file_has_a_pinned_digest(self):
        assert set(ref.FILE_DIGESTS) == set(ref.FILES)

    def test_the_pinned_digests_match_the_patch(self):
        assert ref.file_digests() == ref.FILE_DIGESTS

    def test_a_moved_hunk_names_itself(self, monkeypatch):
        monkeypatch.setattr(
            ref, "FILE_DIGESTS",
            {**ref.FILE_DIGESTS, "include/xrpl/hook/Macro.h": "0" * 64})

        findings = ref.check_pin()

        assert any("include/xrpl/hook/Macro.h" in f and "hunk changed" in f
                   for f in findings), findings
        # Only the one that moved.
        assert len([f for f in findings if "hunk changed" in f]) == 1

    def test_the_digests_are_per_file_not_one_hash(self):
        """A single digest repeated for every file would satisfy the two
        tests above and lose the whole point."""
        assert len(set(ref.FILE_DIGESTS.values())) == len(ref.FILE_DIGESTS)
