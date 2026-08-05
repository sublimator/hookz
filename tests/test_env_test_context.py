"""`hookz env-test-context` — the document an agent writes an env test from.

The value of the command is entirely in what the document asserts, so these
test the assertions rather than the formatting: that a name it prints is one
the hook really imports, that a section it omits does not leave a hole in the
numbering, and that the places it cannot know something say so instead of
printing a plausible default.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

WASM = Path(__file__).parent / "e2e/hooks/genesis/govern.wasm"


def _config(root):
    """Enough of Config for a wasm-input run: only xahaud_root is read."""
    return SimpleNamespace(xahaud_root=Path(root))


def _doc(root, **kw):
    from hookz.cli.env_test_context import build_context

    kw.setdefault("include_impl", False)
    kw.setdefault("include_patch", False)
    return build_context(WASM, _config(root), **kw)


@pytest.fixture
def checkout(tmp_path):
    """A directory stand-in for a xahaud checkout, without TestEnv.h."""
    (tmp_path / "src/test/jtx").mkdir(parents=True)
    return tmp_path


class TestItRefusesRatherThanQuietlyUnderdelivering:
    """The vendored xahaud_lite tree satisfies every other command.

    It has no src/test/jtx, so falling back to it would produce a document
    that looks complete and silently omits the harness half — the half this
    command exists to supply.
    """

    def test_the_vendored_tree_is_refused_by_name(self):
        from hookz.cli.env_test_context import ContextError, build_context
        from hookz.xahaud_files import _vendored_root

        with pytest.raises(ContextError) as e:
            build_context(WASM, _config(_vendored_root()), include_patch=False)

        assert "xahaud_lite" in str(e.value)
        assert "src/test/jtx" in str(e.value)

    def test_the_refusal_names_both_ways_to_fix_it(self):
        """A path that exits without saying what to do next is the failure
        mode this repo keeps removing elsewhere."""
        from hookz.cli.env_test_context import ContextError, build_context

        with pytest.raises(ContextError) as e:
            build_context(WASM, _config(Path("/nonexistent-xahaud")),
                          include_patch=False)

        assert "hookz.toml" in str(e.value)
        assert "HOOKZ_XAHAUD" in str(e.value)

    def test_a_checkout_without_the_branch_is_a_note_not_a_refusal(
        self, checkout
    ):
        """Plain `dev` has every file the hook-API sections read. Only the
        skeleton needs the branch, so the document is still worth having.

        The remediation assertion used to read `"git apply" in doc or "apply"
        in doc`, which cannot fail: the left side is always False (the command
        is `git -C <root> apply <patch>`) and the right side always True (the
        harness section mentions `applyHook.h`). It asserted nothing about the
        one thing it is named for.
        """
        doc = _doc(checkout)

        assert "does not carry the env-tests harness" in doc

        line = next(ln for ln in doc.splitlines() if " apply " in ln)
        assert str(checkout) in line, line
        assert line.rstrip().endswith(".patch"), line

    def test_a_checkout_with_the_branch_says_nothing_about_it(self, checkout):
        (checkout / "src/test/jtx/TestEnv.h").write_text("// stub\n")

        assert "does not carry the env-tests harness" not in _doc(checkout)


class TestTheSurfaceIsTheHooksOwn:
    def test_every_named_function_is_really_imported(self, checkout):
        """Guards against a table built from the whitelist rather than the
        binary — which would list the whole API for every hook."""
        from hookz.cli.env_test_context import _imports

        imported = {n for _, n, _, _ in _imports(WASM.read_bytes())}
        doc = _doc(checkout)

        table = [ln for ln in doc.splitlines() if ln.startswith("| `")]
        named = {re.match(r"\| `([^`]+)`", ln).group(1) for ln in table}

        assert named == imported

    def test_an_import_outside_the_whitelist_is_called_out(
        self, checkout, monkeypatch
    ):
        """xahaud refuses the hook outright, so the test can never run. That
        has to be louder than one more row in a table.

        Driven by shrinking the whitelist rather than by finding a hook with a
        bad import: govern.wasm is a real deployed hook and every import it
        has is allowed, so on today's data the branch is unreachable and any
        assertion about it would pass without ever rendering.
        """
        import hookz.wasm.whitelist as wl

        original = wl.get_import_signatures
        monkeypatch.setattr(
            wl, "get_import_signatures",
            lambda **k: {n: s for n, s in original(**k).items() if n != "emit"})

        doc = _doc(checkout)

        assert "in no version of the API whitelist" in doc
        assert "> - `env.emit`" in doc, "the offending import is named"

    def test_the_control_flow_calls_get_a_family(self, checkout):
        """accept and rollback decide the ter() the test asserts on, and fell
        through to no family at all because they carry no prefix."""
        doc = _doc(checkout)

        for name in ("accept", "rollback"):
            row = next(ln for ln in doc.splitlines()
                       if ln.startswith(f"| `{name}`"))
            assert "hook outcome" in row, row

    def test_slot_itself_is_grouped_with_the_slot_calls(self, checkout):
        """`slot` has no underscore, so a `slot_` prefix missed it."""
        row = next(ln for ln in _doc(checkout).splitlines()
                   if ln.startswith("| `slot`"))
        assert "slots" in row


class TestItSaysWhatItCannotKnow:
    def test_a_wasm_input_explains_what_source_would_have_added(
        self, checkout
    ):
        """Call-site attribution comes from instrumentation markers. A built
        artifact has none, and nothing can put the line numbers back — so the
        document says which input gets them rather than just omitting them.
        """
        doc = _doc(checkout)

        note = next(ln for ln in doc.splitlines()
                    if "no instrumentation markers" in ln)
        # `assert ".c" in doc` was the first version — always true, since the
        # map key in the skeleton is `file:<domain>/govern.c`.
        assert "`.c`" in note, note
        assert "## 3. Where it calls them" not in doc

    def test_omitted_sections_do_not_leave_a_hole_in_the_numbering(
        self, checkout
    ):
        """The headings were numbered by hand, so --no-impl --no-patch
        produced 1, 2, 5, 6 and a reader looking for section 3 found nothing.
        """
        for kw in ({}, {"include_impl": True}, {"include_patch": True}):
            doc = _doc(checkout, **kw)
            numbers = [int(m.group(1)) for m in
                       re.finditer(r"^## (\d+)\. ", doc, re.M)]
            assert numbers == list(range(1, len(numbers) + 1)), (kw, numbers)

    def test_a_filtered_call_does_not_report_zero_call_sites(self):
        """`_g` is filtered out of the listing and is called constantly, so a
        count of 0 would be a claim the listing never made.

        Against `_surface_section` rather than a document, because the count
        column only exists when the input was source — a .wasm run renders no
        column at all, and an assertion on a document built from one passes
        without the branch ever running.
        """
        from hookz.cli.env_test_context import _surface_section
        from hookz.wasm.whitelist import (
            get_function_signatures, get_import_signatures)

        imports = [("env", "_g", (0x7F, 0x7F), (0x7F,)),
                   ("env", "state_set", (0x7F,) * 4, (0x7E,))]
        lines = _surface_section(
            imports, get_function_signatures(),
            get_import_signatures(coverage=True), {"state_set": 3})

        guard = next(ln for ln in lines if ln.startswith("| `_g`"))
        assert "| 0 |" not in guard, guard
        assert "n/a" in guard

        counted = next(ln for ln in lines if ln.startswith("| `state_set`"))
        assert counted.rstrip().endswith("| 3 |"), counted


class TestTheHarnessSectionMatchesAWorkingTest:
    """Every symbol here is copied from examples/tipbot/env-tests, which
    compiles and runs. Reconstructing them from the headers is how the first
    draft got `HOOK_WASM` defined by the generated header — it is not.
    """

    def test_the_generated_symbol_follows_build_test_hooks(self, checkout):
        """build_test_hooks.py:544 — symbol_name is f"{stem.lower()}_wasm"
        for the *test file's* stem, so Govern_test.cpp gives govern_test_wasm.
        """
        doc = _doc(checkout)

        assert "govern_test_wasm" in doc
        assert "Govern_test_hooks.h" in doc

    def test_the_includes_are_the_ones_a_working_test_uses(self, checkout):
        """<xrpld/...>, not the <ripple/...> spelling that predates the
        rename and does not resolve."""
        doc = _doc(checkout)

        assert "<xrpld/app/hook/applyHook.h>" in doc
        assert "<ripple/app/hook/applyHook.h>" not in doc

    def test_every_macro_it_uses_it_also_defines(self, checkout):
        """The skeleton shipped using `HSFEE` and `M(...)` without them.

        Both are per-test-file `#define`s in xahaud — no header declares them,
        and `-DHOOKS_TEST_ONLY=ON`, which this document tells you to pass,
        excludes the `src/test/*_test.cpp` files that do. So the one artifact
        an agent pastes verbatim failed on two undeclared identifiers.

        The sibling tests here spot-check symbols that happened to be
        remembered, which is why a partial copy passed all four of them.

        The first version of this test scanned the skeleton for uppercase
        identifiers followed by `(`, and saw neither offender: `HSFEE` is used
        as a bare `HSFEE,` and `M` is one character. A filter that excludes
        the interesting cases is how several of these got through, so the
        oracle is the reference file rather than a pattern guessed at from the
        offenders already known.
        """
        from hookz.cli.env_test_context import _SKELETON

        reference = (Path(__file__).parents[1]
                     / "examples/tipbot/env-tests/TipBot_test.cpp").read_text()
        per_file_macros = set(re.findall(r"^#define (\w+)", reference, re.M))
        assert {"HSFEE", "M", "BEAST_REQUIRE"} <= per_file_macros, (
            "premise: the reference test defines these itself")

        body = _SKELETON.format(header="H.h", symbol="s", suite="S", name="n")
        defined = set(re.findall(r"^#define (\w+)", body, re.M))

        borrowed = {m for m in per_file_macros
                    if re.search(rf"\b{re.escape(m)}\b", body)}
        assert borrowed - defined == set(), (
            "uses xahaud per-test-file macros without defining them: "
            + ", ".join(sorted(borrowed - defined)))

    def test_the_map_key_placeholder_is_not_a_guessable_default(
        self, checkout
    ):
        """The key is file:<domain>/<file>.c and <domain> comes from the
        caller's -DHOOKS_C_DIR. Printing a made-up domain would compile into
        a map lookup that silently returns an empty vector."""
        doc = _doc(checkout)

        assert "file:<domain>/govern.c" in doc
        assert "HOOKS_C_DIR" in doc


class TestTheDocumentDoesNotOverclaim:
    """Each of these is a sentence the document printed regardless of whether
    it was true — the failure mode the whole feature exists to avoid, since an
    agent has no way to check.
    """

    def test_the_family_table_covers_every_function_in_the_whitelist(self):
        """Three fell through to no family at all — `meta_slot` and
        `xpop_slot` (a `slot` *prefix* misses a `slot` suffix) and `fee_base`.

        Asserting the two cases someone already thought of is what let the
        next three through: `accept`/`rollback` and bare `slot` each got a
        test, and nothing asserted the table was total.
        """
        from hookz.cli.env_test_context import _family
        from hookz.wasm.whitelist import get_function_signatures

        # get_function_signatures, not get_import_signatures: the latter is
        # amendment-filtered against the mainnet manifest, so it excluded
        # `prepare` — which was the one function still without a family. A
        # totality test whose filter hides the untotal case is the shape this
        # file keeps finding.
        unfamilied = sorted(n for n in get_function_signatures()
                            if not _family(n)[0])
        assert unfamilied == [], unfamilied

    def test_no_family_pattern_is_dead(self):
        """`keylet_` matched nothing — the API is `util_keylet`, already
        caught by `util_`. A pattern matching nothing is a claim about the API
        that stopped being true, or never was."""
        from fnmatch import fnmatchcase

        from hookz.cli.env_test_context import _FAMILIES
        from hookz.wasm.whitelist import get_function_signatures

        # Every function the API defines, not the mainnet-enabled subset —
        # `prepare` is gated out of the latter, so its pattern read as dead.
        names = list(get_function_signatures())
        dead = [p for patterns, _, _ in _FAMILIES for p in patterns
                if not any(fnmatchcase(n, p) for n in names)]
        assert dead == [], dead

    def test_no_impl_does_not_promise_implementations(self, checkout):
        """The surface section said "the implementations are quoted below"
        unconditionally, and the docs recommend --no-impl for context size."""
        with_impl = _doc(checkout, include_impl=True)
        without = _doc(checkout, include_impl=False)

        assert "implementations are quoted below" in with_impl
        assert "implementations are quoted below" not in without
        assert "--no-impl" in without

    def test_a_directory_that_is_not_a_checkout_says_so(self, checkout):
        """`checkout` exists and has src/test/jtx, so it passes the refusal —
        but nothing in it is xahaud, and every lookup returns None. That
        rendered a heading per function with no code under it and no
        explanation: the "looks complete, silently omits" shape one level
        down from the one the refusal prevents.
        """
        doc = _doc(checkout, include_impl=True)

        assert "Nothing was found for any function" in doc
        assert doc.count("_Not found in this checkout._") >= 20

    def test_the_vendored_patch_is_reachable_where_it_is_installed(self):
        """`patches/` lives outside `src/hookz`, so a wheel gets it only via
        the force-include in pyproject. Without that the command degraded to
        "could not read ..." on every non-source install."""
        import tomllib

        from hookz.cli.env_test_context import PATCH_NAME, _default_patch

        assert _default_patch(None).is_file(), _default_patch(None)

        pyproject = Path(__file__).parents[1] / "pyproject.toml"
        cfg = tomllib.loads(pyproject.read_text())
        forced = (cfg["tool"]["hatch"]["build"]["targets"]["wheel"]
                  ["force-include"])
        assert f"patches/{PATCH_NAME}" in forced
        assert forced[f"patches/{PATCH_NAME}"].endswith(PATCH_NAME)


class TestTheBranchSectionIsPiecesNotADiff:
    """Inlining the whole patch was half the document, and most of it is
    context lines around one-line edits that a reader has to decode.
    """

    def test_the_harness_header_is_inlined_as_source(self, checkout):
        from hookz import env_tests_ref as ref

        doc = _doc(checkout, include_patch=True)

        assert "class TestEnv : public Env" in doc
        assert "#ifndef TEST_JTX_TESTENV_H_INCLUDED" in doc
        # As C++, not as a diff of C++.
        assert "```cpp" in doc
        assert f"### `{ref.HARNESS_HEADER}`" in doc

    def test_the_full_diff_is_not_there_by_default(self, checkout):
        default = _doc(checkout, include_patch=True)
        full = _doc(checkout, include_patch=True, full_patch=True)

        assert "```diff" not in default
        assert "--full-patch" in default
        assert "```diff" in full
        assert len(full) > len(default)

    def test_every_file_in_the_patch_is_accounted_for(self, checkout):
        """The manifest replaces the diff, so anything it omits is a change
        the reader now has no way to learn about."""
        from hookz import env_tests_ref as ref

        doc = _doc(checkout, include_patch=True)

        for path, _, _, _ in ref.files_in_patch():
            assert f"`{path}`" in doc, path
            assert ref.FILES[path] in doc, path

    def test_the_pin_is_stated_so_it_can_be_checked(self, checkout):
        from hookz import env_tests_ref as ref

        doc = _doc(checkout, include_patch=True)

        assert ref.PATCH_SHA256 in doc
        assert ref.BRANCH in doc
        assert ref.BRANCH_COMMIT[:12] in doc

    def test_a_drifted_patch_says_so_rather_than_printing_a_wrong_pin(
        self, checkout, monkeypatch
    ):
        """Everything rendered is read from the patch on disk, so it stays
        accurate — but the branch, commit and hash beside it would not be."""
        from hookz import env_tests_ref as ref

        monkeypatch.setattr(ref, "PATCH_SHA256", "0" * 64)
        doc = _doc(checkout, include_patch=True)

        assert "does not match its pin" in doc


class TestTheSkeletonStatesWhatFailsSilently:
    def test_it_names_the_file_cmake_globs_for(self, checkout):
        """CMake globs `${HOOKS_TEST_DIR}/*_test.cpp` and derives the header
        name from the stem, so a file named anything else is skipped with no
        warning and the build succeeds without the test."""
        doc = _doc(checkout)

        assert "env-tests/Govern_test.cpp" in doc
        assert "_test.cpp" in doc

    def test_it_wires_up_coverage_rather_than_implying_xahaud_does(
        self, checkout
    ):
        """`HOOKS_COVERAGE_DIR` is read by nothing in the branch — it is a
        convention the test file implements. The document told a reader to set
        it and emitted a `run()` with no dump, so the hits accumulated and were
        dropped at exit with no error.

        Asserted against `_SKELETON` rather than the document. The bullet
        explaining the problem names all three calls, so `"coverageReset" in
        doc` passes with the wiring deleted — the assertion matched the prose
        about the fix instead of the fix.
        """
        from hookz.cli.env_test_context import _SKELETON

        body = _SKELETON.format(header="H.h", symbol="s", suite="S", name="n")
        for call in ("coverageReset", "coverageLabel", "coverageDump"):
            assert f"hook::{call}(" in body, call
        assert 'std::getenv("HOOKS_COVERAGE_DIR")' in body

        doc = _doc(checkout)
        assert "convention" in doc


class TestTheLegendExplainsWhatTheTableNames:
    """The `family` column is a label; the legend under it is the arrangement
    advice — "submit a transaction that reaches the hook", "needs etxn_reserve
    and a ledger close". The column without the note is the half a test author
    cannot act on.

    They were matched by two different mechanisms. When the patterns became
    globs only `_family` was updated; the legend went on calling `startswith`
    on `"otxn_*"`, so five of eight families could never match and their notes
    silently stopped printing while the table still named them.
    """

    @staticmethod
    def _families_in_table(doc):
        return {ln.split("|")[3].strip()
                for ln in doc.splitlines() if ln.startswith("| `")} - {"—", ""}

    @staticmethod
    def _families_in_legend(doc):
        return {m.group(1) for m in
                re.finditer(r"^- \*\*(.+?)\*\* — ", doc, re.M)}

    def test_every_family_the_table_names_is_explained(self, checkout):
        doc = _doc(checkout)

        named = self._families_in_table(doc)
        explained = self._families_in_legend(doc)

        assert named, "premise: the table assigns families"
        assert named - explained == set(), sorted(named - explained)

    def test_it_does_not_explain_families_the_hook_never_uses(self, checkout):
        """The other direction: the legend is scoped to this hook, so a note
        about emitted transactions on a hook that cannot emit is noise."""
        doc = _doc(checkout)

        assert self._families_in_legend(doc) <= self._families_in_table(doc)

    def test_the_glob_families_reach_the_legend(self, checkout):
        """govern.wasm imports otxn_*, state*, emit*, slot* and trace* — every
        one of them a starred pattern, and every one of them absent from the
        legend before this. `accept` and `_g` matched under either matcher,
        which is why the existing family tests stayed green.
        """
        explained = self._families_in_legend(_doc(checkout))

        for label in ("originating transaction", "hook state / installation",
                      "emitted transactions", "slots", "diagnostics only"):
            assert label in explained, label

    def test_the_churn_column_shows_the_real_numbers(self, checkout):
        """`+142` and `+114` are what tell a reader the manifest is hiding
        something substantial — they are the evidence for the sentence below
        the table, so a swapped or blanked column makes that sentence
        unfalsifiable from the document alone.

        Against the rendered row, not `files_in_patch`: the counting function
        was already pinned, and a mutation swapping the two columns *in the
        renderer* survived that.
        """
        from hookz import env_tests_ref as ref

        doc = _doc(checkout, include_patch=True)
        churn = {p: (a, r) for p, a, r, _ in ref.files_in_patch()}

        row = next(ln for ln in doc.splitlines()
                   if ln.startswith("| `src/xrpld/app/hook/applyHook.h`"))
        assert churn["src/xrpld/app/hook/applyHook.h"] == (142, 0)
        assert "+142" in row, row

        row = next(ln for ln in doc.splitlines()
                   if ln.startswith("| `include/xrpl/hook/Guard.h`"))
        assert churn["include/xrpl/hook/Guard.h"] == (42, 12)
        assert "+42" in row and "12" in row, row
        # Swapped columns would render "+12 −42".
        assert "+12" not in row, row

    def test_the_sentence_under_the_table_names_the_big_files(self, checkout):
        """It used to read "the remaining changes are one- and two-line edits
        inside existing files" — the document's argument for not showing them,
        and false: two of eleven are that small, and the two largest are the
        coverage API the skeleton calls and the build integration that
        compiles the test at all.
        """
        doc = _doc(checkout, include_patch=True)

        line = next(ln for ln in doc.splitlines()
                    if "--full-patch` inlines the complete diff" in ln)
        assert "one- and two-line edits" not in line
        assert "applyHook.h" in line and "+142" in line
        assert "RippledCore.cmake" in line and "+114" in line


class TestSectionOneIdentifiesSomethingReal:
    """A hook is identified by the hash of its wasm, so a sha256 in section 1
    is exactly the field a reader quotes.

    On the source path that hash was of the throwaway `-g -O0` build made for
    call-site attribution: three times the size of the deployable artifact,
    matching no artifact anywhere, and different on every run — `compile_hook`
    writes to a NamedTemporaryFile whose random name lands in the wasm `name`
    section, so 8 bytes of the hashed input changed each time.
    """

    def test_a_wasm_input_is_hashed_as_handed_over(self, checkout):
        import hashlib

        doc = _doc(checkout)
        digest = hashlib.sha256(WASM.read_bytes()).hexdigest()

        assert f"- sha256: `{digest}`" in doc

    def test_the_source_path_hashes_the_source_not_the_build(self):
        """Unit-level, so it runs without a toolchain."""
        import hashlib

        from hookz.cli.env_test_context import _identity

        src = Path(__file__)
        built = b"\x00asm\x01\x00\x00\x00 pretend this came out of clang"
        lines = "\n".join(_identity(src, built, from_source=True))

        assert hashlib.sha256(src.read_bytes()).hexdigest() in lines
        assert hashlib.sha256(built).hexdigest() not in lines, (
            "the analysis build's hash is unstable and identifies nothing")
        assert "deployable artifact" in lines
        assert "not stable across runs" in lines
        assert "hookz build" in lines

    def test_a_wasm_input_still_shows_the_artifact_hash(self):
        import hashlib

        from hookz.cli.env_test_context import _identity

        blob = b"\x00asm\x01\x00\x00\x00"
        lines = "\n".join(_identity(Path("h.wasm"), blob, from_source=False))

        assert hashlib.sha256(blob).hexdigest() in lines


class TestTheDocumentIsReproducible:
    """The strongest available statement that nothing unstable leaks in.

    Two runs over the same source produced different documents, because
    section 1 hashed a build whose bytes carried a random temp filename. Any
    future field with the same problem fails here rather than being noticed
    by someone diffing two copies months later.
    """

    def test_two_runs_over_the_same_source_agree(self, tmp_path):
        from hookz.cli.env_test_context import build_context
        from hookz.config import load_config
        from hookz.xahaud_files import _vendored_root

        source = Path("examples/tipbot/hooks/tip.c")
        if not source.is_file():
            pytest.skip("tipbot example not present")

        config = load_config(source_file=source)
        if Path(config.xahaud_root).resolve() == _vendored_root().resolve():
            pytest.skip("needs a real xahaud checkout")

        first = build_context(source, config, include_impl=False,
                              include_patch=False)
        second = build_context(source, config, include_impl=False,
                               include_patch=False)

        assert first == second

    def test_the_call_site_legend_defines_every_glyph_it_uses(self, tmp_path):
        """`?` was 37% of rendered arguments on tip.c — 121 of 324 — and the
        legend explained only the trailing `*`. An undefined glyph appearing
        that often, in a document whose premise is that it is trusted without
        checking, is the gap the `*` sentence shows the author knew to close.
        """
        from hookz.cli.env_test_context import build_context
        from hookz.config import load_config
        from hookz.xahaud_files import _vendored_root

        source = Path("examples/tipbot/hooks/tip.c")
        if not source.is_file():
            pytest.skip("tipbot example not present")

        config = load_config(source_file=source)
        if Path(config.xahaud_root).resolve() == _vendored_root().resolve():
            pytest.skip("needs a real xahaud checkout")

        doc = build_context(source, config, include_impl=False,
                            include_patch=False)

        assert "## 3. Where it calls them" in doc
        assert "(?" in doc or ", ?" in doc, "premise: unresolved args render"
        assert "- `?` —" in doc, "the glyph is never defined"
        # A call inlined from an included header reports the header's line,
        # because the instrumentation marker carries the line but not the
        # file. Verified: a 12-line main.c reported two calls at line 11 and
        # one at 12, all three actually in helper.h. The section says so
        # rather than presenting every number as a line in the target.
        assert "inlined from an included header" in doc


class TestTheWhitelistIsScopedToTheTestNotToMainnet:
    """xahaud's APIWhitelist is amendment-conditional
    (`getImportWhitelist(Rules const&)`), and the skeleton runs under
    `supported_amendments()`, which enables every `Supported::yes` feature
    regardless of how it is voting on the live network.

    Scoping the check to the mainnet manifest made the document print, in
    bold, that xahaud "refuses a hook that imports anything outside it, so the
    test cannot get as far as running this hook" — for `prepare`, which is
    gated on featureHooksUpdate2 and works fine in any jtx Env. It told an
    agent to delete a working call, while the amendment column two cells away
    named the amendment that makes it work.
    """

    def test_the_two_whitelists_actually_differ(self):
        """Premise. If mainnet ever enables everything the API defines, these
        tests stop proving anything and should be revisited rather than
        quietly passing."""
        from hookz.wasm.whitelist import (
            derive_amendments, get_import_signatures, load_from_config)

        mainnet = set(get_import_signatures())
        test_env = set(get_import_signatures(
            amendments=derive_amendments(load_from_config())))

        assert test_env - mainnet == {"prepare"}, sorted(test_env - mainnet)

    def test_a_gated_import_is_not_called_a_refusal(self):
        from hookz.cli.env_test_context import _surface_section
        from hookz.wasm.whitelist import (
            derive_amendments, get_function_signatures, get_import_signatures,
            load_from_config)

        imports = [("env", "prepare", (0x7F,) * 4, (0x7E,))]
        lines = "\n".join(_surface_section(
            imports, get_function_signatures(),
            get_import_signatures(
                amendments=derive_amendments(load_from_config()),
                coverage=True),
            mainnet=get_import_signatures(coverage=True)))

        assert "in no version of the API whitelist" not in lines
        assert "not in the whitelist" not in lines
        assert "available to your test" in lines
        assert "needs `featureHooksUpdate2`" in lines
        assert "supported_amendments()" in lines

    def test_a_genuinely_unknown_import_is_still_a_refusal(self):
        """The loud banner has to survive for the case it was written for."""
        from hookz.cli.env_test_context import _surface_section
        from hookz.wasm.whitelist import (
            derive_amendments, get_function_signatures, get_import_signatures,
            load_from_config)

        imports = [("env", "definitely_not_an_api", (0x7F,), (0x7E,))]
        lines = "\n".join(_surface_section(
            imports, get_function_signatures(),
            get_import_signatures(
                amendments=derive_amendments(load_from_config()),
                coverage=True),
            mainnet=get_import_signatures(coverage=True)))

        assert "in no version of the API whitelist" in lines
        assert "> - `env.definitely_not_an_api`" in lines

    def test_prepare_has_a_family_like_everything_else(self):
        from hookz.cli.env_test_context import _family

        assert _family("prepare")[0] == "emitted transactions"


class TestBuildContextWiresTheRightWhitelists:
    """The scoping fix lives in `build_context`, and every test of the new
    behaviour called `_surface_section` directly with whitelists it built
    itself — so reverting `build_context` to the mainnet set left them all
    green. Testing a fix below the function that chose wrong is not testing
    the fix.
    """

    def test_it_passes_the_test_environment_whitelist(self, checkout,
                                                      monkeypatch):
        import hookz.cli.env_test_context as etc

        captured = {}
        real = etc._surface_section

        def spy(imports, signatures, whitelist, *a, **kw):
            captured["whitelist"] = set(whitelist)
            captured["mainnet"] = set(kw.get("mainnet") or ())
            return real(imports, signatures, whitelist, *a, **kw)

        monkeypatch.setattr(etc, "_surface_section", spy)
        _doc(checkout)

        assert "prepare" in captured["whitelist"], (
            "the surface is judged against mainnet, not against the env the "
            "skeleton runs in")
        assert "prepare" not in captured["mainnet"], (
            "the mainnet set is what makes a gated import distinguishable")


class TestTheQuotedSourceIsLabelledWithItsOwnFile:
    """Two hardcoded path strings said which file each quoted body came from.
    Swapping them left the whole suite green — a confidently-stated filename
    with nothing pinning it. They read from XahaudFile now, but that only
    removes the duplication; this pins the pairing.

    Hermetic: the vendored xahaud_lite tree carries both files.
    """

    @staticmethod
    def _section():
        from hookz.cli.env_test_context import _related_code_section
        from hookz.wasm.whitelist import get_function_signatures
        from hookz.xahaud_files import _vendored_root
        from hookz.xrpl.xahaud import XahaudRepo

        imports = [("env", "otxn_field", (0x7F,) * 3, (0x7E,))]
        return "\n".join(_related_code_section(
            imports, XahaudRepo(str(_vendored_root())),
            get_function_signatures()))

    def test_the_wrapper_is_labelled_applyhook_cpp(self):
        from hookz.xahaud_files import XahaudFile

        text = self._section()
        label = f"`{XahaudFile.APPLY_HOOK_CPP.value}`:"
        assert label in text

        after = text.split(label, 1)[1]
        assert "DEFINE_HOOK_FUNCTION" in after.split("```")[1], (
            "the applyHook.cpp label sits above something that is not a "
            "DEFINE_HOOK_FUNCTION body")

    def test_the_implementation_is_labelled_hookapi_cpp(self):
        from hookz.xahaud_files import XahaudFile

        text = self._section()
        label = f"`{XahaudFile.HOOK_API_CPP.value}`:"
        assert label in text

        after = text.split(label, 1)[1]
        assert "DEFINE_HOOK_FUNCTION" not in after.split("```")[1], (
            "the HookAPI.cpp label sits above a wrapper body")
