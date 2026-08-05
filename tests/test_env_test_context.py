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
        skeleton needs the branch, so the document is still worth having."""
        doc = _doc(checkout)

        assert "does not carry the env-tests harness" in doc
        assert "git apply" in doc or "apply" in doc

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

        assert "not in the API whitelist" in doc
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

        assert "no instrumentation markers" in doc
        assert ".c" in doc
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

    def test_the_map_key_placeholder_is_not_a_guessable_default(
        self, checkout
    ):
        """The key is file:<domain>/<file>.c and <domain> comes from the
        caller's -DHOOKS_C_DIR. Printing a made-up domain would compile into
        a map lookup that silently returns an empty vector."""
        doc = _doc(checkout)

        assert "file:<domain>/govern.c" in doc
        assert "HOOKS_C_DIR" in doc
