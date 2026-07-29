"""Tests for hookz.annotations — stripping audit annotations back out.

Why this matters: hooks compile `__LINE__` into the binary as the accept /
rollback code and the `_g()` guard id. Writing a note above a line therefore
changes the artifact — same logic, different bytes, different HookHash. These
tests pin the property that makes annotating safe: strip() restores the
original numbering exactly, and verify() refuses to be fooled when it hasn't.
"""

import textwrap

import pytest

from hookz.annotations import (
    annotated_line, line_map, published_line, strip, verify,
)


def dedent(s: str) -> str:
    return textwrap.dedent(s).lstrip("\n")


class TestStrip:
    def test_removes_declaration_lines(self):
        assert strip(dedent("""
            int a = 1;
            //@@entity slot pool key=cfg len=72
            int b = 2;
        """)) == "int a = 1;\nint b = 2;\n"

    def test_removes_bare_separator(self):
        assert strip("int a = 1;\n//@@\nint b = 2;\n") == "int a = 1;\nint b = 2;\n"

    def test_removes_at_block(self):
        assert strip(dedent("""
            int a = 1;
            /*@@ a note
               spanning lines */
            int b = 2;
        """)) == "int a = 1;\nint b = 2;\n"

    def test_removes_one_line_at_block(self):
        assert strip("int a = 1;\n/*@@ note */\nint b = 2;\n") == "int a = 1;\nint b = 2;\n"

    def test_removes_dev_directive_block(self):
        """`hookz:` blocks are annotations too — they are rendered for dev builds."""
        assert strip(dedent("""
            int a = 1;
            /* hookz:
            HOOKZ_U64("a", a);
            HOOKZ_CHECK("here");
            */
            int b = 2;
        """)) == "int a = 1;\nint b = 2;\n"

    def test_keeps_the_authors_own_comments(self):
        """Only annotations go. A plain comment is part of the file."""
        src = "int a = 1;\n/* the author wrote this */\nint b = 2;\n"
        assert strip(src) == src

    def test_keeps_indented_code_containing_the_marker_text(self):
        """`//@@` must start the line to count — not appear anywhere in it."""
        src = 'int a = 1;  // see //@@entity above\n'
        assert strip(src) == src

    def test_is_idempotent(self):
        src = "int a = 1;\n//@@entity actor any\nint b = 2;\n"
        assert strip(strip(src)) == strip(src)

    def test_preserves_line_numbering_of_what_remains(self):
        """The whole point: surviving lines land where they started."""
        original = dedent("""
            int a = 1;
            int b = 2;
            int c = 3;
        """)
        annotated = dedent("""
            //@@entity actor any
            int a = 1;
            /*@@ a note */
            int b = 2;
            //@@
            int c = 3;
        """)
        assert strip(annotated) == original
        assert strip(annotated).splitlines().index("int c = 3;") == 2


class TestVerify:
    ORIGINAL = "int a = 1;\nint b = 2;\n"

    def test_clean_when_only_annotations_were_added(self):
        annotated = "//@@entity actor any\nint a = 1;\n/*@@ note */\nint b = 2;\n"
        assert verify(annotated, self.ORIGINAL) == []

    def test_catches_a_note_written_as_a_plain_comment(self):
        """The failure this exists for — an unmarked comment shifts every line below."""
        annotated = "int a = 1;\n/* a note nobody marked */\nint b = 2;\n"
        problems = verify(annotated, self.ORIGINAL)
        assert problems
        assert "a note nobody marked" in problems[0]

    def test_catches_added_code(self):
        annotated = "int a = 1;\nint sneaky = 3;\nint b = 2;\n"
        problems = verify(annotated, self.ORIGINAL)
        assert problems and "sneaky" in problems[0]

    def test_catches_removed_code(self):
        problems = verify("int a = 1;\n", self.ORIGINAL)
        assert problems and "int b = 2;" in problems[0]

    def test_catches_a_moved_line(self):
        """Reordering keeps every line but changes what __LINE__ compiles to."""
        assert verify("int b = 2;\nint a = 1;\n", self.ORIGINAL) != []


class TestPipelineIntegration:
    """The transform is declared by the pipeline, not wired in behind it."""

    def test_local_structural_pipeline_declares_the_strip(self):
        from hookz.wasm.pipeline import LOCAL_STRUCTURAL_PIPELINE

        assert "hookz.annotations:strip" in LOCAL_STRUCTURAL_PIPELINE.transforms

    def test_transforms_resolve_by_import_path(self):
        from hookz.wasm.pipeline import _resolve_transform

        assert _resolve_transform("hookz.annotations:strip") is strip

    @pytest.mark.parametrize("ref, match", [
        ("hookz.annotations", "module:function"),
        ("no.such.module:strip", "cannot import"),
        ("hookz.annotations:nope", "not callable"),
    ])
    def test_bad_transform_refs_are_rejected(self, ref, match):
        from hookz.wasm.pipeline import _resolve_transform

        with pytest.raises(ValueError, match=match):
            _resolve_transform(ref)

    def test_annotating_a_hook_does_not_change_its_binary(self, tmp_path):
        """The property the whole module exists for, end to end."""
        from pathlib import Path

        from hookz.config import load_config
        from hookz.wasm.pipeline import run_pipeline

        original = Path(__file__).parent / "e2e" / "hooks" / "misc" / "balance_gate.c"
        text = original.read_text()

        plain = tmp_path / "plain.c"
        plain.write_text(text)
        annotated = tmp_path / "annotated.c"
        annotated.write_text(
            "//@@entity actor any\n"
            "/*@@ a note that would otherwise shift every line below it */\n"
            "//@@\n" + text)

        cfg = load_config(source_file=original)
        assert run_pipeline(plain, "buildbox", cfg).wasm == \
            run_pipeline(annotated, "buildbox", cfg).wasm


class TestLineMapping:
    """A line number means nothing without saying which file it indexes.

    Hooks compile `__LINE__` in, so a rollback code from chain indexes the
    *published* file. Coverage, `hookz wce` and every finding cite the
    *annotated* one. On a heavily annotated hook those differ by hundreds of
    lines, and neither number carries a label — so looking an on-chain code up
    in the annotated source silently lands on unrelated code.
    """

    ANNOTATED = dedent("""
        //@@entity actor any
        int a = 1;
        /*@@ a note
           over two lines */
        int b = 2;
        //@@
        int c = 3;
    """)

    def test_annotation_lines_have_no_published_counterpart(self):
        m = line_map(self.ANNOTATED)
        assert 1 not in m          # //@@entity
        assert 3 not in m          # /*@@ opener
        assert 4 not in m          # its continuation
        assert 6 not in m          # //@@

    def test_code_lines_map_to_their_stripped_position(self):
        assert line_map(self.ANNOTATED) == {2: 1, 5: 2, 7: 3}

    def test_the_map_agrees_with_strip(self):
        """The two must not be able to disagree about what an annotation is."""
        stripped = strip(self.ANNOTATED).splitlines()
        for annotated_no, published_no in line_map(self.ANNOTATED).items():
            assert (self.ANNOTATED.splitlines()[annotated_no - 1]
                    == stripped[published_no - 1])

    def test_a_chain_rollback_code_locates_its_line(self):
        assert annotated_line(self.ANNOTATED, 3) == 7
        assert published_line(self.ANNOTATED, 7) == 3

    def test_an_annotation_line_has_no_published_line(self):
        assert published_line(self.ANNOTATED, 1) is None

    def test_a_code_past_the_end_locates_nothing(self):
        assert annotated_line(self.ANNOTATED, 999) is None

    def test_it_round_trips(self):
        for a, p in line_map(self.ANNOTATED).items():
            assert annotated_line(self.ANNOTATED, p) == a
