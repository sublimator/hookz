"""CLI panels that display C or C++ must not parse it as Rich markup.

The sibling of `test_coverage_rich_markup.py`, for the panels `hookz wce
--source` and `hookz show` print. `seen_ids[i]` displayed as `seen_ids` is
valid-looking C: nothing in the output says a subscript was eaten, so the panel
reports a line of code that is not in the file.
"""

from __future__ import annotations

from io import StringIO
from types import SimpleNamespace

import pytest
from rich.console import Console

from hookz.cli.main import _print_annotated_source, _show_function


SOURCE_LINE = '            if (seen_ids[i] == entry_id) NOPE("reg: duplicate entry id.");'

# Every shape Rich would otherwise read as a tag. `[2]` and `[SBUF(key)]` are
# NOT among them — Rich only opens a tag on [a-z#/@], so a digit or a capital
# is inert and proves nothing. Each line here must contain a live one.
BRACKET_LINES = [
    "uint8_t seen_ids[i];",
    "int x[bold];",
    "state[SBUF(key)] = acc[red];",
    "if (buf[/i] == 0) return 0;",
    "arr[dim] = arr[red] + arr[not a tag];",
]


def _console():
    buf = StringIO()
    return buf, Console(
        file=buf, force_terminal=False, width=200, legacy_windows=False
    )


class TestAnnotatedSourceViewEscapesC:
    """This view interleaves markup with source, so it escapes rather than
    handing the whole body to Text."""

    def _run(self, tmp_path, lines, *, opt=(), debug=()):
        src = tmp_path / "hook.c"
        src.write_text("\n".join(lines) + "\n")
        buf, console = _console()
        _print_annotated_source(
            console,
            src,
            [SimpleNamespace(line=n) for n in opt],
            [SimpleNamespace(line=n) for n in debug],
            SimpleNamespace(hook_tree=None, cbak_tree=None),
        )
        return buf.getvalue()

    @pytest.mark.parametrize("line", BRACKET_LINES)
    def test_brackets_survive_every_column_state(self, tmp_path, line):
        # line 1 has both counts, line 2 is ELIM, line 3 is never mentioned
        out = self._run(tmp_path, [line, line, line], opt=[1], debug=[1, 1, 2])
        assert out.count(line) == 3

    def test_eliminated_lines_keep_their_subscripts(self, tmp_path):
        out = self._run(tmp_path, [SOURCE_LINE], debug=[1])
        assert "ELIM" in out
        assert "seen_ids[i]" in out

    def test_loop_marker_row_keeps_its_subscripts(self, tmp_path):
        from hookz.wasm.guard import BlockInfo

        src = tmp_path / "hook.c"
        src.write_text(f"{SOURCE_LINE}\n")
        tree = BlockInfo(iteration_bound=1)
        tree.add_child(5, 0, is_loop=True, guard_id=(1 << 31) + 1)
        buf, console = _console()
        _print_annotated_source(
            console,
            src,
            [SimpleNamespace(line=1)],
            [SimpleNamespace(line=1)],
            SimpleNamespace(hook_tree=tree, cbak_tree=None),
        )
        out = buf.getvalue()
        assert "►" in out
        assert "seen_ids[i]" in out

    def test_a_loop_line_absent_from_the_oz_twin_is_marked_eliminated(
        self, tmp_path
    ):
        """The loop-marker row is the only consumer of the ELIM column value —
        every other row hardcodes it — so without this the branch never runs.
        """
        from hookz.wasm.guard import BlockInfo

        src = tmp_path / "hook.c"
        src.write_text("for (int i = 0; GUARD(2), i < 2; ++i) sum += buf[i];\n")
        tree = BlockInfo(iteration_bound=1)
        tree.add_child(2, 0, is_loop=True, guard_id=(1 << 31) + 1)
        buf, console = _console()
        _print_annotated_source(
            console,
            src,
            [],  # nothing survived into the -Oz twin's line table
            [SimpleNamespace(line=1)],
            SimpleNamespace(hook_tree=tree, cbak_tree=None),
        )
        out = buf.getvalue()
        # "ELIM" also appears in the caption, so assert on the row's own cell
        row = next(ln for ln in out.splitlines() if "►" in ln)
        cells = [c.strip() for c in row.split("│")]
        assert cells[1] == "1" and cells[2] == "ELIM"
        assert "buf[i]" in cells[4]

    def test_the_view_disclaims_being_artifact_wce(self, tmp_path):
        out = self._run(tmp_path, ["int a;"], opt=[1], debug=[1])
        assert "not artifact WCE" in out
        assert "Secondary estimate only" in out

    def test_the_three_rules_and_columns_all_line_up(self, tmp_path):
        """Header, rule and data are one table; a rule that does not meet its
        own columns is the tell that a label was widened without the rest."""
        out = self._run(tmp_path, ["int a;"], opt=[1], debug=[1])
        lines = out.splitlines()
        header = next(ln for ln in lines if "debug" in ln and "│" in ln)
        rule = next(ln for ln in lines if "┼" in ln)
        counts = next(ln for ln in lines if "int a;" in ln and "│" in ln)

        def stops(line, ch):
            return [i for i, c in enumerate(line) if c == ch]

        assert stops(header, "│") == stops(counts, "│")
        # [0] is the panel's own left border; the three column separators follow
        assert stops(rule, "┼") == stops(counts, "│")[1:4]

    def test_an_unreadable_source_says_so_instead_of_raising(self, tmp_path):
        buf, console = _console()
        _print_annotated_source(
            console,
            tmp_path / "gone.c",
            [],
            [],
            SimpleNamespace(hook_tree=None, cbak_tree=None),
        )
        assert "Could not read source file" in buf.getvalue()


class TestShowPanelsAreNotMarkup:
    """`hookz show <fn>` panels hold C++ from xahaud, which is just as full of
    brackets as the hooks are."""

    CPP = (
        "DEFINE_HOOK_FUNCTION(int64_t, state_set, uint32_t read_ptr)\n"
        "{\n"
        "    uint8_t buf[32];\n"
        "    if (ptr[i] > memory_length) return OUT_OF_BOUNDS;\n"
        "}\n"
    )

    def _show(self, monkeypatch, tmp_path, *, wrapper=None, impl=None, test=None):
        import hookz.xrpl.xahaud as xahaud

        seen_root = []

        class FakeRepo:
            def __init__(self, root):
                # the real XahaudRepo raises FileNotFoundError on a root that
                # does not exist, so the fixture must not invent one
                seen_root.append(root)

            def find_hook_function(self, name):
                return wrapper

            def find_api_method(self, name):
                return impl

            def find_test_function(self, name):
                return test

        monkeypatch.setattr(xahaud, "XahaudRepo", FakeRepo)

        buf, console = _console()
        config = SimpleNamespace(xahaud_root=tmp_path, network="mainnet")
        _show_function(console, config, "state_set")
        assert seen_root == [str(tmp_path)]
        return buf.getvalue()

    def test_wrapper_panel_keeps_c_subscripts(self, monkeypatch, tmp_path):
        out = self._show(monkeypatch, tmp_path, wrapper=self.CPP)
        assert "uint8_t buf[32];" in out
        assert "ptr[i]" in out

    def test_implementation_panel_keeps_c_subscripts(self, monkeypatch, tmp_path):
        out = self._show(monkeypatch, tmp_path, impl=self.CPP)
        # buf[32] alone proves nothing — a digit never opens a Rich tag
        assert "ptr[i]" in out
        assert "uint8_t buf[32];" in out

    def test_test_panel_keeps_c_subscripts(self, monkeypatch, tmp_path):
        out = self._show(monkeypatch, tmp_path, test=self.CPP)
        assert "ptr[i]" in out

    def test_nothing_found_is_said_plainly(self, monkeypatch, tmp_path):
        out = self._show(monkeypatch, tmp_path)
        assert "No xahaud source found for 'state_set'" in out
