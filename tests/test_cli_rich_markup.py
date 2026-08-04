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

# Every shape of square bracket a hook can contain that Rich would otherwise
# read as a tag: a subscript, something that is also a real style name, and a
# closing tag that would terminate a style opened elsewhere in the line.
BRACKET_LINES = [
    "uint8_t seen_ids[i];",
    "int bold[2];",
    "state[SBUF(key)] = acc[0];",
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

    def test_the_view_disclaims_being_artifact_wce(self, tmp_path):
        out = self._run(tmp_path, ["int a;"], opt=[1], debug=[1])
        assert "not artifact WCE" in out
        assert "Secondary estimate only" in out

    def test_column_header_lines_up_with_the_counts_below_it(self, tmp_path):
        out = self._run(tmp_path, ["int a;"], opt=[1], debug=[1])
        header = next(ln for ln in out.splitlines() if "debug" in ln)
        counts = next(
            ln for ln in out.splitlines() if "int a;" in ln and "│" in ln
        )
        assert [i for i, c in enumerate(header) if c == "│"][:3] == [
            i for i, c in enumerate(counts) if c == "│"
        ][:3]

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

    def _show(self, monkeypatch, *, wrapper=None, impl=None, test=None):
        import hookz.xrpl.xahaud as xahaud

        class FakeRepo:
            def __init__(self, root):
                pass

            def find_hook_function(self, name):
                return wrapper

            def find_api_method(self, name):
                return impl

            def find_test_function(self, name):
                return test

        monkeypatch.setattr(xahaud, "XahaudRepo", FakeRepo)

        buf, console = _console()
        config = SimpleNamespace(xahaud_root="/nowhere", network="mainnet")
        _show_function(console, config, "state_set")
        return buf.getvalue()

    def test_wrapper_panel_keeps_c_subscripts(self, monkeypatch):
        out = self._show(monkeypatch, wrapper=self.CPP)
        assert "uint8_t buf[32];" in out
        assert "ptr[i]" in out

    def test_implementation_panel_keeps_c_subscripts(self, monkeypatch):
        out = self._show(monkeypatch, impl=self.CPP)
        assert "uint8_t buf[32];" in out

    def test_test_panel_keeps_c_subscripts(self, monkeypatch):
        out = self._show(monkeypatch, test=self.CPP)
        assert "ptr[i]" in out

    def test_nothing_found_is_said_plainly(self, monkeypatch):
        out = self._show(monkeypatch)
        assert "No xahaud source found for 'state_set'" in out
