"""Coverage panels must not parse C source as Rich markup.

See one-xahau-audits `.ai-docs/issues/hookz-coverage-source-rich-markup-corruption.md`.
`seen_ids[i]` displayed as `seen_ids` is valid-looking C and an audit lie: the
reader has no way to tell that a subscript was eaten, so the panel reports a
line of code that is not in the file.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from hookz.coverage.tracker import CoverageTracker
from hookz.testing.plugin import _plain_panel


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


def _render(renderable, width: int = 120) -> str:
    buf = StringIO()
    console = Console(
        file=buf, force_terminal=False, width=width, legacy_windows=False
    )
    console.print(renderable)
    return buf.getvalue()


class TestSourceIsNotRichMarkup:
    def test_raw_panel_string_eats_array_subscripts(self):
        """Document the failure mode: Panel(str) enables markup."""
        out = _render(Panel(SOURCE_LINE, title="broken"))
        assert "seen_ids[i]" not in out
        assert "seen_ids" in out

    def test_plain_panel_preserves_array_subscripts(self):
        out = _render(_plain_panel(SOURCE_LINE, title="ok", border_style="red"))
        assert "seen_ids[i]" in out
        assert "entry_id" in out

    @pytest.mark.parametrize("line", BRACKET_LINES)
    def test_plain_panel_preserves_every_bracket_shape(self, line):
        out = _render(_plain_panel(line, title="ok", border_style="red"))
        assert line in out

    def test_plain_panel_does_not_raise_on_an_unclosed_tag(self):
        """Rich raises MarkupError on some malformed tags; a source line that
        happens to contain one must still print."""
        out = _render(
            _plain_panel("x = a[/bold];", title="ok", border_style="red")
        )
        assert "a[/bold]" in out

    def test_region_table_node_tags_survive(self):
        """render_regions() emits `[node]`-style tags of its own."""
        table = "  0.0%  [rollback] lines 12-19\n 50.0%  [emit] lines 20-24"
        out = _render(_plain_panel(table, title="regions", border_style="yellow"))
        assert "[rollback]" in out
        assert "[emit]" in out

    def test_uncovered_report_through_plain_panel_preserves_brackets(
        self, tmp_path: Path
    ):
        src = tmp_path / "bracket_hook.c"
        src.write_text(
            "int64_t hook(uint32_t r) {\n"
            f"{SOURCE_LINE}\n"
            "  return 0;\n"
            "}\n"
        )
        tracker = CoverageTracker()
        # Executable lines include the subscript line; leave it unhit.
        tracker._executable_lines = {1, 2, 3}
        tracker.hit(1)  # so the file is not "never run"
        report = tracker.uncovered_report(src, context=0)
        assert "seen_ids[i]" in report
        out = _render(_plain_panel(report, title="uncovered", border_style="red"))
        assert "seen_ids[i]" in out

    def test_text_wrapper_also_preserves_brackets(self):
        out = _render(Panel(Text(SOURCE_LINE), title="text"))
        assert "seen_ids[i]" in out

    def test_plain_panel_keeps_the_border_style_it_was_given(self):
        panel = _plain_panel("x", title="t", border_style="red")
        assert panel.border_style == "red"
        assert panel.title == "t"
