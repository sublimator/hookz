"""Tests for editor URL generation."""

from pathlib import Path

from hookz.editor import editor_url, osc8_link, JETBRAINS_TOOL_TAGS


SOURCE = Path("/Users/someone/projects/tip.c")


class TestEditorUrl:
    def test_no_editor_uses_file(self):
        assert editor_url(SOURCE, 42, editor="") == f"file://{SOURCE}"

    def test_clion(self):
        url = editor_url(SOURCE, 42, editor="clion")
        assert url == f"jetbrains://clion/navigate/reference?project=projects&path={SOURCE}:41"

    def test_pycharm(self):
        url = editor_url(SOURCE, 10, editor="pycharm")
        assert url == f"jetbrains://pycharm/navigate/reference?project=projects&path={SOURCE}:9"

    def test_idea(self):
        url = editor_url(SOURCE, 1, editor="IDEA")
        assert url == f"jetbrains://idea/navigate/reference?project=projects&path={SOURCE}:0"

    def test_webstorm_tag(self):
        """WebStorm uses 'web-storm' as its Toolbox tag."""
        url = editor_url(SOURCE, 5, editor="webstorm")
        assert "web-storm" in url

    def test_rider_tag(self):
        """Rider uses 'rd' as its Toolbox tag."""
        url = editor_url(SOURCE, 5, editor="rider")
        assert "rd" in url

    def test_all_jetbrains_ides(self):
        for name, tag in JETBRAINS_TOOL_TAGS.items():
            url = editor_url(SOURCE, 99, editor=name)
            assert url == f"jetbrains://{tag}/navigate/reference?project=projects&path={SOURCE}:98", \
                f"Failed for {name} (tag={tag})"

    def test_case_insensitive(self):
        url = editor_url(SOURCE, 5, editor="CLion")
        assert "jetbrains://clion/" in url

    def test_custom_format(self):
        fmt = "@txmt://open?url=file://%file&line=%line"
        assert editor_url(SOURCE, 42, editor=fmt) == f"txmt://open?url=file://{SOURCE}&line=42"

    def test_custom_format_arbitrary(self):
        fmt = "@myeditor:%file#L%line"
        assert editor_url(SOURCE, 7, editor=fmt) == f"myeditor:{SOURCE}#L7"

    def test_unknown_editor_falls_back_to_file(self):
        assert editor_url(SOURCE, 42, editor="notepad") == f"file://{SOURCE}"


class TestOsc8Link:
    def test_wraps_text(self):
        result = osc8_link("tip.c:42", "jetbrains://clion/navigate/reference?project=projects&path=tip.c:41")
        assert "\033]8;;" in result
        assert "tip.c:42" in result
        assert "jetbrains://clion" in result
        assert result.endswith("\033]8;;\033\\")
