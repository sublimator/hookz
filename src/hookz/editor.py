"""Editor URL generation for clickable trace links.

Supports JetBrains IDEs via Toolbox's jetbrains:// protocol,
and custom formats via @-prefix.

Usage:
    HOOKZ_EDITOR=clion            → jetbrains://clion/navigate/reference?path=...
    HOOKZ_EDITOR=pycharm          → jetbrains://pycharm/navigate/reference?path=...
    HOOKZ_EDITOR='@fmt'           → fmt with %file and %line replaced

Without HOOKZ_EDITOR, no links are emitted (plain text).
"""

from __future__ import annotations

import os
from pathlib import Path

# JetBrains Toolbox tool tags → jetbrains://{tag}/navigate/reference
# Requires JetBrains Toolbox to be installed (registers the jetbrains:// handler)
JETBRAINS_TOOL_TAGS = {
    "idea": "idea",
    "pycharm": "pycharm",
    "clion": "clion",
    "webstorm": "web-storm",
    "phpstorm": "php-storm",
    "goland": "goland",
    "rubymine": "rubymine",
    "rider": "rd",
    "datagrip": "datagrip",
}


def editor_url(source: Path, line: int, editor: str | None = None) -> str:
    """Build a URL that opens source:line in the configured editor.

    Args:
        source: absolute path to source file
        line: 1-based line number
        editor: editor name or @format string (default: HOOKZ_EDITOR env var)
    """
    if editor is None:
        editor = os.environ.get("HOOKZ_EDITOR", "")

    if not editor:
        return f"file://{source}"

    if editor.startswith("@"):
        return editor[1:].replace("%file", str(source)).replace("%line", str(line))

    name = editor.lower()
    tag = JETBRAINS_TOOL_TAGS.get(name)
    if tag:
        project = os.environ.get("HOOKZ_PROJECT", source.parent.name)
        return f"jetbrains://{tag}/navigate/reference?project={project}&path={source}:{line - 1}"

    return f"file://{source}"


def osc8_link(text: str, url: str) -> str:
    """Wrap text in an OSC 8 hyperlink escape sequence."""
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"
