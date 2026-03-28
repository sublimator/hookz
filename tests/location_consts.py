"""Resolved paths for framework tests — loaded from hookz.toml.

Tests that need compilation or xahaud source should use these.
If paths don't exist, the constants are set to None so conftest
can skip dependent tests.
"""

from pathlib import Path

from hookz.config import load_config

_config = load_config()

FIXTURES = Path(__file__).parent / "fixtures"

# Resolved from hookz.toml — None if path doesn't exist
XAHAUD = _config.xahaud_root if _config.xahaud_root.exists() else None
HOOK_DIR = _config.hook_headers if _config.hook_headers.exists() else None
WASI_SDK = _config.wasi_sdk if _config.wasi_sdk.exists() else None

# Tipbot hooks — inlined in examples/tipbot/hooks/
_tipbot_dir = Path(__file__).parents[1] / "examples/tipbot/hooks"
TIPBOT_DIR = _tipbot_dir.resolve() if _tipbot_dir.exists() else None
