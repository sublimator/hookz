from hookz.testing import register_hooks_from_config
from e2e.lean_adapters import register_lean_adapters

register_lean_adapters()
register_hooks_from_config()
