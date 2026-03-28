"""hookz testing library — reusable fixtures and helpers for hook test projects."""

from hookz.testing.plugin import register_hooks


def register_hooks_from_config():
    """Read [hooks] from hookz.toml and register them all."""
    from hookz.config import load_config
    config = load_config()
    if not config.hooks:
        return
    register_hooks({name: str(path) for name, path in config.hooks.items()})


__all__ = ["register_hooks", "register_hooks_from_config"]
