"""Auto-discover and register all handler functions from this package."""

import importlib
import pkgutil


def collect_handlers() -> dict[str, callable]:
    """Scan all modules in this package, collect handler functions.

    A handler is any function that doesn't start with a single underscore
    (Python private convention), OR any function explicitly listed in the
    module's __handlers__ list. The _g and __on_source_line handlers use
    this mechanism since their names look private but are real hook API names.

    Returns a dict mapping handler name → function(rt, *wasm_args).
    """
    handlers = {}
    for info in pkgutil.iter_modules(__path__):
        mod = importlib.import_module(f".{info.name}", __package__)

        # Explicit exports override naming convention
        explicit = getattr(mod, "__handlers__", None)

        for name in dir(mod):
            fn = getattr(mod, name)
            if not callable(fn) or isinstance(fn, type):
                continue
            if explicit and name in explicit:
                handlers[name] = fn
            elif not name.startswith("_"):
                handlers[name] = fn
    return handlers
