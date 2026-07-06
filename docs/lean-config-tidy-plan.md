# Lean Hook Config Tidy Plan

## Goal

Make Lean integration read like hook metadata, not a personal coverage todo list.
The hook registry should bind a hook name to its C source and, when available,
one Lean root file. Todo/status notes belong in docs or issue logs, not
`hookz.toml`.

## Plan

1. Normalize hook config entries so a hook can be either a string shorthand or an
   expanded object.
   - String form: `name = "path/to/hook.c"`
   - Object form: `name = { source = "path/to/hook.c", lean = "path/to/hook.lean" }`
2. Keep `HookzConfig.hooks` as the existing source-only map for compatibility.
3. Add a richer normalized entry map for code that needs optional Lean sidecars.
4. Collapse `[lean4.<hook>]` blocks into the corresponding `[hooks]` entries.
5. Remove `status`/`note` coverage markers from `hookz.toml`.
6. Remove stale source-level Lean metadata comments that duplicate config.
7. Update tests to enforce the new shape:
   - string and object hook forms both parse
   - Lean bindings are discovered from hook entries
   - no top-level `[lean4]` table remains
   - hook metadata only uses schema fields, not todo/status fields
8. Run the focused Python tests, Lean build, and runtime smoke bridge.
9. Ask a fresh reviewer to inspect the cleanup for schema, compatibility, and
   missed references.

## Coverage Note

Normal e2e hook coverage still compiles through `compile_hook`, so the config
cleanup does not change existing coverage reports.

Development-directive compilation rewrites comments into a temporary C file.
That generated source now emits `#line` markers around the original source and
unwrapped directive blocks so DWARF line numbers stay anchored to the source
hook rather than the generated prelude. Future coverage work should still make
coverage filename-aware; today the tracker records only line and column.

## Intended Shape

```toml
[hooks]
govern = "hooks/genesis/govern.c"
balance_gate = { source = "hooks/misc/balance_gate.c", lean = "hooks/misc/balance_gate.lean" }
```

Equivalent table form:

```toml
[hooks.balance_gate]
source = "hooks/misc/balance_gate.c"
lean = "hooks/misc/balance_gate.lean"
```

The configured `lean` file is the hook's Lean root/index. It can be colocated
with the source or live elsewhere; generated witnesses derive the Lean module
mechanics from that file when needed.
