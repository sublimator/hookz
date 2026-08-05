"""hookz env-test-context — one document that is enough to write an env test.

Writing a C++ env test for a hook means answering three questions, and today
each one is answered somewhere else: which host functions does this hook
actually call (the wasm), what does each of them read or write (xahaud's
HookAPI.cpp), and what does the harness give me to arrange that (the
external-env-tests branch). An agent asked to write a test either goes and
finds all three or guesses at the parts it did not find.

This assembles them into one markdown document, in that order.

WHY IT REQUIRES A REAL XAHAUD CHECKOUT
--------------------------------------
hookz ships `xahaud_lite/`, a vendored subset big enough to compile hooks and
run `hookz show`. It is deliberately not big enough for this: the jtx harness
(`src/test/jtx/`) is not in it, and the whole point of the document is the
code around the hook rather than the hook alone. Falling back to the vendored
tree would produce a document that looks complete and silently omits the half
this command exists to supply, so a missing checkout is an error with the two
ways to fix it rather than a quieter answer.

The branch's own changes are not read from the checkout — they come from
the vendored patch, pinned in `hookz.env_tests_ref`, so they are correct even
when the configured checkout is plain `dev`.

Not inlined verbatim: the whole diff was half the document, and most of it is
context lines around one-line edits that a reader has to decode. What goes in
is `TestEnv.h` — the one file the branch adds outright, so its diff *is* the
file and it can be handed over as C++ — plus a manifest of what else changed
and why, with the pin so it can be checked. `--full-patch` inlines the rest.
"""

from __future__ import annotations

import hashlib
from fnmatch import fnmatchcase
from pathlib import Path

# Which host functions imply which setup. Keyed on globs over xahaud's own
# naming, because that grouping is a fact about the API rather than a taxonomy
# invented here. `test_the_table_covers_every_function_in_the_whitelist` keeps
# it total: three functions fell through to no family at all, and each was
# found only after someone happened to look at that row.
#
# This is a routing hint and says so in the rendered document: it tells a
# reader which of the three or four families a call belongs to, so they know
# whether the test needs a transaction, ledger objects, or nothing at all. The
# authority for what any single call does is its implementation, which is
# quoted in full further down the same document.
_FAMILIES: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("accept", "rollback"), "hook outcome",
     "decides the ter() the triggering transaction gets — this is what the "
     "test asserts on"),
    (("otxn_*",), "originating transaction",
     "the test must submit a transaction that reaches the hook; these read "
     "fields off it"),
    (("state*", "hook_*"), "hook state / installation",
     "needs the hook installed on an account with reserve for the state it "
     "writes"),
    (("emit*", "etxn_*"), "emitted transactions",
     "needs etxn_reserve and a ledger close after the triggering transaction "
     "for emitted results to apply"),
    # Glob rather than prefix because the API puts `slot` on both ends:
    # `slot_set`, bare `slot`, and `meta_slot`/`xpop_slot`. A `slot_` prefix
    # missed the bare one, and fixing only that missed the two suffixed ones.
    (("slot*", "*_slot"), "slots",
     "reads ledger objects loaded into slots, so those objects must exist "
     "before the hook runs"),
    (("trace*",), "diagnostics only",
     "no ledger arrangement; see the output with "
     'TESTENV_LOGGING="HooksTrace=trace"'),
    (("float_*", "util_*", "sto_*", "ledger_*", "fee_base"), "computation",
     "pure or near-pure; no ledger arrangement needed to reach them"),
    (("_g",), "guard",
     "the loop guard, enforced at check time rather than something a test "
     "arranges"),
)

# Copied from a test that compiles and runs today
# (examples/tipbot/env-tests/TipBot_test.cpp) rather than reconstructed from
# the headers. The detail most easily got wrong is that HOOK_WASM is defined
# per test file — the generated header supplies only the map it indexes.
_SKELETON = '''\
// Save as env-tests/{suite}_test.cpp — the name is load-bearing, and getting
// it wrong fails silently. CMake globs "${{HOOKS_TEST_DIR}}/*_test.cpp"
// (RippledCore.cmake), so a file not ending in _test.cpp is skipped with no
// warning; and the header is named from the stem, so only {suite}_test.cpp
// generates the {header} this file includes.
#include "{header}"
#include <test/jtx.h>
#include <test/jtx/TestEnv.h>
#include <test/jtx/hook.h>
#include <xrpld/app/hook/applyHook.h>
#include <xrpld/app/tx/detail/SetHook.h>
#include <xrpl/hook/Enum.h>
#include <xrpl/protocol/jss.h>
#include <cstdlib>

namespace ripple {{
namespace test {{

// All three are per-test-file defines in xahaud, not header declarations —
// nothing in <test/jtx.h> provides them, and -DHOOKS_TEST_ONLY=ON excludes
// the src/test/*_test.cpp files that do.
#define BEAST_REQUIRE(x)     \\
    {{                        \\
        BEAST_EXPECT(!!(x)); \\
        if (!(x))            \\
            return;          \\
    }}
#define HSFEE fee(100'000'000)
#define M(m) memo(m, "", "")

// Binds `{name}_wasm`, `{name}_hash`, `{name}_hash_str` and `{name}_keylet`
// from the generated map. The string is the map key: "file:<domain>/<file>.c",
// where <domain> is the name you gave in -DHOOKS_C_DIR=<domain>=<path>.
#define HOOK_WASM(name, path)                                                  \\
    [[maybe_unused]] auto const& name##_wasm = {symbol}[path];                 \\
    [[maybe_unused]] uint256 const name##_hash = ripple::sha512Half_s(         \\
        ripple::Slice(name##_wasm.data(), name##_wasm.size()));                \\
    [[maybe_unused]] std::string const name##_hash_str = to_string(name##_hash); \\
    [[maybe_unused]] Keylet const name##_keylet =                              \\
        keylet::hookDefinition(name##_hash);

class {suite}_test : public beast::unit_test::suite
{{
private:
    void static overrideFlag(Json::Value& jv)
    {{
        jv[jss::Flags] = hsfOVERRIDE;
    }}

    using TestEnv = jtx::TestEnv;

    TestEnv
    makeEnv(FeatureBitset features)
    {{
        return TestEnv{{*this, features}};
    }}

    void
    testItRuns(FeatureBitset features)
    {{
        testcase("{name}: installs and fires");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        env.setPrefix("install");
        HOOK_WASM({name}, "file:<domain>/{name}.c");
        env(ripple::test::jtx::hook(
                alice, {{{{hso({name}_wasm, overrideFlag)}}}}, 0),
            M("Install {name}"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        auto const installed = env.le(keylet::hook(alice.id()));
        BEAST_REQUIRE(installed);
        BEAST_REQUIRE(installed->isFieldPresent(sfHooks));
        BEAST_EXPECT(
            installed->getFieldArray(sfHooks)[0].getFieldH256(sfHookHash) ==
            {name}_hash);

        env.setPrefix("trigger");
        env(pay(bob, alice, XRP(1)), ter(tesSUCCESS));
        env.close();

        // Assert what the hook did. The surface table above says which of
        // these it can produce: state it wrote, transactions it emitted, or
        // the ter() it forced.
    }}

public:
    void
    run() override
    {{
        using namespace jtx;

        // Coverage is opt-in and entirely up to this function: -DHOOKS_COVERAGE=ON
        // only instruments the hooks. Nothing in xahaud reads an output path or
        // writes a file, so without the three calls below the hits accumulate in
        // memory and are dropped when the process exits, with no error.
        hook::coverageReset();
        {{
            HOOK_WASM({name}, "file:<domain>/{name}.c");
            // Label it, or the dump is keyed by hook hash instead of filename.
            hook::coverageLabel({name}_hash, "file:<domain>/{name}.c");
        }}

        testItRuns(supported_amendments());

        if (auto const* dir = std::getenv("HOOKS_COVERAGE_DIR"))
            hook::coverageDump(std::string(dir) + "/{suite}.dat");
    }}
}};

BEAST_DEFINE_TESTSUITE({suite}, app, ripple);

}}  // namespace test
}}  // namespace ripple
'''


class ContextError(Exception):
    """Something the caller has to fix before a document can be built."""


def _require_checkout(config) -> Path:
    """The configured xahaud checkout, or an error naming both ways to set it.

    `load_config` falls back to the vendored `xahaud_lite/` tree when nothing
    is configured, and that fallback is right for every other command. Here it
    would silently drop `src/test/jtx/`, so it is detected and refused.
    """
    from hookz.xahaud_files import _vendored_root

    root = Path(config.xahaud_root)
    if root == Path() or not root.exists():
        raise ContextError(
            "env-test-context needs a xahaud checkout and none is configured.\n"
            "  hookz.toml:  [paths] xahaud = \"/path/to/xahaud\"\n"
            "  or:          HOOKZ_XAHAUD=/path/to/xahaud hookz env-test-context ...")

    if root.resolve() == _vendored_root().resolve():
        raise ContextError(
            "env-test-context resolved to the vendored xahaud_lite tree, which "
            "does not carry src/test/jtx.\n"
            "Point it at a real checkout:\n"
            "  hookz.toml:  [paths] xahaud = \"/path/to/xahaud\"\n"
            "  or:          HOOKZ_XAHAUD=/path/to/xahaud hookz env-test-context ...")

    return root


def _has_env_tests(root: Path) -> bool:
    """Whether the checkout carries the branch, judged by the file it adds.

    TestEnv.h is new in the patch — `git checkout dev` has every other file
    this command reads, so nothing else distinguishes the two.
    """
    return (root / "src/test/jtx/TestEnv.h").is_file()


def _imports(wasm: bytes) -> list[tuple[str, str, tuple, tuple]]:
    """(module, name, params, results) for each function import, in wasm order."""
    from hookz.wasm.decode import decode_module

    mod = decode_module(wasm)
    out = []
    for imp in mod.imports:
        ft = mod.types[imp.type_idx] if imp.type_idx < len(mod.types) else None
        out.append((imp.module, imp.name,
                    tuple(ft.params) if ft else (),
                    tuple(ft.results) if ft else ()))
    return out


# Calls that say nothing about what a test has to arrange. Deliberately much
# smaller than `surface`'s _PLUMBING, which also drops accept/rollback/trace:
# those three are exactly what an env test asserts on — the ter() the hook
# forced and the log line proving which branch ran.
_NOISE = frozenset({
    "_g", "__on_source_line", "hookz_dev_u64", "hookz_dev_str", "hookz_dev_check",
})


def _call_sites(source: Path, config) -> tuple[bytes, list[tuple[int, object]]]:
    """(wasm, [(line, ApiCall)]) — every host call attributed to its source line.

    The same compile-then-instrument path `hookz surface` uses. Attribution
    comes from the `__on_source_line` markers an instrumented build carries, so
    it needs the source rather than a finished binary: a deployed wasm has no
    DWARF and no markers, and nothing can put the line numbers back.
    """
    import tempfile

    from hookz.compiler import compile_hook
    from hookz.coverage.rewriter import instrument_wasm
    from hookz.wasm.dataflow import calls_by_source_line

    wasm = compile_hook(source, config=config)
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    try:
        tmp.write(wasm)
        tmp.close()
        instrumented, _locs = instrument_wasm(wasm, tmp.name)
    finally:
        Path(tmp.name).unlink(missing_ok=True)

    sites = [(ln, c) for ln, c in calls_by_source_line(instrumented)
             if c.name not in _NOISE]
    return wasm, sites


def _family(name: str) -> tuple[str, str]:
    for patterns, label, note in _FAMILIES:
        if any(fnmatchcase(name, p) for p in patterns):
            return label, note
    return "", ""


def _c_signature(fn) -> str:
    """`int64_t otxn_field(uint32_t, uint32_t, uint32_t)` from the macro defs."""
    return f"{fn.return_type} {fn.name}({', '.join(fn.param_types) or 'void'})"


def _wasm_signature(name: str, params: tuple, results: tuple) -> str:
    """Fallback spelling for an import with no hook-API definition."""
    def t(v):
        return {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64"}.get(v, hex(v))
    got = ", ".join(t(p) for p in params)
    ret = ", ".join(t(r) for r in results) or "void"
    return f"{ret} {name}({got})"


def _call_site_section(sites, source: Path) -> list[str]:
    """Where each call is, with the constants the source hid behind macros.

    The surface table says the hook can write state; this says it writes two
    keys, at these lines, under these field ids. That is the difference
    between knowing a test needs hook state and knowing what to assert about
    it, and it is why the command prefers a `.c` over a finished binary.
    """
    from hookz.cli.main import _pretty

    lines = [
        f"Read out of the compiled binary and attributed back to `{source.name}`, "
        "so the constants the source hid behind macros are resolved to the "
        "values xahaud will see. A trailing `*` means the value came from a "
        "single-assignment local rather than off the stack at the call.",
        "",
        "```",
    ]
    for line, call in sites:
        args = ", ".join(_pretty(a, call.name, i)
                         for i, a in enumerate(call.args))
        lines.append(f"  {line:>5}  {call.name}({args})")
    lines += ["```", ""]
    return lines


def _surface_section(imports, signatures, whitelist, counts=None,
                     impl_below: bool = True) -> list[str]:
    lines = [
        "Every host function in the wasm's import section. `family` groups by "
        "what a test has to arrange to reach the call — a routing hint, not "
        "the authority. "
        + ("The implementations are quoted below." if impl_below else
           "Re-run without `--no-impl` to see the implementations."),
        "",
        "| host function | signature | family | amendment |"
        + (" calls |" if counts else ""),
        "|---|---|---|---|" + ("---|" if counts else ""),
    ]
    unknown = []
    for module, name, params, results in imports:
        fn = signatures.get(name)
        sig = _c_signature(fn) if fn else _wasm_signature(name, params, results)
        label, _ = _family(name)
        gate = (fn.amendment if fn and fn.amendment else "—")
        if name not in whitelist:
            unknown.append((module, name))
            label = label or "**not in the whitelist**"
        row = f"| `{name}` | `{sig}` | {label or '—'} | {gate} |"
        if counts is not None:
            # Noise is filtered out of the call-site listing, so a count of 0
            # would be a claim the listing never made. `_g` is imported by
            # every hook and called constantly.
            row += " n/a |" if name in _NOISE else f" {counts.get(name, 0)} |"
        lines.append(row)

    lines.append("")
    seen = {n for _, n, _, _ in imports}
    for prefixes, label, note in _FAMILIES:
        if any(n.startswith(p) for n in seen for p in prefixes):
            lines.append(f"- **{label}** — {note}")

    if unknown:
        lines += [
            "",
            "> **These imports are not in the API whitelist.** xahaud refuses "
            "a hook that imports anything outside it, so the test cannot get "
            "as far as running this hook until they are resolved:",
            "",
        ] + [f"> - `{m}.{n}`" for m, n in unknown]
    lines.append("")
    return lines


def _related_code_section(imports, repo, signatures) -> list[str]:
    """The implementation of each call, quoted from the configured checkout."""
    lines = [
        "Quoted from the configured checkout, so it is the code the test will "
        "actually run against rather than a description of it.",
        "",
    ]
    names = sorted({n for _, n, _, _ in imports if n in signatures})
    if not names:
        lines += ["_No imports with hook-API definitions._", ""]
        return lines

    found_any = False
    for name in names:
        lines.append(f"### `{name}`")
        lines.append("")
        lines.append(f"```c\n{_c_signature(signatures[name])}\n```")
        lines.append("")
        quoted = False
        for finder, path in (
            (repo.find_hook_function, "src/xrpld/app/hook/detail/applyHook.cpp"),
            (repo.find_api_method, "src/xrpld/app/hook/detail/HookAPI.cpp"),
        ):
            try:
                body = finder(name)
            except Exception:                                  # noqa: BLE001
                body = None
            if body:
                quoted = found_any = True
                lines += [f"`{path}`:", "", "```cpp", body.rstrip(), "```", ""]
        if not quoted:
            # Silence here rendered a heading per function with nothing under
            # it — the "looks complete, silently omits" shape the vendored-tree
            # refusal exists to prevent, reproduced one level down.
            lines += ["_Not found in this checkout._", ""]

    if not found_any:
        lines[:0] = [
            "> **Nothing was found for any function.** The configured path is "
            "a directory, but not a xahaud checkout with "
            "`src/xrpld/app/hook/detail/` in it — so every entry below is a "
            "signature with no implementation.",
            "",
        ]
    return lines


def _patch_section(patch_path: Path, full: bool = False) -> list[str]:
    """The branch, as the pieces you need rather than as 30KB of diff.

    Inlining the whole patch was half the document, and most of it is context
    lines around one-line edits — a reader has to reconstruct what each hunk
    means. The one file that is worth having verbatim is `TestEnv.h`, because
    the patch adds it outright: its diff *is* the file, so it can be handed
    over as C++, and it is the class the test constructs. The rest is a
    manifest of what changed and why, pinned so it can be checked.
    """
    from hookz import env_tests_ref as ref

    lines = [
        f"Vendored as the branch's diff against `{ref.BASE_REF}`, so it "
        f"applies to a current checkout. Pinned separately from the xahaud "
        f"port revision, because a branch moves for its own reasons.",
        "",
        f"- branch: `{ref.BRANCH}` @ `{ref.BRANCH_COMMIT[:12]}` "
        f"({ref.BRANCH_COMMIT_DATE})",
        f"- patch: `{patch_path}`",
        f"- sha256: `{ref.PATCH_SHA256}`",
    ]

    try:
        text = patch_path.read_text(errors="replace")
    except OSError as e:
        return lines + ["", f"_Could not read the patch: {e}_", ""]

    drift = ref.check_pin()
    if drift:
        lines += ["", "> **The vendored patch does not match its pin.** "
                  "Everything below is read from the patch as it is on disk, "
                  "so it is accurate — but it is not the revision this "
                  "registry describes:", ""]
        lines += [f"> - {d}" for d in drift]

    rows = ref.files_in_patch(text)
    lines += [
        "",
        f"### What it changes ({len(rows)} files)",
        "",
        "| file | +/- | what it is for |",
        "|---|---|---|",
    ]
    for path, added, removed, is_new in rows:
        churn = f"+{added}" + (f" −{removed}" if removed else "")
        note = ref.FILES.get(path, "_not described in env_tests_ref.FILES_")
        lines.append(f"| `{path}`{' **(new)**' if is_new else ''} "
                     f"| {churn} | {note} |")

    harness = ref.new_file(ref.HARNESS_HEADER, text)
    if harness:
        lines += [
            "",
            f"### `{ref.HARNESS_HEADER}`",
            "",
            "The whole file, not a diff — the patch adds it outright, so this "
            "is exactly what your test compiles against. It is the class the "
            "skeleton below constructs.",
            "",
            "```cpp",
            harness.rstrip(),
            "```",
            "",
        ]

    if full:
        lines += ["### The full diff", "", "```diff", text.rstrip(), "```", ""]
    else:
        lines += [
            f"The remaining changes are one- and two-line edits inside "
            f"existing files; `--full-patch` inlines the complete diff "
            f"({len(text):,} bytes), or read it at `{patch_path}`.",
            "",
        ]
    return lines


def _harness_section(suite: str, name: str, stem: str) -> list[str]:
    return [
        f"`hookz build-test-hooks` compiles your hooks into "
        f"`{suite}_test_hooks.h`, which defines the map "
        f"`{suite.lower()}_test_wasm` keyed by `file:<domain>/<file>.c`. "
        "`HOOK_WASM` below indexes that map; it is defined in the test file, "
        "not by the header.",
        "",
        "```cpp",
        _SKELETON.format(
            header=f"{suite}_test_hooks.h",
            symbol=f"{suite.lower()}_test_wasm",
            suite=suite,
            name=name,
        ).rstrip(),
        "```",
        "",
        "Build and run it:",
        "",
        "```bash",
        "cmake -B build \\",
        "  -DHOOKS_TEST_DIR=$PWD/env-tests \\",
        f"  -DHOOKS_C_DIR=\"<domain>=$PWD/hooks\" \\",
        "  -DHOOKS_TEST_ONLY=ON",
        "cmake --build build -j",
        f"./build/rippled --unittest={suite}",
        "```",
        "",
        "The `<domain>` you pass to `HOOKS_C_DIR` is the same one that appears "
        "in the map key, so `-DHOOKS_C_DIR=\"myhooks=$PWD/hooks\"` makes "
        f"`{stem}.c` reachable as `\"file:myhooks/{stem}.c\"`.",
        "",
        "While iterating:",
        "",
        '- `TESTENV_LOGGING="HooksTrace=trace"` — the hook\'s own `trace()` '
        "output, without unrelated partitions drowning it.",
        '- `env.setPrefix("phase")` — tags every following log line, so a '
        "failure says which phase produced it.",
        "- `env.account(\"alice\")` — creates and reuses by name, and the log "
        "transform rewrites r-addresses to `Account(alice)` in all output.",
        "- `-DHOOKS_COVERAGE=ON` instruments the hooks; **writing the hits "
        "out is the test's job**, not xahaud's. `HOOKS_COVERAGE_DIR` is a "
        "convention the skeleton's `run()` implements — nothing in the branch "
        "reads it — and without `coverageReset`/`coverageLabel`/`coverageDump` "
        "the hits accumulate and are dropped at exit with no error.",
        "",
    ]


def build_context(
    target: Path,
    config,
    *,
    include_impl: bool = True,
    include_patch: bool = True,
    full_patch: bool = False,
    patch_path: Path | None = None,
) -> str:
    """Assemble the document. Raises ContextError for anything the caller fixes.

    TARGET is a hook `.c` or a compiled `.wasm`. Source is worth preferring:
    call-site attribution comes from instrumentation markers, and a finished
    binary does not carry them, so a `.wasm` yields the import list without
    the lines or the resolved arguments.
    """
    from hookz.wasm.whitelist import get_function_signatures, get_import_signatures
    from hookz.xrpl.xahaud import XahaudRepo

    root = _require_checkout(config)
    target = Path(target)
    from_source = target.suffix in (".c", ".h")

    sites: list = []
    degraded: str | None = None

    if from_source:
        try:
            wasm, sites = _call_sites(target, config)
        except Exception as e:                                 # noqa: BLE001
            raise ContextError(
                f"could not compile and instrument {target}: {e}\n"
                "Pass a built .wasm instead for the import list without "
                "call-site attribution.") from e
        if not sites:
            degraded = (
                "The instrumented build carried no `__on_source_line` markers, "
                "so calls could not be attributed to source lines.")
    else:
        try:
            wasm = target.read_bytes()
        except OSError as e:
            raise ContextError(f"could not read {target}: {e}") from e
        degraded = (
            "Built from a compiled `.wasm`, which carries no instrumentation "
            "markers. Pass the hook's `.c` instead to also get every call "
            "site with its source line and resolved arguments.")

    try:
        imports = _imports(wasm)
    except Exception as e:                                     # noqa: BLE001
        raise ContextError(f"{target} is not a wasm module hookz can read: {e}") from e

    # Both read the configured checkout's macro file, and the second also
    # reads the amendment manifest. Outside a handler they escaped as
    # WhitelistError/ManifestError past this function's documented contract —
    # `main()` renders both, but a caller told "raises ContextError" got
    # something else.
    try:
        signatures = get_function_signatures()
        whitelist = get_import_signatures(coverage=True)
    except ValueError as e:
        raise ContextError(
            f"the API whitelist could not be built: {e}\n"
            "That is the configured xahaud checkout or the vendored amendment "
            "manifest, not the hook.") from None

    counts: dict[str, int] = {}
    for _, call in sites:
        counts[call.name] = counts.get(call.name, 0) + 1

    stem = target.stem
    suite = "".join(p.capitalize() for p in stem.replace("-", "_").split("_"))

    head: list[str] = [
        f"# Env-test context for `{target.name}`",
        "",
        "Assembled by `hookz env-test-context`: what this hook does to the "
        "ledger, what those calls do inside xahaud, and what the "
        "external-env-tests harness gives you to arrange them.",
        "",
        "## 1. The hook",
        "",
        f"- path: `{target}`",
        f"- size: {len(wasm):,} bytes"
        + (" (compiled here)" if from_source else ""),
        f"- sha256: `{hashlib.sha256(wasm).hexdigest()}`",
        f"- host functions imported: {len(imports)}"
        + (f", called from {len(sites)} site(s)" if sites else ""),
        f"- xahaud checkout: `{root}`",
    ]

    if degraded:
        head += ["", f"> {degraded}"]

    if not _has_env_tests(root):
        head += [
            "",
            "> **This checkout does not carry the env-tests harness.** "
            "`src/test/jtx/TestEnv.h` is absent, so the skeleton below will "
            "not compile against it yet. The hook-API sections are unaffected "
            "— the branch does not change the API. To get the harness:",
            "",
            "> ```bash",
            f"> git -C {root} apply {_default_patch(patch_path)}",
            "> ```",
        ]
    head.append("")

    sections: list[tuple[str, list[str]]] = [
        ("The surface this hook uses",
         _surface_section(imports, signatures, whitelist,
                          counts if sites else None,
                          impl_below=include_impl)),
    ]
    if sites:
        sections.append(("Where it calls them", _call_site_section(sites, target)))
    if include_impl:
        sections.append(("What each of those calls does",
                         _related_code_section(imports, XahaudRepo(str(root)),
                                               signatures)))
    if include_patch:
        sections.append(("What the external-env-tests branch adds",
                         _patch_section(_default_patch(patch_path),
                                        full=full_patch)))
    sections.append(("A test to start from",
                     _harness_section(suite, stem, stem)))

    out = head
    for i, (title, body) in enumerate(sections, start=2):
        out += [f"## {i}. {title}", ""] + body

    return "\n".join(out)


PATCH_NAME = "xahaud-external-env-tests.patch"


def _default_patch(patch_path: Path | None) -> Path:
    """Where the vendored branch patch lives, installed or in a checkout.

    Packaged copy first: `patches/` sits outside `src/hookz`, so a wheel gets
    it only via the force-include in pyproject, and only under `hookz/data/`.
    A source checkout has no packaged copy, so it falls through to the repo
    path — which is also the one `git diff origin/dev … > patches/…` writes,
    so a developer who regenerates it sees the new one immediately.
    """
    if patch_path is not None:
        return patch_path
    packaged = Path(__file__).resolve().parent.parent / "data" / PATCH_NAME
    if packaged.is_file():
        return packaged
    return Path(__file__).resolve().parents[3] / "patches" / PATCH_NAME
