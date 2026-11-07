"""hooks-compiler, the reference compiler, as hookz drives it.

None of these run Node: `run` is replaced by a fake that records argv and
plays hooks-compiler's part. tests/test_hooks_compiler_live.py runs the real
thing (opt-in; CI enables it).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from hookz import hooks_compiler
from hookz.build_test_hooks import HookBlock, OutputWriter
from hookz.build_test_hooks import TestHookBuilder as HookBuilder
from hookz.cli.main import cli
from hookz.hooks_compiler import (
    SPEC,
    HooksCompilerError,
    compile_source,
    ensure_available,
    headers_digest,
    include_dirs,
    safe_filename,
)

WASM = b"\x00asm\x01\x00\x00\x00reference"
ANNOTATED = (
    "/* hookz:\n"
    " * @audit the guard bound\n"
    " */\n"
    "int64_t hook(uint32_t r) { return 0; }\n"
)


class FakeCompiler:
    """Plays hooks-compiler's CLI: writes -o, prints the --json report."""

    def __init__(self, wasm=WASM, returncode=0, stderr="", report=None,
                 write=True):
        self.wasm = wasm
        self.returncode = returncode
        self.stderr = stderr
        self.report = report
        self.write = write
        self.calls = []

    def __call__(self, argv, **kwargs):
        sent = {}
        if "build" in argv:
            src = Path(argv[argv.index("build") + 1])
            sent = {"name": src.name, "text": src.read_text(), "staged": {}}
            if "-I" in argv:
                root = Path(argv[argv.index("-I") + 1])
                sent["staged"] = {
                    p.relative_to(root).as_posix(): p.read_text()
                    for p in sorted(root.rglob("*")) if p.is_file()
                }
        self.calls.append(SimpleNamespace(argv=argv, kwargs=kwargs, **sent))
        stdout = ""
        if "-o" in argv and self.returncode == 0:
            if self.write:
                Path(argv[argv.index("-o") + 1]).write_bytes(self.wasm)
            report = self.report or {
                "sha256": hashlib.sha256(self.wasm).hexdigest(),
                "imports": ["env._g", "env.accept"],
                "exports": ["hook"],
                "rawSize": 300,
                "optimizedSize": 200,
                "finalSize": len(self.wasm),
            }
            stdout = "warming up\n" + json.dumps(report) + "\n"
        return subprocess.CompletedProcess(argv, self.returncode, stdout,
                                           self.stderr)


class TestCompileSource:
    def test_runs_the_pinned_package_through_npx(self, tmp_path):
        fake = FakeCompiler()
        compile_source("int x;", npx="/bin/npx", run=fake)

        argv = fake.calls[0].argv
        assert argv[:3] == ["/bin/npx", "--yes", SPEC]
        assert argv[3] == "build"
        assert "--json" in argv

    def test_returns_the_exact_bytes_and_their_provenance(self):
        result = compile_source("int x;", npx="npx", run=FakeCompiler())

        assert result.wasm == WASM
        assert result.compiler == SPEC
        assert result.wasm_sha256 == hashlib.sha256(WASM).hexdigest()
        assert result.imports == ("env._g", "env.accept")
        assert result.exports == ("hook",)

    def test_annotations_are_stripped_before_the_compiler_sees_them(self):
        """Annotated and plain sources must compile to the same bytes."""
        fake = FakeCompiler()
        result = compile_source(ANNOTATED, npx="npx", run=fake)

        assert "@audit" not in fake.calls[0].text
        assert result.source_sha256 == hashlib.sha256(
            fake.calls[0].text.encode()
        ).hexdigest()

    @pytest.mark.parametrize(
        "given, sent",
        [("reward.c", "reward.c"), ("dir/tip_bot-2.c", "tip_bot-2.c"),
         ("hook.cpp", "hook.c"), ("../evil name.c", "hook.c"),
         ("stdin", "hook.c")],
    )
    def test_the_entry_name_is_a_plain_c_basename(self, given, sent):
        """hooks-compiler picks C or C++ by extension and keys by basename."""
        assert safe_filename(given) == sent
        fake = FakeCompiler()
        compile_source("int x;", filename=given, npx="npx", run=fake)
        assert fake.calls[0].name == sent

    @staticmethod
    def _tree(root, files):
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return root

    def test_every_root_is_staged_into_one_tree(self, tmp_path):
        """hooks-compiler compiles against one tree keyed by relative path;
        nested headers beside the source keep their place in it."""
        src = self._tree(tmp_path / "src", {"s.h": "s", "sub/n.h": "n"})
        a = self._tree(tmp_path / "a", {"x.h": "x"})
        b = self._tree(tmp_path / "b", {"deep/y.h": "y"})
        fake = FakeCompiler()
        compile_source("int x;", include_dirs=[a, b], source_dir=src,
                       npx="npx", run=fake)

        argv = fake.calls[0].argv
        assert argv.count("-I") == 1
        assert fake.calls[0].staged == {
            "s.h": "s", "sub/n.h": "n", "x.h": "x", "deep/y.h": "y"}

    @pytest.mark.parametrize("first, second", [("src", "a"), ("a", "b")])
    def test_a_name_two_roots_supply_differently_is_refused(
        self, tmp_path, first, second
    ):
        """codex's include probe: a sibling against an -I, and -I A against
        -I B whose own header includes its neighbour. clang and the merged
        tree can pick different files, so neither is guessed."""
        roots = {name: self._tree(tmp_path / name, {"choice.h": name})
                 for name in ("src", "a", "b")}
        fake = FakeCompiler()

        with pytest.raises(HooksCompilerError, match="choice.h") as e:
            compile_source(
                "int x;",
                source_dir=roots[first] if first == "src" else None,
                include_dirs=[roots[n] for n in (first, second) if n != "src"],
                npx="npx", run=fake)

        assert str(roots[first] / "choice.h") in str(e.value)
        assert str(roots[second] / "choice.h") in str(e.value)
        assert fake.calls == []

    def test_identical_copies_are_not_a_conflict(self, tmp_path):
        """The e2e layout: the hook's directory is also on the -I path."""
        misc = self._tree(tmp_path / "misc", {"encode_macros.h": "m"})
        fake = FakeCompiler()
        compile_source("int x;", source_dir=misc, include_dirs=[misc],
                       npx="npx", run=fake)

        assert fake.calls[0].staged == {"encode_macros.h": "m"}

    def test_only_headers_outside_hidden_directories_are_staged(self, tmp_path):
        root = self._tree(tmp_path / "a", {
            "x.h": "x", "hook.c": "c", "hook.wasm": "w", ".git/y.h": "y"})
        fake = FakeCompiler()
        compile_source("int x;", include_dirs=[root], npx="npx", run=fake)

        assert fake.calls[0].staged == {"x.h": "x"}

    def test_no_headers_means_no_include_flag(self, tmp_path):
        fake = FakeCompiler()
        compile_source("int x;", include_dirs=[tmp_path / "nope"],
                       source_dir=tmp_path, npx="npx", run=fake)

        assert "-I" not in fake.calls[0].argv

    def test_include_dirs_follow_clang_order(self, tmp_path, monkeypatch):
        """extra_cflags -I entries (both spellings, relative to the working
        directory), then the hook headers."""
        monkeypatch.chdir(tmp_path)
        config = SimpleNamespace(
            extra_cflags=["-Ihooks/misc", "-O2", "-I", "/abs/inc", "-DX"],
            hook_headers=Path("/hdrs"),
        )

        assert include_dirs(config) == [
            (tmp_path / "hooks/misc").resolve(), Path("/abs/inc").resolve(),
            Path("/hdrs"),
        ]

    def test_the_digest_covers_every_include_dir_and_their_order(
        self, tmp_path
    ):
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir(), b.mkdir()
        (a / "x.h").write_text("1")
        (b / "y.h").write_text("2")
        before = headers_digest([a, b])
        (b / "y.h").write_text("3")

        assert headers_digest([a, b]) != before
        assert headers_digest([b, a]) != headers_digest([a, b])
        (a / "notes.txt").write_text("not a header")
        after = headers_digest([a, b])
        (a / "notes.txt").write_text("still not one")
        assert headers_digest([a, b]) == after  # only what is staged counts

    def test_no_npx_says_what_to_install(self, monkeypatch):
        monkeypatch.setattr(hooks_compiler.shutil, "which", lambda name: None)

        with pytest.raises(HooksCompilerError, match="install Node"):
            compile_source("int x;", run=FakeCompiler())

    def test_a_compile_error_carries_clangs_diagnostics(self):
        fake = FakeCompiler(returncode=1,
                            stderr="/src/hook.c:1:1: error: unknown type name")

        with pytest.raises(HooksCompilerError, match="unknown type name"):
            compile_source("bad", npx="npx", run=fake)

    def test_a_timeout_is_an_error_not_a_hang(self):
        def slow(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        with pytest.raises(HooksCompilerError, match="did not finish"):
            compile_source("int x;", npx="npx", run=slow, timeout=1)

    def test_a_report_that_disagrees_with_the_file_is_refused(self):
        fake = FakeCompiler(report={"sha256": "0" * 64})

        with pytest.raises(HooksCompilerError, match="reported sha256"):
            compile_source("int x;", npx="npx", run=fake)

    def test_output_that_is_not_wasm_is_refused(self):
        with pytest.raises(HooksCompilerError, match="not a WebAssembly"):
            compile_source("int x;", npx="npx", run=FakeCompiler(wasm=b"nope"))

    def test_no_output_file_is_refused(self):
        with pytest.raises(HooksCompilerError, match="wrote no output"):
            compile_source("int x;", npx="npx", run=FakeCompiler(write=False))

    def test_ensure_available_fetches_once_with_help(self):
        fake = FakeCompiler()
        ensure_available(npx="npx", run=fake)

        assert fake.calls[0].argv == ["npx", "--yes", SPEC, "--help"]

    def test_ensure_available_reports_a_failed_fetch(self):
        fake = FakeCompiler(returncode=1, stderr="npm error network")

        with pytest.raises(HooksCompilerError, match="npm error network"):
            ensure_available(npx="npx", run=fake)


@pytest.fixture
def reference(monkeypatch):
    """Stub compile_source as build_test_hooks and the CLI import it."""
    calls = []

    def fake(source, **kwargs):
        calls.append((source, kwargs))
        text, digest = hooks_compiler.stripped_source(source)
        return SimpleNamespace(
            wasm=WASM, compiler=SPEC, source_sha256=digest,
            wasm_sha256=hashlib.sha256(WASM).hexdigest(),
            raw_size=300, optimized_size=200,
        )

    monkeypatch.setattr(hooks_compiler, "compile_source", fake)
    monkeypatch.setattr(hooks_compiler, "ensure_available", lambda **k: None)
    return calls


class TestBuildTestHooks:
    @staticmethod
    def _block(source="int64_t hook(uint32_t r){return 0;}", **kw):
        return HookBlock(map_key=source, source=source, filename="hook.c",
                         line_number=1, is_file_ref=False, **kw)

    @pytest.fixture
    def builder(self, tmp_path, reference, monkeypatch):
        """A hooks-compiler builder over a real header tree, with a stub
        compiler whose output depends on that tree, as the real one's does."""
        headers = tmp_path / "hook"
        headers.mkdir()
        (headers / "answer.h").write_text("#define ANSWER 1\n")
        monkeypatch.setattr(
            "hookz.config.load_config",
            lambda **k: SimpleNamespace(hook_headers=headers),
        )
        monkeypatch.setattr("hookz.wasm.guard.validate_guards", lambda wasm: None)

        def compile_source(source, **kwargs):
            reference.append((source, kwargs))
            tree = (kwargs["include_dirs"][-1] / "answer.h").read_bytes()
            return SimpleNamespace(wasm=WASM + tree)

        monkeypatch.setattr(hooks_compiler, "compile_source", compile_source)
        test_file = tmp_path / "Proof_test.cpp"
        test_file.write_text("")
        b = HookBuilder(test_file, compiler="hooks-compiler",
                        cache_dir=tmp_path / "cache")
        b.headers = headers
        return b

    def test_a_repeat_build_is_served_from_the_cache(self, builder, reference):
        builder._compile_block(0, self._block())
        builder._compile_block(0, self._block())

        assert len(reference) == 1

    def test_a_cached_build_under_another_version_is_not_reused(
        self, builder, reference
    ):
        block = self._block()
        builder.cache.put(block.source, b"older", compiler="hooks-compiler@0.1.0")

        _, _, wasm = builder._compile_block(0, block)

        assert wasm.startswith(WASM)
        assert len(reference) == 1

    def test_a_header_edit_misses_the_cache(self, builder, reference):
        """codex's reproducer: the source and version unchanged, ANSWER 1 -> 2
        in an included header, and the cache still handed back the build
        made with 1. The header tree is in the key now."""
        _, _, first = builder._compile_block(0, self._block())
        (builder.headers / "answer.h").write_text("#define ANSWER 2\n")
        fresh = HookBuilder(builder.input_file, compiler="hooks-compiler",
                            cache_dir=builder.cache.cache_dir)

        _, _, second = fresh._compile_block(0, self._block())

        assert len(reference) == 2
        assert first != second

    def test_the_entry_name_is_in_the_key(self, builder, reference):
        """hooks-compiler compiles under that name, so __FILE__ and the C/C++
        choice can depend on it."""
        builder._compile_block(0, self._block())
        renamed = HookBlock(map_key="x", source=self._block().source,
                            filename="other.c", line_number=1,
                            is_file_ref=False)

        builder._compile_block(1, renamed)

        assert len(reference) == 2

    def test_jobs_are_capped_for_memory(self, tmp_path):
        test_file = tmp_path / "Proof_test.cpp"
        test_file.write_text("")
        builder = HookBuilder(test_file, jobs=32, compiler="hooks-compiler",
                                  cache_dir=tmp_path / "cache")

        assert builder.jobs == 4

    def test_wat_is_refused_rather_than_built_locally(self, tmp_path):
        test_file = tmp_path / "Proof_test.cpp"
        test_file.write_text("")
        builder = HookBuilder(test_file, compiler="hooks-compiler",
                                  no_cache=True)

        with pytest.raises(RuntimeError, match="C source only"):
            builder._compile_block(0, self._block("(module)"))

    def test_the_header_and_manifest_record_the_compiler(self, tmp_path):
        writer = OutputWriter(tmp_path / "Proof_hooks.h", "proof_wasm",
                              cache_dir=tmp_path, compiler="hooks-compiler")
        block = self._block(ANNOTATED)
        compiled = {0: (block, WASM)}

        writer.write(compiled, force_write=True)
        manifest = writer.write_python_manifest(compiled).read_text()
        header = (tmp_path / "Proof_hooks.h").read_text()

        digest = hooks_compiler.stripped_source(ANNOTATED)[1]
        assert f"hookz-build-mode: {SPEC}" in header
        assert f"source-sha256={digest}" in header
        assert f"'compiler': {SPEC!r}" in manifest
        assert digest in manifest

    def test_the_compiler_is_given_the_configured_headers(
        self, tmp_path, reference, monkeypatch
    ):
        monkeypatch.setattr(
            "hookz.config.load_config",
            lambda **k: SimpleNamespace(hook_headers=Path("/hdrs")),
        )
        test_file = tmp_path / "Proof_test.cpp"
        test_file.write_text("")
        builder = HookBuilder(test_file, compiler="hooks-compiler",
                                  no_cache=True)
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm: None
        )

        builder._compile_block(0, self._block())

        assert reference[0][1]["include_dirs"] == [Path("/hdrs")]


class TestCli:
    @staticmethod
    def _run(args, **env):
        return CliRunner().invoke(cli, args, env=env)

    @pytest.mark.parametrize("command", ["build", "build-test-hooks"])
    @pytest.mark.parametrize("flag", ["--buildbox", "--build-box"])
    def test_the_retired_flag_points_at_the_new_one(self, tmp_path, command,
                                                    flag):
        source = tmp_path / ("hook.c" if command == "build" else "X_test.cpp")
        source.write_text("")

        out = self._run([command, str(source), flag])

        assert out.exit_code == 2, out.output
        assert "retired" in out.output
        assert "--hooks-compiler" in out.output

    def test_a_file_named_stdin_c_keeps_its_directory(
        self, tmp_path, reference, monkeypatch
    ):
        """codex's R3: the name used to decide whether input was piped."""
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm, **kw: SimpleNamespace(waived=False, hook_wce=1),
        )
        monkeypatch.setattr("hookz.cli.main._validate_wasm", lambda *a: None)
        monkeypatch.setattr("hookz.cli.main._report_waived", lambda *a: None)
        source = tmp_path / "stdin.c"
        source.write_text("int x;")

        self._run(["build", str(source), "-o", str(tmp_path / "o.wasm"),
                   "--hooks-compiler"])

        assert reference[0][1]["source_dir"] == tmp_path.resolve()

    def test_piped_input_has_no_directory(self, tmp_path, reference,
                                          monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm, **kw: SimpleNamespace(waived=False, hook_wce=1),
        )
        monkeypatch.setattr("hookz.cli.main._validate_wasm", lambda *a: None)
        monkeypatch.setattr("hookz.cli.main._report_waived", lambda *a: None)

        CliRunner().invoke(cli, ["build", "-", "-o", str(tmp_path / "o.wasm"),
                                 "--hooks-compiler"], input="int x;")

        assert reference[0][1]["source_dir"] is None
        assert reference[0][1]["filename"] == "stdin.c"

    @pytest.mark.parametrize("command", ["build", "build-test-hooks"])
    def test_the_retired_env_switch_is_refused(self, tmp_path, command):
        """xahaud's external-env-tests CMake still turns HOOKZ_BUILDBOX=1
        into --buildbox; a local build under it would be the wrong bytes."""
        source = tmp_path / ("hook.c" if command == "build" else "X_test.cpp")
        source.write_text("")

        out = self._run([command, str(source)], HOOKZ_BUILDBOX="1")

        assert out.exit_code == 2, out.output
        assert "HOOKZ_HOOKS_COMPILER=1" in out.output

    def test_build_writes_the_reference_bytes_after_a_local_guard_check(
        self, tmp_path, reference, monkeypatch
    ):
        checked = []
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm, **kw: checked.append(wasm)
            or SimpleNamespace(waived=False, hook_wce=1),
        )
        monkeypatch.setattr("hookz.cli.main._validate_wasm", lambda *a: None)
        monkeypatch.setattr("hookz.cli.main._report_waived", lambda *a: None)
        source = tmp_path / "reward.c"
        source.write_text(ANNOTATED)
        output = tmp_path / "reward.wasm"

        out = self._run(["build", str(source), "-o", str(output),
                         "--hooks-compiler"])

        assert out.exit_code == 0, out.output
        assert f"via {SPEC}" in out.output
        assert output.read_bytes() == WASM
        assert checked == [WASM]
        assert reference[0][1]["filename"] == "reward.c"

    def test_build_test_hooks_takes_the_compiler_by_name(self, tmp_path):
        source = tmp_path / "X_test.cpp"
        source.write_text("")

        out = self._run(["build-test-hooks", str(source), "--compiler",
                         "hooks-compiler", "--hook-coverage"])

        assert out.exit_code == 2, out.output
        assert "--hook-coverage" in out.output
