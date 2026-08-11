from pathlib import Path

import pytest

import hookz.build_test_hooks as build_test_hooks
from hookz.build_test_hooks import (
    HookBlock,
    SourceExtractor,
    TestHookBuilder as HookBuilder,
)


def test_source_extractor_discovers_inline_and_file_quickjs_hooks(tmp_path: Path):
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "external.ts").write_text("export function hook(): never { throw 1 }")
    test_file = tmp_path / "Proof_test.cpp"
    test_file.write_text(
        """
        auto c = R"[test.hook](int64_t hook(uint32_t r) { return 0; })[test.hook]";
        auto js = R"[test.jshook](export function hook() {})[test.jshook]";
        auto ts = R"[test.tshook](export function hook(_r: number) {})[test.tshook]";
        auto external = "file:demo/external.ts";
        """
    )

    blocks = SourceExtractor(test_file, {"demo": sources}).extract()

    assert [block.suffix for block in blocks] == [".c", ".js", ".ts", ".ts"]
    assert blocks[-1].map_key == "file:demo/external.ts"


def test_quickjs_compiler_command_receives_source_extension(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    compiler = tmp_path / "fake-qjs-compiler"
    compiler.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        "source = pathlib.Path(sys.argv[1])\n"
        "output = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
        "output.write_bytes(source.suffix.encode() + b':qjsc')\n"
    )
    compiler.chmod(0o755)
    monkeypatch.setenv("QJS_HOOK_COMPILER", str(compiler))

    assert (
        build_test_hooks._compile_hook_quickjs("let x: number = 1", "x.ts")
        == b".ts:qjsc"
    )


def test_quickjs_blocks_bypass_persistent_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    test_file = tmp_path / "Proof_test.cpp"
    test_file.write_text("")
    builder = HookBuilder(test_file, cache_dir=tmp_path / "cache")
    block = HookBlock(
        map_key="file:demo/hook.ts",
        source="export function hook() {}",
        filename="hook.ts",
        line_number=1,
        is_file_ref=True,
    )
    monkeypatch.setattr(
        build_test_hooks,
        "_compile_hook_quickjs",
        lambda source, filename: b"qjsc",
    )
    monkeypatch.setattr(
        builder.cache,
        "get",
        lambda *args, **kwargs: pytest.fail("QuickJS cache lookup must be skipped"),
    )
    monkeypatch.setattr(
        builder.cache,
        "put",
        lambda *args, **kwargs: pytest.fail("QuickJS cache write must be skipped"),
    )

    assert builder._compile_block(0, block)[2] == b"qjsc"
