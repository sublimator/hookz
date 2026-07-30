"""Buildbox client and CLI contracts without depending on the live service."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest
from click.testing import CliRunner

from hookz import buildbox
from hookz.build_test_hooks import (
    HookBlock,
    OutputWriter,
    TestHookBuilder as HookBuilder,
    _compile_hook_buildbox,
)
from hookz.cli.main import _build_buildbox, cli


WASM = b"\x00asm\x01\x00\x00\x00canonical"
SOURCE = """\
#include <stdint.h>
//@@ audit annotation
extern int32_t _g(uint32_t, uint32_t);
extern int64_t accept(uint32_t, uint32_t, int64_t);
int64_t hook(uint32_t reserved) {
    _g(1, 1);
    return accept(0, 0, 0);
}
"""


def response(
    *,
    status: int = 200,
    success: bool = True,
    output: str | None = None,
    message: str = "Success",
    headers: dict[str, str] | None = None,
    tasks: list[dict] | None = None,
) -> buildbox._Response:
    import base64

    body = json.dumps(
        {
            "success": success,
            "message": message,
            "output": (
                base64.b64encode(WASM).decode()
                if output is None and success
                else output or ""
            ),
            "tasks": tasks or [],
        }
    ).encode()
    return buildbox._Response(status, body, headers or {})


class TestRequest:
    def test_exact_payload_strips_annotations_and_is_fingerprinted(self):
        request = buildbox.prepare_request(
            SOURCE, filename="my-hook.c", options="-O3"
        )
        payload = json.loads(request.body)

        assert payload == {
            "compress": False,
            "files": [{
                "name": "my-hook.c",
                "options": "-O3",
                "src": SOURCE.replace("//@@ audit annotation\n", ""),
                "type": "c",
            }],
            "output": "wasm",
            "strip": True,
        }
        assert request.sha256 == hashlib.sha256(request.body).hexdigest()
        assert request.source_sha256 == hashlib.sha256(
            payload["files"][0]["src"].encode()
        ).hexdigest()

    @pytest.mark.parametrize("unsafe", ["two.parts.c", "x c.c", ""])
    def test_unsafe_or_unsupported_filename_falls_back(self, unsafe):
        assert buildbox.prepare_request(SOURCE, filename=unsafe).filename == "hook.c"

    def test_paths_are_reduced_to_a_safe_basename(self):
        assert buildbox.prepare_request(
            SOURCE, filename="../x.c"
        ).filename == "x.c"


class TestRetryPolicy:
    def test_local_default_is_two_attempts(self):
        assert buildbox.RetryPolicy.from_environment({}).attempts == 2

    def test_ci_default_is_four_attempts(self):
        assert buildbox.RetryPolicy.from_environment({"CI": "true"}).attempts == 4

    def test_explicit_attempts_win_in_ci(self):
        policy = buildbox.RetryPolicy.from_environment({
            "CI": "true",
            "HOOKZ_BUILDBOX_ATTEMPTS": "3",
        })
        assert policy.attempts == 3

    @pytest.mark.parametrize("value", ["0", "11"])
    def test_attempts_are_bounded(self, value):
        with pytest.raises(buildbox.BuildboxError, match="between 1 and 10"):
            buildbox.RetryPolicy.from_environment({
                "HOOKZ_BUILDBOX_ATTEMPTS": value,
            })

    def test_attempts_must_be_an_integer(self):
        with pytest.raises(buildbox.BuildboxError, match="integer"):
            buildbox.RetryPolicy.from_environment({
                "HOOKZ_BUILDBOX_ATTEMPTS": "many",
            })

    @pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0"])
    def test_timeout_must_be_finite_and_positive(self, value, monkeypatch):
        monkeypatch.setenv("HOOKZ_BUILDBOX_TIMEOUT", value)
        with pytest.raises(buildbox.BuildboxError, match="finite number"):
            buildbox.timeout_from_environment()


class TestCompileSource:
    def test_returns_artifact_and_provenance(self, monkeypatch):
        monkeypatch.setattr(buildbox, "_post", lambda *args: response())

        result = buildbox.compile_source(
            SOURCE,
            endpoint="https://compiler.example/api/build",
            retry_policy=buildbox.RetryPolicy(1),
        )

        assert result.wasm == WASM
        assert result.endpoint == "https://compiler.example/api/build"
        assert result.attempts == 1
        assert result.wasm_sha256 == hashlib.sha256(WASM).hexdigest()
        assert len(result.request_sha256) == 64

    def test_retries_transient_http_then_succeeds(self, monkeypatch):
        replies = iter([
            buildbox._Response(503, b"busy", {}),
            response(),
        ])
        calls = []
        sleeps = []

        def post(*args):
            calls.append(args)
            return next(replies)

        monkeypatch.setattr(buildbox, "_post", post)
        result = buildbox.compile_source(
            SOURCE,
            retry_policy=buildbox.RetryPolicy(3),
            sleep=sleeps.append,
        )

        assert result.attempts == 2
        assert len(calls) == 2
        assert sleeps == [1.0]

    def test_respects_bounded_retry_after(self, monkeypatch):
        replies = iter([
            buildbox._Response(429, b"slow down", {"Retry-After": "90"}),
            response(),
        ])
        monkeypatch.setattr(buildbox, "_post", lambda *args: next(replies))
        sleeps = []

        buildbox.compile_source(
            SOURCE,
            retry_policy=buildbox.RetryPolicy(2),
            sleep=sleeps.append,
        )

        assert sleeps == [30.0]

    def test_build_rejection_is_not_retried(self, monkeypatch):
        calls = 0

        def post(*args):
            nonlocal calls
            calls += 1
            return response(
                success=False,
                message="Build error",
                tasks=[{
                    "name": "building wasm",
                    "success": False,
                    "console": "bad source",
                }],
            )

        monkeypatch.setattr(buildbox, "_post", post)
        with pytest.raises(buildbox.BuildboxRejected, match="bad source"):
            buildbox.compile_source(
                SOURCE, retry_policy=buildbox.RetryPolicy(4), sleep=lambda _: None
            )
        assert calls == 1

    def test_nontransient_http_is_not_retried(self, monkeypatch):
        calls = 0

        def post(*args):
            nonlocal calls
            calls += 1
            return buildbox._Response(400, b"bad request", {})

        monkeypatch.setattr(buildbox, "_post", post)
        with pytest.raises(buildbox.BuildboxRejected, match="HTTP 400"):
            buildbox.compile_source(
                SOURCE, retry_policy=buildbox.RetryPolicy(4), sleep=lambda _: None
            )
        assert calls == 1

    def test_malformed_success_exhausts_retries(self, monkeypatch):
        monkeypatch.setattr(
            buildbox,
            "_post",
            lambda *args: response(output="not base64"),
        )
        with pytest.raises(buildbox.BuildboxUnavailable, match="2 attempt"):
            buildbox.compile_source(
                SOURCE, retry_policy=buildbox.RetryPolicy(2), sleep=lambda _: None
            )

    def test_malformed_tasks_field_is_retried(self, monkeypatch):
        malformed = buildbox._Response(
            200,
            json.dumps({
                "success": True,
                "output": "AGFzbQEAAAA=",
                "tasks": None,
            }).encode(),
            {},
        )
        replies = iter([malformed, response()])
        monkeypatch.setattr(buildbox, "_post", lambda *args: next(replies))

        result = buildbox.compile_source(
            SOURCE,
            retry_policy=buildbox.RetryPolicy(2),
            sleep=lambda _: None,
        )

        assert result.attempts == 2
        assert result.wasm == WASM

    def test_http_error_body_read_failure_uses_retry_boundary(
        self, monkeypatch
    ):
        calls = 0

        class BrokenBody:
            def read(self, _limit):
                raise TimeoutError("body stalled")

            def close(self):
                pass

        def fail(*args, **kwargs):
            nonlocal calls
            calls += 1
            raise HTTPError(
                buildbox.DEFAULT_ENDPOINT,
                503,
                "Service Unavailable",
                {},
                BrokenBody(),
            )

        monkeypatch.setattr(buildbox, "urlopen", fail)
        with pytest.raises(buildbox.BuildboxUnavailable, match="2 attempt"):
            buildbox.compile_source(
                SOURCE,
                retry_policy=buildbox.RetryPolicy(2),
                sleep=lambda _: None,
            )
        assert calls == 2


class TestBuildCommand:
    def test_remote_artifact_is_locally_validated_before_write(
        self, tmp_path, monkeypatch, capsys
    ):
        source = tmp_path / "hook.c"
        source.write_text(SOURCE)
        output = tmp_path / "hook.wasm"
        result = buildbox.BuildboxResult(
            wasm=WASM,
            endpoint=buildbox.DEFAULT_ENDPOINT,
            request_sha256="a" * 64,
            source_sha256="b" * 64,
            wasm_sha256=hashlib.sha256(WASM).hexdigest(),
            filename="hook.c",
            options="-O3",
            attempts=2,
        )
        monkeypatch.setattr(buildbox, "compile_source", lambda *a, **k: result)
        import hookz.cli.main as main_mod
        import hookz.wasm.guard as guard_mod

        checked = []

        def validate(wasm, **kwargs):
            checked.append(wasm)
            return SimpleNamespace(waived=False, hook_wce=9)

        monkeypatch.setattr(guard_mod, "validate_guards", validate)
        monkeypatch.setattr(main_mod, "_validate_wasm", lambda *args: None)

        with pytest.raises(SystemExit) as exc:
            _build_buildbox(source, output)

        assert exc.value.code == 0
        assert checked == [WASM]
        assert output.read_bytes() == WASM
        text = capsys.readouterr().out
        assert "canonical buildbox" in text
        assert "attempts: 2" in text

    def test_remote_failure_does_not_fall_back_or_write(
        self, tmp_path, monkeypatch, capsys
    ):
        source = tmp_path / "hook.c"
        source.write_text(SOURCE)
        output = tmp_path / "hook.wasm"

        def unavailable(*args, **kwargs):
            raise buildbox.BuildboxUnavailable("service down")

        monkeypatch.setattr(buildbox, "compile_source", unavailable)
        with pytest.raises(SystemExit) as exc:
            _build_buildbox(source, output)

        assert exc.value.code == 1
        assert not output.exists()
        assert "service down" in capsys.readouterr().out

    @pytest.mark.parametrize("flag", ["--buildbox", "--build-box"])
    def test_both_spellings_select_remote_mode(self, tmp_path, monkeypatch, flag):
        source = tmp_path / "hook.c"
        source.write_text(SOURCE)
        selected = []

        def remote(*args, **kwargs):
            selected.append(kwargs)
            raise SystemExit(0)

        monkeypatch.setattr("hookz.cli.main._build_buildbox", remote)
        result = CliRunner().invoke(cli, ["build", str(source), flag])
        assert result.exit_code == 0
        assert len(selected) == 1

    def test_remote_and_local_pipeline_are_mutually_exclusive(self, tmp_path):
        source = tmp_path / "hook.c"
        source.write_text(SOURCE)
        result = CliRunner().invoke(
            cli,
            ["build", str(source), "--buildbox", "--pipeline", "debug"],
        )
        assert result.exit_code == 2
        assert "cannot be combined" in result.output

    def test_ci_environment_can_select_remote_mode(self, tmp_path, monkeypatch):
        source = tmp_path / "hook.c"
        source.write_text(SOURCE)
        selected = []

        def remote(*args, **kwargs):
            selected.append(kwargs)
            raise SystemExit(0)

        monkeypatch.setattr("hookz.cli.main._build_buildbox", remote)
        result = CliRunner().invoke(
            cli,
            ["build", str(source)],
            env={"HOOKZ_BUILDBOX": "1"},
        )
        assert result.exit_code == 0
        assert len(selected) == 1

    def test_stdin_uses_a_stable_request_filename(self, monkeypatch):
        selected = []

        def remote(*args, **kwargs):
            selected.append(kwargs)
            raise SystemExit(0)

        monkeypatch.setattr("hookz.cli.main._build_buildbox", remote)
        result = CliRunner().invoke(
            cli,
            ["build", "-", "--buildbox"],
            input=SOURCE,
        )

        assert result.exit_code == 0
        assert selected[0]["request_filename"] == "stdin.c"


class TestBuildTestHooks:
    def test_traversal_never_reaches_remote_compiler(
        self, tmp_path, monkeypatch
    ):
        hooks = tmp_path / "hooks"
        hooks.mkdir()
        (tmp_path / "secret.c").write_text(SOURCE)
        test_file = tmp_path / "Proof_test.cpp"
        test_file.write_text('auto hook = "file:audit/../secret.c";\n')
        calls = []
        monkeypatch.setattr(
            buildbox,
            "compile_source",
            lambda *args, **kwargs: calls.append((args, kwargs)),
        )
        builder = HookBuilder(
            test_file,
            compiler="buildbox",
            hooks_c_dirs={"audit": hooks},
            cache_dir=tmp_path / "cache",
        )

        with pytest.raises(RuntimeError, match="escapes domain"):
            builder.build()
        assert calls == []

    def test_symlink_escape_never_reaches_remote_compiler(
        self, tmp_path, monkeypatch
    ):
        hooks = tmp_path / "hooks"
        hooks.mkdir()
        secret = tmp_path / "secret.c"
        secret.write_text(SOURCE)
        (hooks / "linked.c").symlink_to(secret)
        test_file = tmp_path / "Proof_test.cpp"
        test_file.write_text('auto hook = "file:audit/linked.c";\n')
        calls = []
        monkeypatch.setattr(
            buildbox,
            "compile_source",
            lambda *args, **kwargs: calls.append((args, kwargs)),
        )
        builder = HookBuilder(
            test_file,
            compiler="buildbox",
            hooks_c_dirs={"audit": hooks},
            cache_dir=tmp_path / "cache",
        )

        with pytest.raises(RuntimeError, match="escapes domain"):
            builder.build()
        assert calls == []

    def test_remote_artifact_is_guard_checked(self, monkeypatch):
        checked = []
        monkeypatch.setattr(
            buildbox,
            "compile_source",
            lambda *args, **kwargs: SimpleNamespace(wasm=WASM),
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm: checked.append(wasm),
        )

        assert _compile_hook_buildbox(
            SOURCE,
            "hook.c",
            endpoint=buildbox.DEFAULT_ENDPOINT,
            options="-O3",
        ) == WASM
        assert checked == [WASM]

    def test_remote_header_and_manifest_record_provenance(self, tmp_path):
        output = tmp_path / "Proof_test_hooks.h"
        writer = OutputWriter(
            output,
            "proof_wasm",
            cache_dir=tmp_path / "cache",
            compiler="buildbox",
            buildbox_endpoint="https://compiler.example/api/build",
            buildbox_options="-O3",
        )
        block = HookBlock(
            map_key="file:audit/hook.c",
            source=SOURCE,
            filename="hook.c",
            line_number=10,
            is_file_ref=True,
        )

        writer.write({0: (block, WASM)})
        manifest = writer.write_python_manifest({0: (block, WASM)})

        header = output.read_text()
        assert "hookz-build-mode: buildbox" in header
        assert "request-sha256=" in header
        assert hashlib.sha256(WASM).hexdigest() in header
        manifest_text = manifest.read_text()
        assert "'mode': 'buildbox'" in manifest_text
        assert "'local_fallback': False" in manifest_text
        assert "'wasm_sha256'" in manifest_text

    def test_remote_builder_disables_persistent_cache_and_caps_workers(
        self, tmp_path
    ):
        test_file = tmp_path / "Proof_test.cpp"
        test_file.write_text("")
        builder = HookBuilder(
            test_file,
            compiler="buildbox",
            jobs=64,
            cache_dir=tmp_path / "cache",
        )
        assert builder.cache is None
        assert builder.jobs == 4

    def test_remote_builder_refuses_to_compile_wat_locally(self, tmp_path):
        test_file = tmp_path / "Proof_test.cpp"
        test_file.write_text("")
        builder = HookBuilder(
            test_file,
            compiler="buildbox",
            cache_dir=tmp_path / "cache",
        )
        block = HookBlock(
            map_key="(module)",
            source="(module)",
            filename="inline.wat",
            line_number=1,
            is_file_ref=False,
        )
        with pytest.raises(RuntimeError, match="refusing to compile WAT locally"):
            builder._compile_block(0, block)

    def test_remote_coverage_is_rejected_at_cli_boundary(self, tmp_path):
        test_file = tmp_path / "Proof_test.cpp"
        test_file.write_text("")
        result = CliRunner().invoke(
            cli,
            [
                "build-test-hooks",
                str(test_file),
                "--buildbox",
                "--hook-coverage",
            ],
        )
        assert result.exit_code == 2
        assert "cannot be combined" in result.output

    def test_ci_environment_selects_remote_test_hook_builder(
        self, tmp_path, monkeypatch
    ):
        test_file = tmp_path / "Proof_test.cpp"
        test_file.write_text("")
        selected = []

        class FakeBuilder:
            def __init__(self, **kwargs):
                selected.append(kwargs)

            def build(self):
                pass

        monkeypatch.setattr(
            "hookz.build_test_hooks.TestHookBuilder", FakeBuilder
        )
        result = CliRunner().invoke(
            cli,
            ["build-test-hooks", str(test_file)],
            env={"HOOKZ_BUILDBOX": "1"},
        )

        assert result.exit_code == 0
        assert selected[0]["compiler"] == "buildbox"
