"""Integration contract for the vendored xahaud external-test CMake block."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


PATCH = (
    Path(__file__).parents[1]
    / "patches"
    / "xahaud-external-env-tests.patch"
)


def _external_test_block() -> str:
    """Extract the post-image block mechanically from the vendored patch."""
    first_file = PATCH.read_text().split(
        "diff --git a/include/", 1
    )[0]
    added = [
        line[1:]
        for line in first_file.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    start = added.index(
        "    # Optional: include external hook test sources from another directory."
    )
    return "\n".join(added[start:]) + "\n"


def _run(*args: str, env: dict[str, str]) -> None:
    subprocess.run(
        args,
        env=env,
        check=True,
        text=True,
        capture_output=True,
    )


@pytest.mark.skipif(shutil.which("cmake") is None, reason="cmake is unavailable")
def test_switching_to_buildbox_regenerates_an_existing_local_header(tmp_path):
    source_dir = tmp_path / "project"
    build_dir = tmp_path / "build"
    tests_dir = tmp_path / "env-tests"
    bin_dir = tmp_path / "bin"
    source_dir.mkdir()
    tests_dir.mkdir()
    bin_dir.mkdir()

    (source_dir / "dummy.cpp").write_text("int hookz_cmake_fixture;\n")
    test_file = tests_dir / "Proof_test.cpp"
    test_file.write_text("// fixture\n")
    (source_dir / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\n"
        "project(hookz_external_test LANGUAGES CXX)\n"
        "add_library(rippled STATIC dummy.cpp)\n"
        + _external_test_block()
    )

    invocation_log = tmp_path / "hookz-invocations.txt"
    fake_hookz = bin_dir / "hookz"
    fake_hookz.write_text(
        "#!/usr/bin/env python3\n"
        "import os\n"
        "import pathlib\n"
        "import sys\n"
        "source = pathlib.Path(sys.argv[2])\n"
        "mode = 'buildbox' if '--buildbox' in sys.argv else 'local'\n"
        "source.with_name(source.stem + '_hooks.h').write_text(mode)\n"
        "with pathlib.Path(os.environ['HOOKZ_TEST_LOG']).open('a') as log:\n"
        "    log.write(' '.join(sys.argv[1:]) + '\\n')\n"
    )
    fake_hookz.chmod(0o755)

    environment = os.environ.copy()
    environment["PATH"] = f"{bin_dir}{os.pathsep}{environment['PATH']}"
    environment["HOOKS_TEST_DIR"] = str(tests_dir)
    environment["HOOKZ_TEST_LOG"] = str(invocation_log)
    environment.pop("HOOKZ_BUILDBOX", None)
    environment.pop("HOOKS_FORCE_RECOMPILE", None)

    _run("cmake", "-S", str(source_dir), "-B", str(build_dir), env=environment)
    _run(
        "cmake",
        "--build",
        str(build_dir),
        "--target",
        "compile_external_hooks",
        env=environment,
    )
    header = tests_dir / "Proof_test_hooks.h"
    assert header.read_text() == "local"

    environment["HOOKZ_BUILDBOX"] = "1"
    _run("cmake", "-S", str(source_dir), "-B", str(build_dir), env=environment)
    for _ in range(2):
        _run(
            "cmake",
            "--build",
            str(build_dir),
            "--target",
            "compile_hooks_Proof_test",
            env=environment,
        )

    assert header.read_text() == "buildbox"
    invocations = invocation_log.read_text().splitlines()
    assert len(invocations) == 3
    assert all("--buildbox" in line for line in invocations[-2:])
