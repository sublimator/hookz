"""wasm-opt wrapper — binaryen pass profiles used by the hook build pipeline.

Requires wasm-opt (binaryen) to be installed.

The pass lists here are not tuning knobs. Which passes run determines whether
xahaud's SetHook *accepts* the binary at all, so each profile records where its
flags came from and is checked against that source. See OPT_PROFILES.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import compiler_ref as _ref


class WasmOptError(Exception):
    """Raised when wasm-opt fails."""


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OptProfile:
    """A named binaryen configuration, with the provenance of its flags.

    `invocations` is a sequence of wasm-opt runs, applied in order — some
    reference pipelines are genuinely multi-pass, and collapsing them would
    change the output.
    """

    name: str
    summary: str
    provenance: str
    invocations: tuple[tuple[str, ...], ...]

    @property
    def passes(self) -> tuple[str, ...]:
        """Every flag across all invocations — for display and assertions."""
        return tuple(f for inv in self.invocations for f in inv)

    def run(self, wasm: bytes) -> bytes:
        for flags in self.invocations:
            wasm = _run_wasm_opt(wasm, list(flags))
        return wasm


# The flag list the official web compiler ran when it built the hooks currently
# live on Xahau mainnet — `get_optimization_options()` in chooks.ts. Full
# provenance, the window it applies to, and the ablation behind the note below
# are in hookz.wasm.compiler_ref.
#
# --rereloop is load-bearing and the reason this profile exists. It reruns
# binaryen's Relooper over the control flow, and it is the only pass here that
# moves block nesting at all — every other flag is size/speed and moves depth
# by zero. It does not simply flatten: on small hooks it costs a level or two
# (treasury.c 3 -> 4, govern.c 9 -> 11), while on a large deeply-nested one it
# collapses the tree wholesale, by something like eight levels. Only the second
# case decides anything, but it decides everything — without the pass the depth
# can exceed xahaud's limit of 16, at which point SetHook refuses the install.
# Match the reference toolchain rather than reasoning about the direction.
# --rereloop requires flat IR, so --flatten must precede it.
BUILDBOX = OptProfile(
    name="buildbox",
    summary="matches the official web compiler that built the live mainnet hooks",
    provenance=f"{_ref.COMPILER_SOURCE} @ {_ref.COMPILER_COMMIT[:8]} "
               f"({_ref.COMPILER_COMMIT_DATE}) `get_optimization_options()`",
    invocations=((
        "--shrink-level=100000000",
        "--coalesce-locals-learning",
        "--vacuum",
        "--merge-blocks",
        "--merge-locals",
        "--flatten",             # required before --rereloop
        "--ignore-implicit-traps",
        "-ffm",
        "--const-hoisting",
        "--code-folding",
        "--code-pushing",
        "--dae-optimizing",
        "--dce",
        "--simplify-globals-optimizing",
        "--simplify-locals-nonesting",
        "--reorder-locals",
        "--rereloop",            # collapses block nesting — see note above
        "--precompute-propagate",
        "--local-cse",
        "--remove-unused-brs",
        "--memory-packing",
        "-c",                    # --converge
        "--avoid-reinterprets",
        "-O3",
    ),),
)

SIZE = OptProfile(
    name="size",
    summary="plain -Oz",
    provenance="binaryen default",
    invocations=(("-Oz",),),
)

NONE = OptProfile(
    name="none",
    summary="skip wasm-opt entirely",
    provenance="—",
    invocations=(),
)

OPT_PROFILES: dict[str, OptProfile] = {
    p.name: p for p in (BUILDBOX, SIZE, NONE)
}

DEFAULT_OPT_PROFILE = BUILDBOX


def get_opt_profile(name: str) -> OptProfile:
    try:
        return OPT_PROFILES[name]
    except KeyError:
        known = ", ".join(sorted(OPT_PROFILES))
        raise WasmOptError(
            f"unknown wasm-opt profile {name!r} (known: {known})") from None


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def _find_wasm_opt() -> str:
    """Find wasm-opt binary."""
    import platform
    path = shutil.which("wasm-opt")
    if path is None:
        system = platform.system()
        if system == "Darwin":
            hint = "brew install binaryen"
        elif system == "Linux":
            hint = "apt install binaryen  # or your package manager"
        else:
            hint = "install binaryen from https://github.com/WebAssembly/binaryen/releases"
        raise WasmOptError(f"wasm-opt not found. Install with: {hint}")
    return path


def _run_wasm_opt(wasm: bytes, flags: list[str]) -> bytes:
    """Run wasm-opt with given flags on WASM bytes, return result bytes."""
    wasm_opt = _find_wasm_opt()
    with tempfile.NamedTemporaryFile(suffix=".wasm", delete=False) as f_in:
        f_in.write(wasm)
        in_path = f_in.name
    out_path = in_path + ".out"
    try:
        result = subprocess.run(
            [wasm_opt, in_path, "-o", out_path] + flags,
            capture_output=True,
        )
        if result.returncode != 0:
            raise WasmOptError(
                f"wasm-opt failed (exit {result.returncode}): "
                f"{result.stderr.decode(errors='replace')}")
        return Path(out_path).read_bytes()
    finally:
        Path(in_path).unlink(missing_ok=True)
        Path(out_path).unlink(missing_ok=True)


def strip_debug(wasm: bytes) -> bytes:
    """Strip debug info, producers, and target features sections."""
    return _run_wasm_opt(wasm, [
        "--strip-debug",
        "--strip-producers",
        "--strip-target-features",
    ])


def optimize_size(wasm: bytes) -> bytes:
    """Optimize for size — good default for production hooks."""
    return SIZE.run(wasm)


def optimize_hook(wasm: bytes, profile: OptProfile | str | None = None) -> bytes:
    """Run a binaryen profile over a hook, defaulting to the official one."""
    if profile is None:
        profile = DEFAULT_OPT_PROFILE
    elif isinstance(profile, str):
        profile = get_opt_profile(profile)
    return profile.run(wasm)


def remove_unused(wasm: bytes) -> bytes:
    """Remove unused module elements (global DCE)."""
    return _run_wasm_opt(wasm, ["--remove-unused-module-elements"])
