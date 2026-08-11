"""Optional ctypes bridge to the Xahau differential-testing oracle.

The shared library is built in the dedicated Xahau vectors worktree. It is
never required by hookz at runtime; tests opt in with ``HOOKZ_XAHAUD_ORACLE``.
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path

ORACLE_ENV = "HOOKZ_XAHAUD_ORACLE"
EXPECTED_ABI_VERSION = 1


@dataclass(frozen=True)
class XahaudOracle:
    """Versioned, fixed-width C ABI exported by the Xahau vectors worktree."""

    path: Path
    _library: ctypes.CDLL

    @classmethod
    def load(cls, path: str | Path) -> XahaudOracle:
        resolved = Path(path).expanduser().resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"Xahau oracle library not found: {resolved}")

        library = ctypes.CDLL(str(resolved))
        library.hookz_xahaud_oracle_abi_version.argtypes = []
        library.hookz_xahaud_oracle_abi_version.restype = ctypes.c_uint32
        library.hookz_xahaud_oracle_git_commit.argtypes = []
        library.hookz_xahaud_oracle_git_commit.restype = ctypes.c_char_p
        library.hookz_xahaud_float_mulratio.argtypes = [
            ctypes.c_uint64,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]
        library.hookz_xahaud_float_mulratio.restype = ctypes.c_int64

        oracle = cls(path=resolved, _library=library)
        if oracle.abi_version != EXPECTED_ABI_VERSION:
            raise RuntimeError(
                f"unsupported Xahau oracle ABI {oracle.abi_version}; "
                f"expected {EXPECTED_ABI_VERSION} ({resolved})"
            )
        return oracle

    @classmethod
    def from_env(cls) -> XahaudOracle | None:
        value = os.environ.get(ORACLE_ENV)
        return cls.load(value) if value else None

    @property
    def abi_version(self) -> int:
        return int(self._library.hookz_xahaud_oracle_abi_version())

    @property
    def git_commit(self) -> str:
        raw = self._library.hookz_xahaud_oracle_git_commit()
        if raw is None:
            raise RuntimeError("Xahau oracle returned a null commit string")
        return raw.decode("ascii")

    def float_mulratio(
        self,
        xfl: int,
        round_up: int,
        numerator: int,
        denominator: int,
    ) -> int:
        """Call Xahau's real IOUAmount ratio path through ABI v1.

        xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1023-1048
        xahaud:src/libxrpl/protocol/IOUAmount.cpp:183-315
        """
        return int(
            self._library.hookz_xahaud_float_mulratio(
                xfl & 0xFFFF_FFFF_FFFF_FFFF,
                round_up & 0xFFFF_FFFF,
                numerator & 0xFFFF_FFFF,
                denominator & 0xFFFF_FFFF,
            )
        )
