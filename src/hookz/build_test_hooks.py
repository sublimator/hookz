"""Generate _hooks.h from C++ test files containing WASM hook blocks.

Extracts hook code blocks from test files, compiles them to WASM, and
generates C++ headers with the compiled bytecode as static maps.

Input formats:
  - Inline: R"[test.hook]( ... C code ... )[test.hook]"
  - File refs: "file:domain/path.c"  (requires --hooks-c-dir domain=path)

Output: C++ header with std::map<std::string, std::vector<uint8_t>>

Ported from xahaud-scripts (x-build-test-hooks) to use hookz
compilation pipeline directly instead of shelling out.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("hookz.build-test-hooks")


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

class OutputFormatter:
    """Format compiled bytecode as C++ arrays."""

    @staticmethod
    def bytes_to_cpp_array(data: bytes) -> str:
        lines = []
        for i in range(0, len(data), 10):
            chunk = data[i : i + 10]
            hex_values = ",".join(f"0x{b:02X}U" for b in chunk)
            lines.append(f"    {hex_values},")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Source extraction
# ---------------------------------------------------------------------------

@dataclass
class HookBlock:
    """A hook block to compile."""
    map_key: str       # C++ map key: inline source or "file:domain/path.c"
    source: str        # Compilable source code
    line_number: int   # Line number in test file
    is_file_ref: bool  # True if from external file


class SourceExtractor:
    """Extract WASM test blocks from a C++ test file."""

    def __init__(
        self,
        input_file: Path,
        hooks_c_dirs: dict[str, Path] | None = None,
    ) -> None:
        self.input_file = input_file
        self.hooks_c_dirs = hooks_c_dirs or {}

    def _resolve_file_ref(self, ref: str, line_number: int) -> tuple[str, Path]:
        if "/" not in ref:
            raise RuntimeError(
                f'"file:{ref}" at line {line_number} is missing a domain. '
                f'Use "file:<domain>/<path>" (e.g. "file:tipbot/tip.c")'
            )

        domain, path = ref.split("/", 1)

        if not self.hooks_c_dirs:
            raise RuntimeError(
                f'Found file reference "file:{ref}" at line {line_number} '
                f"but no --hooks-c-dir was specified"
            )

        if domain not in self.hooks_c_dirs:
            available = ", ".join(sorted(self.hooks_c_dirs))
            raise RuntimeError(
                f'Unknown domain "{domain}" in "file:{ref}" at line {line_number}. '
                f"Available: {available}"
            )

        file_path = self.hooks_c_dirs[domain] / path
        if not file_path.exists():
            raise RuntimeError(
                f"Hook file not found: {file_path} "
                f'(referenced as "file:{ref}" at line {line_number})'
            )

        return domain, file_path

    def extract(self) -> list[HookBlock]:
        logger.info(f"Reading {self.input_file}")
        content = self.input_file.read_text()

        blocks: list[HookBlock] = []

        # Inline blocks: R"[test.hook](...)[test.hook]"
        pattern = r'R"\[test\.hook\]\((.*?)\)\[test\.hook\]"'
        for match in re.finditer(pattern, content, re.DOTALL):
            source = match.group(1)
            line_number = content[: match.start()].count("\n") + 1
            blocks.append(HookBlock(
                map_key=source, source=source,
                line_number=line_number, is_file_ref=False,
            ))

        # File references: "file:domain/path.c"
        file_pattern = r'"file:([^"]+)"'
        seen_refs: set[str] = set()
        for match in re.finditer(file_pattern, content):
            ref = match.group(1)
            if ref in seen_refs:
                continue
            seen_refs.add(ref)

            line_number = content[: match.start()].count("\n") + 1
            _domain, file_path = self._resolve_file_ref(ref, line_number)

            source = file_path.read_text()
            blocks.append(HookBlock(
                map_key=f"file:{ref}", source=source,
                line_number=line_number, is_file_ref=True,
            ))

        inline_count = sum(1 for b in blocks if not b.is_file_ref)
        file_count = sum(1 for b in blocks if b.is_file_ref)
        logger.info(f"Found {len(blocks)} hook blocks ({inline_count} inline, {file_count} file refs)")
        return blocks


# ---------------------------------------------------------------------------
# Compilation cache
# ---------------------------------------------------------------------------

class CompilationCache:
    """SHA256-based cache keyed on source + hookz version."""

    DEFAULT_CACHE_DIR = Path.home() / ".cache" / "hookz-builds"

    def __init__(self, cache_dir: Path | None = None) -> None:
        self.cache_dir = cache_dir or self.DEFAULT_CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._version = self._get_hookz_version()

    @staticmethod
    def _get_hookz_version() -> str:
        try:
            from hookz._version import get_version
            return get_version()
        except Exception:
            return "unknown"

    def _cache_key(self, source: str, coverage: bool) -> str:
        hasher = hashlib.sha256()
        hasher.update(source.encode("utf-8"))
        hasher.update(self._version.encode("utf-8"))
        if coverage:
            hasher.update(b"coverage")
        return hasher.hexdigest()

    def get(self, source: str, coverage: bool = False) -> bytes | None:
        key = self._cache_key(source, coverage)
        path = self.cache_dir / f"{key}.wasm"
        if path.exists():
            logger.debug(f"Cache hit: {key[:16]}...")
            return path.read_bytes()
        return None

    def put(self, source: str, bytecode: bytes, coverage: bool = False) -> None:
        key = self._cache_key(source, coverage)
        path = self.cache_dir / f"{key}.wasm"
        path.write_bytes(bytecode)
        logger.debug(f"Cached: {key[:16]}... ({len(bytecode)} bytes)")


# ---------------------------------------------------------------------------
# Compilation — uses hookz pipeline directly
# ---------------------------------------------------------------------------

def _compile_hook(source: str, label: str, coverage: bool = False,
                  guard_check: bool = True) -> bytes:
    """Compile a hook source string to WASM bytes using hookz internals.

    guard_check=False skips guard validation — useful for test hooks that
    are intentionally malformed (no _g, memory.copy tests, etc.). xahaud
    does its own guard check at SetHook time anyway.
    """
    from hookz.compiler import compile_hook, compile_hook_two_stage, COVERAGE_OPT_LEVEL
    from hookz.config import load_config
    from hookz.wasm.clean import clean_hook, CleanError
    from hookz.wasm.guard import validate_guards
    from hookz.wasm.whitelist import get_whitelist

    config = load_config()

    with tempfile.NamedTemporaryFile(suffix=".c", delete=False, mode="w") as f:
        f.write(source)
        source_path = Path(f.name)

    try:
        if coverage:
            from hookz.coverage.rewriter import instrument_wasm

            wasm = compile_hook_two_stage(source_path, config, opt_level=COVERAGE_OPT_LEVEL)
            wasm, _locs = instrument_wasm(wasm)
            try:
                cleaned = clean_hook(wasm, coverage_call_idx=0)
            except CleanError:
                # Hook might not have _g (intentional test case)
                cleaned = wasm
            if guard_check:
                coverage_whitelist = get_whitelist() | {"__on_source_line"}
                validate_guards(cleaned, import_whitelist=coverage_whitelist)
            return cleaned
        else:
            wasm = compile_hook(source_path, config=config, debug=False, optimize=True)
            try:
                cleaned = clean_hook(wasm)
            except CleanError:
                cleaned = wasm
            if guard_check:
                validate_guards(cleaned)
            return cleaned
    finally:
        source_path.unlink(missing_ok=True)


def _compile_wat(source: str) -> bytes:
    """Compile WAT source via wat2wasm."""
    source = re.sub(r"/\*end\*/$", "", source)
    result = subprocess.run(
        ["wat2wasm", "-", "-o", "/dev/stdout"],
        input=source.encode("utf-8"),
        capture_output=True, check=True,
    )
    return result.stdout


def _is_wat(source: str) -> bool:
    return "(module" in source


# ---------------------------------------------------------------------------
# Output writer
# ---------------------------------------------------------------------------

class OutputWriter:
    """Write compiled blocks to C++ header and Python manifest."""

    def __init__(self, output_file: Path, symbol_name: str,
                 cache_dir: Path | None = None) -> None:
        self.output_file = output_file
        self.symbol_name = symbol_name
        self.include_guard = f"{symbol_name.upper()}_INCLUDED"
        self._cache_dir = cache_dir or CompilationCache.DEFAULT_CACHE_DIR

    def _header(self) -> str:
        return f"""
//This file is generated by hookz build-test-hooks
#ifndef {self.include_guard}
#define {self.include_guard}
#include <map>
#include <stdint.h>
#include <string>
#include <vector>
namespace ripple {{
namespace test {{
inline std::map<std::string, std::vector<uint8_t>> {self.symbol_name} = {{
"""

    def _footer(self) -> str:
        return """};
}
}
#endif
"""

    def _format_with_clang_format(self, content: str) -> str:
        if not shutil.which("clang-format"):
            return content
        result = subprocess.run(
            ["clang-format", f"--assume-filename={self.output_file}"],
            input=content, capture_output=True, text=True,
        )
        return result.stdout if result.returncode == 0 else content

    def write(
        self,
        compiled_blocks: dict[int, tuple[HookBlock, bytes]],
        force_write: bool = False,
    ) -> None:
        parts = [self._header()]
        for counter in sorted(compiled_blocks.keys()):
            block, bytecode = compiled_blocks[counter]
            if block.is_file_ref:
                parts.append(f"/* ==== WASM: {block.map_key} ==== */\n")
                parts.append(f'{{ "{block.map_key}",\n{{\n')
            else:
                parts.append(f"/* ==== WASM: {counter} ==== */\n")
                parts.append('{ R"[test.hook](')
                parts.append(block.map_key)
                parts.append(')[test.hook]",\n{\n')
            parts.append(OutputFormatter.bytes_to_cpp_array(bytecode))
            parts.append("\n}},\n\n")
        parts.append(self._footer())
        unformatted = "".join(parts)

        # Cache formatted output to avoid redundant clang-format runs
        content_hash = hashlib.sha256(unformatted.encode("utf-8")).hexdigest()
        cache_file = self._cache_dir / f"formatted_{content_hash}.h"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        if cache_file.exists():
            formatted = cache_file.read_text()
        else:
            formatted = self._format_with_clang_format(unformatted)
            cache_file.write_text(formatted)

        if not force_write and self.output_file.exists():
            if self.output_file.read_text() == formatted:
                logger.info("Output unchanged, skipping write")
                return

        logger.info(f"Writing {self.output_file}")
        self.output_file.write_text(formatted)

    def write_python_manifest(
        self, compiled_blocks: dict[int, tuple[HookBlock, bytes]],
    ) -> Path:
        """Write Python manifest to cache dir, keyed by content hash.

        Returns the path to the manifest file.
        """
        lines = ["# Generated by hookz build-test-hooks\n", "hooks = {\n"]
        for counter in sorted(compiled_blocks.keys()):
            block, bytecode = compiled_blocks[counter]
            lines.append(f'    {repr(block.map_key)}: "{bytecode.hex()}",\n')
        lines.append("}\n")
        content = "".join(lines)

        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        manifest = self._cache_dir / f"manifest_{content_hash}.py"

        if not manifest.exists():
            manifest.write_text(content)
            logger.info(f"Manifest: {manifest}")
        else:
            logger.debug(f"Manifest cached: {manifest}")

        return manifest


# ---------------------------------------------------------------------------
# Builder orchestrator
# ---------------------------------------------------------------------------

class TestHookBuilder:
    """Orchestrate extraction → parallel compilation → output."""

    def __init__(
        self,
        input_file: Path,
        jobs: int = 0,
        force_write: bool = False,
        hooks_c_dirs: dict[str, Path] | None = None,
        coverage: bool = False,
        no_cache: bool = False,
        output_file: Path | None = None,
        symbol_name: str | None = None,
    ) -> None:
        self.jobs = jobs or os.cpu_count() or 1
        self.force_write = force_write
        self.coverage = coverage
        self.input_file = input_file

        stem = input_file.stem

        if output_file is not None:
            self.output_file = output_file
        elif stem == "SetHook_test":
            # Backward compat with xahaud's build_test_hooks.sh
            self.output_file = input_file.parent / "SetHook_wasm.h"
        else:
            self.output_file = input_file.parent / f"{stem}_hooks.h"

        if symbol_name is not None:
            self.symbol_name = symbol_name
        elif stem == "SetHook_test":
            self.symbol_name = "wasm"
        else:
            self.symbol_name = f"{stem.lower()}_wasm"

        self.cache = None if no_cache else CompilationCache()
        self.extractor = SourceExtractor(input_file, hooks_c_dirs=hooks_c_dirs)
        self.writer = OutputWriter(
            self.output_file, self.symbol_name,
            cache_dir=self.cache.cache_dir if self.cache else None,
        )

    def _compile_block(self, counter: int, block: HookBlock) -> tuple[int, HookBlock, bytes]:
        label = block.map_key if block.is_file_ref else f"Block {counter}"
        is_wat = _is_wat(block.source)

        # Check cache
        if self.cache is not None:
            cached = self.cache.get(block.source, coverage=self.coverage)
            if cached is not None:
                logger.info(f"{label}: cached")
                return (counter, block, cached)

        # Compile
        cov_tag = " (coverage)" if self.coverage else ""
        logger.info(f"{label}: compiling {'WAT' if is_wat else 'C'}{cov_tag}")

        if is_wat:
            if self.coverage:
                logger.warning(f"{label}: coverage not supported for WAT")
            bytecode = _compile_wat(block.source)
        else:
            bytecode = _compile_hook(block.source, label, coverage=self.coverage,
                                     guard_check=False)

        # Store in cache
        if self.cache is not None:
            self.cache.put(block.source, bytecode, coverage=self.coverage)

        return (counter, block, bytecode)

    def build(self) -> None:
        logger.info(f"Building test hooks from {self.input_file}")
        logger.info(f"  Output: {self.output_file}")
        logger.info(f"  Workers: {self.jobs}, Coverage: {self.coverage}")

        blocks = self.extractor.extract()

        compiled: dict[int, tuple[HookBlock, bytes]] = {}
        failed: list[tuple[int, HookBlock, str]] = []

        with ThreadPoolExecutor(max_workers=self.jobs) as executor:
            futures = {
                executor.submit(self._compile_block, i, block): (i, block)
                for i, block in enumerate(blocks)
            }
            for future in as_completed(futures):
                i, block = futures[future]
                try:
                    counter, result_block, bytecode = future.result()
                    compiled[counter] = (result_block, bytecode)
                except Exception as e:
                    label = block.map_key if block.is_file_ref else f"Block {i}"
                    logger.error(f"{label} (line {block.line_number}) failed: {e}")
                    failed.append((i, block, str(e)))

        if failed:
            nums = sorted(i for i, _, _ in failed)
            raise RuntimeError(f"{len(failed)} block(s) failed: {_format_ranges(nums)}")

        self.writer.write(compiled, force_write=self.force_write)
        self.writer.write_python_manifest(compiled)
        logger.info(f"Done: {self.output_file}")


def _format_ranges(nums: list[int]) -> str:
    """Format [0,1,2,5,7,8] as '0-2,5,7-8'."""
    if not nums:
        return ""
    ranges = []
    start = end = nums[0]
    for n in nums[1:]:
        if n == end + 1:
            end = n
        else:
            ranges.append(f"{start}-{end}" if start != end else str(start))
            start = end = n
    ranges.append(f"{start}-{end}" if start != end else str(start))
    return ",".join(ranges)
