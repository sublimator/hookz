"""Generate _hooks.h from C++ test files containing WASM hook blocks.

Extracts hook code blocks from test files, compiles them to WASM, and
generates C++ headers with the compiled bytecode as static maps.

Input formats:
  - Inline: R"[test.hook]( ... C code ... )[test.hook]"
  - Inline JS: R"[test.jshook]( ... )[test.jshook]"
  - Inline TS: R"[test.tshook]( ... )[test.tshook]"
  - File refs: "file:domain/path.{c,js,ts}" (requires --hooks-c-dir domain=path)

Output: C++ header with std::map<std::string, std::vector<uint8_t>>

Ported from xahaud-scripts (x-build-test-hooks) to use hookz
compilation pipeline directly instead of shelling out.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shlex
import shutil
import subprocess
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

    map_key: str  # C++ map key: inline source or "file:domain/path.c"
    source: str  # Compilable source code
    filename: str  # Safe source filename sent to the compiler
    line_number: int  # Line number in test file
    is_file_ref: bool  # True if from external file

    @property
    def suffix(self) -> str:
        return Path(self.filename).suffix.lower()

    @property
    def is_quickjs(self) -> bool:
        return self.suffix in {".js", ".mjs", ".ts"}


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

        root = self.hooks_c_dirs[domain].resolve()
        if not root.is_dir():
            raise RuntimeError(
                f'Hook source domain "{domain}" is not a directory: {root}'
            )

        file_path = (root / path).resolve()
        if not file_path.is_relative_to(root):
            raise RuntimeError(f'Hook file escapes domain "{domain}": file:{ref}')
        allowed = {".c", ".js", ".mjs", ".ts"}
        if file_path.suffix.lower() not in allowed or not file_path.is_file():
            raise RuntimeError(
                f"Hook file is not a regular .c/.js/.ts source: {file_path} "
                f'(referenced as "file:{ref}" at line {line_number})'
            )

        return domain, file_path

    def extract(self) -> list[HookBlock]:
        logger.info(f"Reading {self.input_file}")
        content = self.input_file.read_text()

        blocks: list[HookBlock] = []

        inline_kinds = {
            "hook": ".c",
            "jshook": ".js",
            "tshook": ".ts",
        }
        for delimiter, suffix in inline_kinds.items():
            pattern = (
                rf'R"\[test\.{delimiter}\]\((.*?)\)'
                rf'\[test\.{delimiter}\]"'
            )
            for match in re.finditer(pattern, content, re.DOTALL):
                source = match.group(1)
                line_number = content[: match.start()].count("\n") + 1
                blocks.append(
                    HookBlock(
                        map_key=source,
                        source=source,
                        filename=f"inline{suffix}",
                        line_number=line_number,
                        is_file_ref=False,
                    )
                )

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
            blocks.append(
                HookBlock(
                    map_key=f"file:{ref}",
                    source=source,
                    filename=file_path.name,
                    line_number=line_number,
                    is_file_ref=True,
                )
            )

        inline_count = sum(1 for b in blocks if not b.is_file_ref)
        file_count = sum(1 for b in blocks if b.is_file_ref)
        logger.info(
            f"Found {len(blocks)} hook blocks ({inline_count} inline, {file_count} file refs)"
        )
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

    def _cache_key(self, source: str, coverage: bool, compiler: str = "hookz") -> str:
        hasher = hashlib.sha256()
        hasher.update(source.encode("utf-8"))
        hasher.update(compiler.encode("utf-8"))
        hasher.update(self._version.encode("utf-8"))
        if coverage:
            hasher.update(b"coverage")
        return hasher.hexdigest()

    def get(
        self, source: str, coverage: bool = False, compiler: str = "hookz"
    ) -> bytes | None:
        key = self._cache_key(source, coverage, compiler)
        path = self.cache_dir / f"{key}.wasm"
        if path.exists():
            logger.debug(f"Cache hit: {key[:16]}...")
            return path.read_bytes()
        return None

    def put(
        self,
        source: str,
        bytecode: bytes,
        coverage: bool = False,
        compiler: str = "hookz",
    ) -> None:
        key = self._cache_key(source, coverage, compiler)
        path = self.cache_dir / f"{key}.wasm"
        path.write_bytes(bytecode)
        logger.debug(f"Cached: {key[:16]}... ({len(bytecode)} bytes)")


# ---------------------------------------------------------------------------
# Compilation — uses hookz pipeline directly
# ---------------------------------------------------------------------------


def _compile_hook_hookz(source: str, label: str, coverage: bool = False) -> bytes:
    """Compile via hookz pipeline (wasi-sdk + hookz cleaner). Used for coverage builds."""
    from hookz.compiler import compile_hook, compile_hook_two_stage, COVERAGE_OPT_LEVEL
    from hookz.config import load_config
    from hookz.wasm.clean import clean_hook, CleanError

    config = load_config()

    with tempfile.NamedTemporaryFile(suffix=".c", delete=False, mode="w") as f:
        f.write(source)
        source_path = Path(f.name)

    try:
        if coverage:
            from hookz.coverage.rewriter import instrument_wasm

            wasm = compile_hook_two_stage(
                source_path, config, opt_level=COVERAGE_OPT_LEVEL
            )
            wasm, _locs = instrument_wasm(wasm)
            try:
                cleaned = clean_hook(wasm, coverage_call_idx=0)
            except CleanError:
                cleaned = wasm
            return cleaned
        else:
            wasm = compile_hook(source_path, config=config, debug=False, optimize=True)
            try:
                cleaned = clean_hook(wasm)
            except CleanError:
                cleaned = wasm
            return cleaned
    finally:
        source_path.unlink(missing_ok=True)


def _compile_hook_wasmcc(source: str, label: str) -> bytes:
    """Compile via wasmcc + hook-cleaner (legacy compat, matches xahaud's build_test_hooks.sh)."""
    wasmcc_result = subprocess.run(
        [
            "wasmcc",
            "-x",
            "c",
            "/dev/stdin",
            "-o",
            "/dev/stdout",
            "-O2",
            "-Wl,--allow-undefined",
        ],
        input=source.encode("utf-8"),
        capture_output=True,
        check=True,
    )
    cleaner_result = subprocess.run(
        ["hook-cleaner", "-", "-"],
        input=wasmcc_result.stdout,
        capture_output=True,
        check=True,
    )
    return cleaner_result.stdout


def _compile_hook_buildbox(
    source: str,
    filename: str,
    *,
    endpoint: str,
    options: str,
) -> bytes:
    """Compile remotely, then independently validate the returned artifact."""
    from hookz.buildbox import compile_source
    from hookz.wasm.guard import validate_guards

    wasm = compile_source(
        source,
        filename=filename,
        endpoint=endpoint,
        options=options,
    ).wasm
    validate_guards(wasm)
    return wasm


def _compile_hook_quickjs(source: str, filename: str) -> bytes:
    """Delegate JS/TS bytecode production to the pinned QuickJS provider."""
    configured = os.environ.get("JSHOOKZ_HOOK_COMPILER")
    if configured is None:
        configured = os.environ.get("QJS_HOOK_COMPILER", "jshookz compile-hook")
    command = shlex.split(configured)
    if not command:
        raise RuntimeError("JSHOOKZ_HOOK_COMPILER resolved to an empty command")

    suffix = Path(filename).suffix.lower()
    with tempfile.TemporaryDirectory(prefix="hookz-qjs-") as temp:
        temp_path = Path(temp)
        source_path = temp_path / f"hook{suffix}"
        output_path = temp_path / "hook.qjsc"
        source_path.write_text(source)
        completed = subprocess.run(
            [*command, str(source_path), "-o", str(output_path)],
            capture_output=True,
            text=True,
        )
        if completed.returncode:
            detail = "\n".join(
                part.strip()
                for part in (completed.stdout, completed.stderr)
                if part.strip()
            )
            raise RuntimeError(f"QuickJS Hook compilation failed:\n{detail}")
        if not output_path.is_file():
            raise RuntimeError(
                "QuickJS Hook compiler succeeded without producing bytecode"
            )
        return output_path.read_bytes()


def _compile_wat(source: str) -> bytes:
    """Compile WAT source via wat2wasm."""
    source = re.sub(r"/\*end\*/$", "", source)
    result = subprocess.run(
        ["wat2wasm", "-", "-o", "/dev/stdout"],
        input=source.encode("utf-8"),
        capture_output=True,
        check=True,
    )
    return result.stdout


def _is_wat(source: str) -> bool:
    return "(module" in source


# ---------------------------------------------------------------------------
# Output writer
# ---------------------------------------------------------------------------


class OutputWriter:
    """Write compiled blocks to C++ header and Python manifest."""

    def __init__(
        self,
        output_file: Path,
        symbol_name: str,
        cache_dir: Path | None = None,
        compat: bool = False,
        compiler: str = "hookz",
        buildbox_endpoint: str | None = None,
        buildbox_options: str = "-O3",
    ) -> None:
        self.output_file = output_file
        self.symbol_name = symbol_name
        self.compat = compat
        self.compiler = compiler
        self.buildbox_endpoint = buildbox_endpoint
        self.buildbox_options = buildbox_options
        self._cache_dir = cache_dir or CompilationCache.DEFAULT_CACHE_DIR

        if compat:
            # Match build_test_hooks.sh: guard from output filename
            stem = output_file.stem.upper()  # SETHOOK_WASM
            self.include_guard = f"{stem}_INCLUDED"
        else:
            self.include_guard = f"{symbol_name.upper()}_INCLUDED"

    def _header(self) -> str:
        provenance = ""
        if self.compiler == "buildbox":
            endpoint = (
                (self.buildbox_endpoint or "")
                .replace("*/", "* /")
                .replace("\r", "")
                .replace("\n", "")
            )
            options = (
                self.buildbox_options.replace("*/", "* /")
                .replace("\r", "")
                .replace("\n", "")
            )
            provenance = (
                "// hookz-build-mode: buildbox (remote; no local fallback)\n"
                f"// hookz-buildbox-endpoint: {endpoint}\n"
                f"// hookz-buildbox-options: {options}\n"
            )
        if self.compat:
            # Exact match for build_test_hooks.sh output
            return f"""
//This file is generated by build_test_hooks.h
#ifndef {self.include_guard}
#define {self.include_guard}
#include <map>
#include <stdint.h>
#include <string>
#include <vector>
namespace ripple {{
namespace test {{
std::map<std::string, std::vector<uint8_t>> {self.symbol_name} = {{
"""
        return f"""
//This file is generated by hookz build-test-hooks
{provenance}\
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
            input=content,
            capture_output=True,
            text=True,
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
            if self.compiler == "buildbox":
                from hookz.buildbox import prepare_request

                request = prepare_request(
                    block.source,
                    filename=block.filename,
                    options=self.buildbox_options,
                )
                parts.append(
                    "/* hookz-buildbox "
                    f"request-sha256={request.sha256} "
                    f"source-sha256={request.source_sha256} "
                    f"wasm-sha256={hashlib.sha256(bytecode).hexdigest()} "
                    "*/\n"
                )
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
        self,
        compiled_blocks: dict[int, tuple[HookBlock, bytes]],
    ) -> Path:
        """Write Python manifest to cache dir, keyed by content hash.

        Returns the path to the manifest file.
        """
        lines = ["# Generated by hookz build-test-hooks\n"]
        if self.compiler == "buildbox":
            lines += [
                "build = {\n",
                "    'mode': 'buildbox',\n",
                f"    'endpoint': {self.buildbox_endpoint!r},\n",
                f"    'options': {self.buildbox_options!r},\n",
                "    'local_fallback': False,\n",
                "}\n",
                "hook_metadata = {\n",
            ]
            from hookz.buildbox import prepare_request

            for counter in sorted(compiled_blocks.keys()):
                block, bytecode = compiled_blocks[counter]
                request = prepare_request(
                    block.source,
                    filename=block.filename,
                    options=self.buildbox_options,
                )
                lines += [
                    f"    {block.map_key!r}: {{\n",
                    f"        'request_sha256': {request.sha256!r},\n",
                    f"        'source_sha256': {request.source_sha256!r},\n",
                    "        'wasm_sha256': "
                    f"{hashlib.sha256(bytecode).hexdigest()!r},\n",
                    "    },\n",
                ]
            lines.append("}\n")

        lines.append("hooks = {\n")
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
        compiler: str = "hookz",
        buildbox_endpoint: str | None = None,
        buildbox_options: str = "-O3",
        cache_dir: Path | None = None,
    ) -> None:
        requested_jobs = jobs or os.cpu_count() or 1
        # The public service is shared infrastructure. Avoid turning a
        # many-core CI runner into an accidental request flood.
        self.jobs = min(requested_jobs, 4) if compiler == "buildbox" else requested_jobs
        self.force_write = force_write
        self.coverage = coverage
        self.compiler = compiler
        self.input_file = input_file
        self.buildbox_options = buildbox_options
        if compiler == "buildbox":
            from hookz.buildbox import endpoint_from_environment

            self.buildbox_endpoint = buildbox_endpoint or endpoint_from_environment()
        else:
            self.buildbox_endpoint = None

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

        # A remote sanity build must actually observe the current service.
        # Persistently caching it would turn the check into a check of an old
        # response under a mutable endpoint.
        self.cache = (
            None if no_cache or compiler == "buildbox" else CompilationCache(cache_dir)
        )
        self.extractor = SourceExtractor(input_file, hooks_c_dirs=hooks_c_dirs)
        self.writer = OutputWriter(
            self.output_file,
            self.symbol_name,
            cache_dir=(self.cache.cache_dir if self.cache else cache_dir),
            compat=(compiler == "wasmcc"),
            compiler=compiler,
            buildbox_endpoint=self.buildbox_endpoint,
            buildbox_options=buildbox_options,
        )

    def _compile_block(
        self, counter: int, block: HookBlock
    ) -> tuple[int, HookBlock, bytes]:
        label = block.map_key if block.is_file_ref else f"Block {counter}"
        is_wat = _is_wat(block.source)
        is_quickjs = block.is_quickjs

        # Check cache
        # QuickJS bytecode is provider-version-specific. Do not persist it until
        # the compiler exposes a provider identity for the cache key.
        if self.cache is not None and not is_quickjs:
            cached = self.cache.get(
                block.source, coverage=self.coverage, compiler=self.compiler
            )
            if cached is not None:
                logger.info(f"{label}: cached")
                return (counter, block, cached)

        # Compile
        cov_tag = " (coverage)" if self.coverage else ""
        compiler_tag = f" [{self.compiler}]" if self.compiler != "hookz" else ""
        source_kind = (
            "TypeScript"
            if block.suffix == ".ts"
            else "JavaScript"
            if is_quickjs
            else "WAT"
            if is_wat
            else "C"
        )
        logger.info(f"{label}: compiling {source_kind}{compiler_tag}{cov_tag}")

        if is_quickjs:
            if self.compiler == "buildbox":
                raise RuntimeError(
                    "buildbox mode cannot compile JS/TS Hooks through a local "
                    "QuickJS provider"
                )
            if self.coverage:
                raise RuntimeError("Hook coverage is not yet supported for JS/TS Hooks")
            bytecode = _compile_hook_quickjs(block.source, block.filename)
        elif is_wat:
            if self.compiler == "buildbox":
                raise RuntimeError(
                    "the canonical buildbox accepts C source only; refusing "
                    "to compile WAT locally"
                )
            if self.coverage:
                logger.warning(f"{label}: coverage not supported for WAT")
            bytecode = _compile_wat(block.source)
        elif self.compiler == "wasmcc":
            bytecode = _compile_hook_wasmcc(block.source, label)
        elif self.compiler == "buildbox":
            bytecode = _compile_hook_buildbox(
                block.source,
                block.filename,
                endpoint=self.buildbox_endpoint,
                options=self.buildbox_options,
            )
        else:
            bytecode = _compile_hook_hookz(block.source, label, coverage=self.coverage)

        # Store in cache
        if self.cache is not None and not is_quickjs:
            self.cache.put(
                block.source, bytecode, coverage=self.coverage, compiler=self.compiler
            )

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
