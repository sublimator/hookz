"""Test source annotation and marker-based coverage assertions."""

import subprocess
import tempfile
from pathlib import Path

import pytest

from hookz.coverage.annotate import analyze_markers, annotate_source, save_marker_names
from location_consts import HOOK_DIR, TIPBOT_DIR, WASI_SDK

pytestmark = pytest.mark.skipif(
    WASI_SDK is None or HOOK_DIR is None or TIPBOT_DIR is None,
    reason="wasi-sdk, hook headers, or tipbot-hooks not found",
)


def _compile(source: Path) -> tuple[bytes, str]:
    clang = WASI_SDK / "bin" / "clang"
    sysroot = WASI_SDK / "share" / "wasi-sysroot"
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    tmp.close()
    r = subprocess.run([
        str(clang), "--target=wasm32-wasip1", f"--sysroot={sysroot}",
        "-nostdlib", "-g", "-O0",
        "-Wno-incompatible-pointer-types", "-Wno-int-conversion", "-Wno-macro-redefined",
        "-Wl,--allow-undefined", "-Wl,--no-entry", "-Wl,--export=hook", "-Wl,--export=cbak",
        f"-I{HOOK_DIR}", "-x", "c", str(source), "-o", tmp.name,
    ], capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode())
    return Path(tmp.name).read_bytes(), tmp.name


class TestAnalyzeMarkers:
    def test_tip_markers(self):
        """Analyze tip.c and show all DWARF markers with AST context."""
        _, wasm_path = _compile(TIPBOT_DIR / "tip.c")
        markers = analyze_markers(TIPBOT_DIR / "tip.c", wasm_path)

        assert len(markers) > 0
        print(f"\ntip.c: {len(markers)} markers")
        for m in markers[:30]:
            print(f"  {m.name:40s} line {m.line:>3}:{m.col:<3} [{m.ast_context}] {m.ast_label[:50]}")
        if len(markers) > 30:
            print(f"  ... and {len(markers) - 30} more")

    def test_annotated_source(self):
        """Generate annotated source and verify markers appear."""
        _, wasm_path = _compile(TIPBOT_DIR / "tip.c")
        annotated, markers = annotate_source(TIPBOT_DIR / "tip.c", wasm_path)

        # Show a slice around the interesting parts
        lines = annotated.splitlines()
        print(f"\ntip.c annotated ({len(markers)} markers):")
        for i, line in enumerate(lines[98:115], start=99):  # lines 99-114
            print(f"  {i:>4} {line}")
        print("  ...")
        for i, line in enumerate(lines[158:170], start=159):  # outgoing check
            print(f"  {i:>4} {line}")
        print("  ...")
        for i, line in enumerate(lines[246:265], start=247):  # opinion loop
            print(f"  {i:>4} {line}")

    def test_save_and_load_markers(self, tmp_path):
        """Save markers to file, edit a name, load back."""
        _, wasm_path = _compile(TIPBOT_DIR / "tip.c")
        markers = analyze_markers(TIPBOT_DIR / "tip.c", wasm_path)

        marker_file = tmp_path / "tip_markers.txt"
        save_marker_names(markers, marker_file)

        content = marker_file.read_text()
        assert "# Hook coverage markers" in content
        print(f"\nMarker file ({len(markers)} entries):")
        for line in content.splitlines()[:15]:
            print(f"  {line}")

        # Edit a name
        content = content.replace(markers[0].name, "my_custom_name")
        marker_file.write_text(content)

        # Reload with custom names
        _, markers2 = annotate_source(TIPBOT_DIR / "tip.c", wasm_path, marker_file)
        assert markers2[0].name == "my_custom_name"
