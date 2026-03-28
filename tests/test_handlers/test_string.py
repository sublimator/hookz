"""Tests for string manipulation handlers."""

import pytest
import wasmtime

from hookz import hookapi
from hookz.handlers.string import str_compare, str_find, str_concat, str_replace
from hookz.runtime import HookRuntime


@pytest.fixture
def rt() -> HookRuntime:
    r = HookRuntime()
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    memory = wasmtime.Memory(store, wasmtime.MemoryType(wasmtime.Limits(1, None)))
    r._store = store
    r._memory = memory
    return r


# ---------------------------------------------------------------------------
# str_compare
# ---------------------------------------------------------------------------

class TestStrCompare:
    """str_compare: compare two byte strings, return 0 (less), 1 (equal), 2 (greater)."""

    def test_equal(self, rt):
        rt._write_memory(0, b"hello")
        rt._write_memory(100, b"hello")
        assert str_compare(rt, 0, 5, 100, 5) == 1

    def test_first_less(self, rt):
        rt._write_memory(0, b"abc")
        rt._write_memory(100, b"abd")
        assert str_compare(rt, 0, 3, 100, 3) == 0

    def test_first_greater(self, rt):
        rt._write_memory(0, b"abd")
        rt._write_memory(100, b"abc")
        assert str_compare(rt, 0, 3, 100, 3) == 2

    def test_case_insensitive_equal(self, rt):
        """mode=0 (default) uses tolower, so case differs but compares equal."""
        rt._write_memory(0, b"Hello")
        rt._write_memory(100, b"hello")
        # mode=0 is the tolower path (matching C++ behavior)
        assert str_compare(rt, 0, 5, 100, 5, mode=0) == 1

    def test_case_sensitive_mode1(self, rt):
        """mode=1 is raw byte compare (matching C++ behavior)."""
        rt._write_memory(0, b"Hello")
        rt._write_memory(100, b"hello")
        # 'H' (0x48) < 'h' (0x68) in raw bytes
        assert str_compare(rt, 0, 5, 100, 5, mode=1) == 0

    def test_empty_returns_too_small(self, rt):
        rt._write_memory(0, b"x")
        assert str_compare(rt, 0, 0, 0, 1) == hookapi.TOO_SMALL
        assert str_compare(rt, 0, 1, 0, 0) == hookapi.TOO_SMALL

    def test_too_long_returns_too_big(self, rt):
        assert str_compare(rt, 0, 256, 0, 1) == hookapi.TOO_BIG
        assert str_compare(rt, 0, 1, 0, 256) == hookapi.TOO_BIG

    def test_invalid_mode(self, rt):
        rt._write_memory(0, b"a")
        rt._write_memory(100, b"a")
        assert str_compare(rt, 0, 1, 100, 1, mode=2) == hookapi.INVALID_ARGUMENT

    def test_different_lengths_equal_prefix(self, rt):
        """Different lengths but same prefix — still returns 1 (equal up to min len)."""
        rt._write_memory(0, b"abc")
        rt._write_memory(100, b"ab")
        assert str_compare(rt, 0, 3, 100, 2) == 1


# ---------------------------------------------------------------------------
# str_find
# ---------------------------------------------------------------------------

class TestStrFind:
    """str_find: find needle in haystack, return offset or DOESNT_EXIST."""

    def test_basic_find(self, rt):
        rt._write_memory(0, b"hello world")
        rt._write_memory(100, b"world")
        assert str_find(rt, 0, 11, 100, 5) == 6

    def test_find_at_start(self, rt):
        rt._write_memory(0, b"hello")
        rt._write_memory(100, b"hel")
        assert str_find(rt, 0, 5, 100, 3) == 0

    def test_not_found(self, rt):
        rt._write_memory(0, b"hello")
        rt._write_memory(100, b"xyz")
        assert str_find(rt, 0, 5, 100, 3) == hookapi.DOESNT_EXIST

    def test_case_insensitive(self, rt):
        rt._write_memory(0, b"Hello World")
        rt._write_memory(100, b"WORLD")
        assert str_find(rt, 0, 11, 100, 5, mode=1) == 6

    def test_case_sensitive_no_match(self, rt):
        rt._write_memory(0, b"Hello World")
        rt._write_memory(100, b"WORLD")
        assert str_find(rt, 0, 11, 100, 5, mode=0) == hookapi.DOESNT_EXIST

    def test_start_offset(self, rt):
        rt._write_memory(0, b"abcabc")
        rt._write_memory(100, b"abc")
        # Start search from offset 1, should find at position 3 relative to offset
        assert str_find(rt, 0, 6, 100, 3, n=1) == 2

    def test_strlen_overload(self, rt):
        """needle_ptr=0, needle_len=0 returns strlen."""
        rt._write_memory(0, b"hello\x00world")
        assert str_find(rt, 0, 11, 0, 0) == 5

    def test_strlen_no_null(self, rt):
        """No null byte means strlen == haystack_len."""
        rt._write_memory(0, b"hello")
        assert str_find(rt, 0, 5, 0, 0) == 5

    def test_strlen_invalid_nonzero_len(self, rt):
        """needle_ptr=0 but needle_len != 0 is INVALID_ARGUMENT."""
        rt._write_memory(0, b"hello")
        assert str_find(rt, 0, 5, 0, 3) == hookapi.INVALID_ARGUMENT

    def test_empty_haystack(self, rt):
        assert str_find(rt, 0, 0, 100, 1) == hookapi.TOO_SMALL

    def test_n_beyond_haystack(self, rt):
        rt._write_memory(0, b"hi")
        rt._write_memory(100, b"h")
        assert str_find(rt, 0, 2, 100, 1, n=2) == hookapi.INVALID_ARGUMENT

    def test_regex_not_implemented(self, rt):
        rt._write_memory(0, b"hello")
        rt._write_memory(100, b"h")
        assert str_find(rt, 0, 5, 100, 1, mode=2) == hookapi.NOT_IMPLEMENTED
        assert str_find(rt, 0, 5, 100, 1, mode=3) == hookapi.NOT_IMPLEMENTED


# ---------------------------------------------------------------------------
# str_concat
# ---------------------------------------------------------------------------

class TestStrConcat:
    """str_concat: concatenate two null-terminated strings."""

    def test_basic(self, rt):
        rt._write_memory(0, b"\x00" * 20)
        rt._write_memory(100, b"hello\x00")
        rt._write_memory(200, b"world\x00")
        result = str_concat(rt, 0, 20, 100, 6, 200, 6)
        assert result == 11  # 5 + 5 + 1 (null)
        assert rt._read_memory(0, 11) == b"helloworld\x00"

    def test_empty_strings(self, rt):
        rt._write_memory(100, b"\x00")
        rt._write_memory(200, b"\x00")
        result = str_concat(rt, 0, 10, 100, 1, 200, 1)
        assert result == 1  # just the null terminator
        assert rt._read_memory(0, 1) == b"\x00"

    def test_first_empty(self, rt):
        rt._write_memory(100, b"\x00")
        rt._write_memory(200, b"abc\x00")
        result = str_concat(rt, 0, 10, 100, 1, 200, 4)
        assert result == 4  # 0 + 3 + 1
        assert rt._read_memory(0, 4) == b"abc\x00"

    def test_write_too_small(self, rt):
        rt._write_memory(100, b"hello\x00")
        rt._write_memory(200, b"world\x00")
        result = str_concat(rt, 0, 10, 100, 6, 200, 6)
        assert result == hookapi.TOO_SMALL

    def test_no_null_in_first(self, rt):
        rt._write_memory(100, b"hello")  # no null
        rt._write_memory(200, b"world\x00")
        result = str_concat(rt, 0, 20, 100, 5, 200, 6)
        assert result == hookapi.NOT_A_STRING

    def test_no_null_in_second(self, rt):
        rt._write_memory(100, b"hello\x00")
        rt._write_memory(200, b"world")  # no null
        result = str_concat(rt, 0, 20, 100, 6, 200, 5)
        assert result == hookapi.NOT_A_STRING

    def test_too_big(self, rt):
        assert str_concat(rt, 0, 1025, 100, 1, 200, 1) == hookapi.TOO_BIG
        assert str_concat(rt, 0, 10, 100, 1025, 200, 1) == hookapi.TOO_BIG

    def test_zero_len(self, rt):
        assert str_concat(rt, 0, 0, 100, 1, 200, 1) == hookapi.TOO_SMALL
        assert str_concat(rt, 0, 10, 100, 0, 200, 1) == hookapi.TOO_SMALL

    def test_write_smaller_than_read(self, rt):
        assert str_concat(rt, 0, 3, 100, 5, 200, 1) == hookapi.TOO_SMALL


# ---------------------------------------------------------------------------
# str_replace
# ---------------------------------------------------------------------------

class TestStrReplace:
    """str_replace: replace first occurrence of needle in haystack."""

    def test_basic(self, rt):
        rt._write_memory(100, b"hello world")
        rt._write_memory(200, b"world")
        rt._write_memory(300, b"there")
        result = str_replace(rt, 0, 50, 100, 11, 200, 5, 300, 5)
        assert result == 11
        assert rt._read_memory(0, 11) == b"hello there"

    def test_shorter_replacement(self, rt):
        rt._write_memory(100, b"hello world")
        rt._write_memory(200, b"world")
        rt._write_memory(300, b"x")
        result = str_replace(rt, 0, 50, 100, 11, 200, 5, 300, 1)
        assert result == 7
        assert rt._read_memory(0, 7) == b"hello x"

    def test_longer_replacement(self, rt):
        rt._write_memory(100, b"hi")
        rt._write_memory(200, b"hi")
        rt._write_memory(300, b"hello")
        result = str_replace(rt, 0, 50, 100, 2, 200, 2, 300, 5)
        assert result == 5
        assert rt._read_memory(0, 5) == b"hello"

    def test_not_found(self, rt):
        rt._write_memory(100, b"hello")
        rt._write_memory(200, b"xyz")
        rt._write_memory(300, b"a")
        assert str_replace(rt, 0, 50, 100, 5, 200, 3, 300, 1) == hookapi.DOESNT_EXIST

    def test_write_buffer_too_small(self, rt):
        rt._write_memory(100, b"hello world")
        rt._write_memory(200, b"world")
        rt._write_memory(300, b"universe!!!")
        result = str_replace(rt, 0, 11, 100, 11, 200, 5, 300, 11)
        assert result == hookapi.TOO_SMALL

    def test_only_first_occurrence(self, rt):
        rt._write_memory(100, b"abcabc")
        rt._write_memory(200, b"abc")
        rt._write_memory(300, b"XYZ")
        result = str_replace(rt, 0, 50, 100, 6, 200, 3, 300, 3)
        assert result == 6
        assert rt._read_memory(0, 6) == b"XYZabc"

    def test_empty_haystack(self, rt):
        assert str_replace(rt, 0, 50, 100, 0, 200, 1, 300, 1) == hookapi.TOO_SMALL

    def test_empty_needle(self, rt):
        rt._write_memory(100, b"hello")
        assert str_replace(rt, 0, 50, 100, 5, 200, 0, 300, 1) == hookapi.TOO_SMALL

    def test_haystack_too_big(self, rt):
        assert str_replace(rt, 0, 50, 100, 32 * 1024 + 1, 200, 1, 300, 1) == hookapi.TOO_BIG

    def test_needle_too_big(self, rt):
        rt._write_memory(100, b"x")
        assert str_replace(rt, 0, 50, 100, 1, 200, 257, 300, 1) == hookapi.TOO_BIG

    def test_empty_replacement(self, rt):
        """Replacing with empty effectively deletes the needle."""
        rt._write_memory(100, b"hello world")
        rt._write_memory(200, b" world")
        result = str_replace(rt, 0, 50, 100, 11, 200, 6, 300, 0)
        assert result == 5
        assert rt._read_memory(0, 5) == b"hello"
