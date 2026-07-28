"""Expanding a citation to the construct it names."""

from __future__ import annotations

import pytest

from hookz.citations import merge, render, span_for
from hookz.wasm.xahaud_ref import cite, vendored_root

HOOKAPI = "src/xrpld/app/hook/detail/HookAPI.cpp"


@pytest.fixture(scope="module")
def hookapi():
    return vendored_root() / HOOKAPI


class TestALineThatSaysNothingResolvesUpward:
    """The reason this exists. Verifying the citations in this repo turned up
    three that are true and unreadable on their own."""

    def test_a_closing_brace_resolves_to_what_it_closes(self, hookapi):
        assert hookapi.read_text().splitlines()[2201].strip() == "}"

        span = span_for(hookapi, 2202)

        assert span.start < 2202, "it expanded upward"
        assert span.node_type == "if_statement"

    def test_a_bare_try_resolves_to_the_whole_handler(self, hookapi):
        span = span_for(hookapi, 511)
        body = render(span)

        assert span.node_type == "try_statement"
        assert "EMISSION_FAILURE" in body, "the catch is the point of citing it"

    def test_the_cited_line_is_marked(self, hookapi):
        assert "→   511" in render(span_for(hookapi, 511))


class TestItNamesTheSymbol:
    """A construct type says what the code is; the symbol says what it is for."""

    def test_a_line_inside_a_method(self, hookapi):
        assert span_for(hookapi, 511).symbol == "HookAPI::emit"

    def test_a_different_method_in_the_same_file(self, hookapi):
        assert span_for(hookapi, 2202).symbol == "HookAPI::slot_subarray"

    def test_the_symbol_appears_in_the_rendering(self, hookapi):
        assert "in HookAPI::emit" in render(span_for(hookapi, 511))


class TestCitationsSharingAConstructMerge:
    def test_six_citations_in_one_function_become_one_block(self, hookapi):
        spans = [span_for(hookapi, n) for n in (505, 508, 511, 553, 562, 571)]

        (merged,) = merge(spans)

        assert merged.lines == [505, 508, 511, 553, 562, 571]
        assert merged.symbol == "HookAPI::emit"

    def test_every_cited_line_is_still_marked(self, hookapi):
        """Two lines inside the same try/catch, so one block carries both."""
        (merged,) = merge([span_for(hookapi, n) for n in (511, 519)])
        body = render(merged, max_lines=20)

        assert "→   511" in body
        assert "→   519" in body

    def test_adjacent_statements_do_not_merge(self, hookapi):
        """Two separate `return`s are two constructs, and collapsing them
        would show code that sits between them as if it were cited."""
        merged = merge([span_for(hookapi, 505), span_for(hookapi, 508)])

        assert len(merged) == 2
        assert all(s.node_type == "return_statement" for s in merged)

    def test_unrelated_citations_stay_apart(self, hookapi):
        merged = merge([span_for(hookapi, 511), span_for(hookapi, 2202)])

        assert len(merged) == 2

    def test_merging_is_order_independent(self, hookapi):
        forward = merge([span_for(hookapi, 505), span_for(hookapi, 553)])
        backward = merge([span_for(hookapi, 553), span_for(hookapi, 505)])

        assert [(s.start, s.end, s.lines) for s in forward] == \
               [(s.start, s.end, s.lines) for s in backward]


class TestLongConstructsAreAbridged:
    """A citation into a 300-line function must still fit on screen, or people
    stop reading citations."""

    def test_it_elides_the_middle(self, hookapi):
        body = render(span_for(hookapi, 511), max_lines=8)

        assert "⋯" in body
        assert len(body.splitlines()) < 30

    def test_a_short_construct_is_shown_whole(self, hookapi):
        span = span_for(hookapi, 2202)
        body = render(span, max_lines=40)

        assert "⋯" not in body
        assert len(body.splitlines()) == span.length + 1   # + the header


class TestItDegradesRatherThanGuesses:
    def test_an_unparseable_line_falls_back_to_itself(self, tmp_path):
        f = tmp_path / "x.cpp"
        f.write_text("\n\n\n")

        span = span_for(f, 2)

        assert (span.start, span.end) == (2, 2)
        assert span.node_type == "line"

    def test_a_citation_into_an_unvendored_file_says_so(self):
        assert "not vendored" in cite("src/nope/missing.cpp", 1).context()

    def test_context_beats_snippet_for_a_brace(self):
        c = cite(HOOKAPI, 2202)

        assert c.snippet().strip() == "}"
        assert "if (new_slot != parent_slot)" in c.context()
