"""Unit tests for src/filter.py: Filter stateless utility class."""

import pytest

from src.filter import Filter


class TestFilterContainsAny:
    """Tests for Filter.contains_any static method."""

    def test_match_returns_true(self):
        assert Filter.contains_any("login-testbrand.com", ["testbrand"]) is True

    def test_no_match_returns_false(self):
        assert Filter.contains_any("example.com", ["testbrand"]) is False

    def test_empty_text_returns_false(self):
        assert Filter.contains_any("", ["testbrand"]) is False

    def test_empty_keywords_returns_false(self):
        assert Filter.contains_any("testbrand.com", []) is False

    def test_keyword_case_insensitive(self):
        # Keywords are normalized (lowercased); text should also be lowercase (caller's responsibility)
        assert Filter.contains_any("login-testbrand.com", ["TestBrand"]) is True

    def test_empty_keyword_in_list_ignored(self):
        assert Filter.contains_any("example.com", ["", "notexist"]) is False

    def test_partial_substring_match(self):
        assert Filter.contains_any("sub.testbrand.com", ["testbrand"]) is True

    def test_multiple_keywords_any_matches(self):
        assert Filter.contains_any("testbrand.evil.com", ["other", "testbrand"]) is True

    def test_all_empty_keywords_returns_false(self):
        assert Filter.contains_any("testbrand.com", ["", "  "]) is False


class TestFilterNormalize:
    """Tests for Filter.normalize static method."""

    def test_strips_whitespace(self):
        assert Filter.normalize("  testbrand  ") == "testbrand"

    def test_lowercases(self):
        assert Filter.normalize("TestBrand") == "testbrand"

    def test_empty_string(self):
        assert Filter.normalize("") == ""

    def test_already_lowercase(self):
        assert Filter.normalize("hello") == "hello"


class TestFilterShouldProcess:
    """Tests for Filter.should_process static method.

    Uses TEST_CONFIG with one brand: TestBrand, accept=["testbrand"], reject=["legitimate"].
    """

    def test_accepted_domain_returns_true(self):
        assert Filter.should_process("phish-testbrand.com") is True

    def test_rejected_domain_returns_false(self):
        # Matches accept keyword but also reject keyword
        assert Filter.should_process("legitimate-testbrand.com") is False

    def test_no_accept_match_returns_false(self):
        assert Filter.should_process("unrelated-site.com") is False

    def test_empty_domain_returns_false(self):
        assert Filter.should_process("") is False

    def test_url_input_normalized_first(self):
        # normalize_host strips scheme and path
        assert Filter.should_process("https://phish-testbrand.com/login") is True

    def test_reject_keyword_alone_is_insufficient_to_accept(self):
        # "legitimate" is in reject_keywords but not in accept_keywords
        assert Filter.should_process("legitimate.com") is False

    def test_accept_requires_keyword_in_domain(self):
        assert Filter.should_process("com.testbrandphishing.net") is True

    def test_wildcard_domain_normalized(self):
        assert Filter.should_process("*.testbrand.com") is True


class TestFilterMatchingBrand:
    """Tests for Filter.matching_brand static method.

    Uses TEST_CONFIG with one brand: TestBrand,
    accept=[\"testbrand\"], reject=[\"legitimate\"].
    """

    def test_returns_brand_name_for_matching_domain(self):
        assert Filter.matching_brand("phish-testbrand.com") == "TestBrand"

    def test_returns_none_for_non_matching_domain(self):
        assert Filter.matching_brand("unrelated-site.com") is None

    def test_returns_none_when_reject_keyword_present(self):
        assert Filter.matching_brand("legitimate-testbrand.com") is None

    def test_returns_none_for_empty_domain(self):
        assert Filter.matching_brand("") is None

    def test_url_input_normalized_before_matching(self):
        assert Filter.matching_brand("https://phish-testbrand.com/login") == "TestBrand"

    def test_consistent_with_should_process_true(self):
        """``matching_brand`` returns non-None whenever ``should_process`` returns True."""
        domain = "evil-testbrand.net"
        assert Filter.should_process(domain) is True
        assert Filter.matching_brand(domain) is not None

    def test_consistent_with_should_process_false(self):
        """``matching_brand`` returns None whenever ``should_process`` returns False."""
        domain = "unrelated.org"
        assert Filter.should_process(domain) is False
        assert Filter.matching_brand(domain) is None
