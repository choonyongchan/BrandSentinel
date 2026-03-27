"""Integration tests: Filter.should_process → Processor.classify routing."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.filter import Filter
from src.processor import Processor
from src.verdict import Verdict


class TestFilterToProcessorFlow:
    """Integration tests calling Filter and Processor directly."""

    def test_accepted_domain_passes_filter(self):
        """A domain matching brand accept keywords returns True from should_process."""
        assert Filter.should_process("phish-testbrand.com") is True

    def test_rejected_domain_fails_filter(self):
        """A domain with no matching brand keyword returns False from should_process."""
        assert Filter.should_process("totally-unrelated.com") is False

    def test_reject_keyword_stops_accepted_domain(self):
        """Domain matching both accept and reject keywords returns False."""
        # TEST_CONFIG: accept_keywords=["testbrand"], reject_keywords=["legitimate"]
        assert Filter.should_process("legitimate-testbrand.com") is False

    async def test_blacklisted_domain_bypasses_heuristics(self, monkeypatch):
        """Processor returns SCAM for blacklisted domain without calling build_context."""
        build_context_called = []

        async def fake_build_context(domain):
            build_context_called.append(domain)
            return MagicMock()

        monkeypatch.setattr("src.processor.build_context", fake_build_context)

        # TEST_CONFIG auto_scam_substrings=["evilbank"]
        verdict = await Processor.classify("evilbank-testbrand.com")

        assert build_context_called == []
        assert verdict is Verdict.SCAM

    def test_multiple_domains_routed_correctly(self):
        """Multiple domains are each routed correctly by Filter."""
        domains_input = [
            "phish-testbrand.com",       # accepted
            "legitimate-testbrand.com",  # rejected (reject keyword)
            "unrelated.org",             # not accepted
        ]
        results = {d: Filter.should_process(d) for d in domains_input}

        assert results["phish-testbrand.com"] is True
        assert results["legitimate-testbrand.com"] is False
        assert results["unrelated.org"] is False
