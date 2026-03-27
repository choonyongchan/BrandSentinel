"""Unit tests for src/processor.py: Processor classification logic."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.heuristics import HeuristicBase, HeuristicResults
from src.processor import Processor
from src.verdict import Verdict


def _result(*, scam=False, benign=False, suspicious=False, weight=1) -> HeuristicResults:
    return HeuristicResults(
        name="test",
        is_scam_definitive=scam,
        is_benign_definitive=benign,
        suspicious=suspicious,
        evidence="",
    )


def _heuristic(*, scam=False, benign=False, suspicious=False, weight=1) -> HeuristicBase:
    h = MagicMock(spec=HeuristicBase)
    h.weight = weight
    h.evaluate.return_value = _result(scam=scam, benign=benign, suspicious=suspicious)
    return h


# ---------------------------------------------------------------------------
# Trusted / auto-scam static methods
# ---------------------------------------------------------------------------

class TestProcessorTrustedAutoScam:
    """Tests for is_trusted and is_auto_scam.

    TEST_CONFIG: trusted_domain_substrings=["pages.dev"], auto_scam_substrings=["evilbank"].
    """

    def test_trusted_host_returns_true(self):
        assert Processor.is_trusted("app.pages.dev") is True

    def test_non_trusted_host_returns_false(self):
        assert Processor.is_trusted("evil.example.com") is False

    def test_trusted_check_case_insensitive(self):
        assert Processor.is_trusted("APP.PAGES.DEV") is True

    def test_auto_scam_host_returns_true(self):
        assert Processor.is_auto_scam("evilbank-login.com") is True

    def test_non_auto_scam_host_returns_false(self):
        assert Processor.is_auto_scam("cleansite.example.com") is False

    def test_auto_scam_check_case_insensitive(self):
        assert Processor.is_auto_scam("EVILBANK.COM") is True

    def test_empty_host_not_trusted(self):
        assert Processor.is_trusted("") is False

    def test_empty_host_not_auto_scam(self):
        assert Processor.is_auto_scam("") is False


# ---------------------------------------------------------------------------
# Processor.classify — return-value routing
# ---------------------------------------------------------------------------

class TestProcessorClassify:
    """Tests for the async Processor.classify classification logic."""

    async def test_trusted_domain_returns_none(self):
        result = await Processor.classify("app.pages.dev")
        assert result is None

    async def test_auto_scam_domain_returns_scam(self):
        result = await Processor.classify("evilbank-login.com")
        assert result is Verdict.SCAM

    async def test_trusted_takes_precedence_over_auto_scam(self, monkeypatch):
        """A domain matching both lists is silently dropped (trusted checked first)."""
        import src.processor
        from src.config import ProcessorConfig

        from tests.conftest import TEST_CONFIG
        from src.config import Config

        dual_config = Config(
            ingester=TEST_CONFIG.ingester,
            processor=ProcessorConfig(
                thresholds=TEST_CONFIG.processor.thresholds,
                trusted_domain_substrings=["evilbank"],
                auto_scam_substrings=["evilbank"],
                suspicious_content_tokens=[],
                parking_signatures=[],
                kit_paths=[],
                suspicious_tlds=[],
                brand_favicon_hashes=[],
                bulletproof_hosting_substrings=[],
            ),
            brands=TEST_CONFIG.brands,
        )
        monkeypatch.setattr(src.processor, "CONFIG", dual_config)

        result = await Processor.classify("evilbank.com")
        assert result is None

    async def test_definitive_scam_returns_scam(self, monkeypatch):
        stub_ctx = MagicMock()
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=stub_ctx))
        monkeypatch.setattr("src.processor.Processor.heuristics", [_heuristic(scam=True)])

        result = await Processor.classify("phish-testbrand.com")
        assert result is Verdict.SCAM

    async def test_definitive_benign_returns_benign(self, monkeypatch):
        stub_ctx = MagicMock()
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=stub_ctx))
        monkeypatch.setattr("src.processor.Processor.heuristics", [_heuristic(benign=True)])

        result = await Processor.classify("phish-testbrand.com")
        assert result is Verdict.BENIGN

    async def test_scam_definitive_overrides_benign(self, monkeypatch):
        stub_ctx = MagicMock()
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=stub_ctx))
        monkeypatch.setattr(
            "src.processor.Processor.heuristics",
            [_heuristic(scam=True), _heuristic(benign=True)],
        )

        result = await Processor.classify("phish-testbrand.com")
        assert result is Verdict.SCAM

    async def test_weight_sum_reaches_threshold_returns_scam(self, monkeypatch):
        """3 of 5 weight-1 heuristics fire → score=0.6 ≥ threshold=0.4 → SCAM."""
        stub_ctx = MagicMock()
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=stub_ctx))
        monkeypatch.setattr(
            "src.processor.Processor.heuristics",
            [_heuristic(suspicious=True, weight=1)] * 3
            + [_heuristic(suspicious=False, weight=1)] * 2,
        )

        result = await Processor.classify("phish-testbrand.com")
        assert result is Verdict.SCAM

    async def test_weight_sum_below_threshold_returns_inconclusive(self, monkeypatch):
        """1 of 5 weight-1 heuristics fires → score=0.2 < threshold=0.4 → INCONCLUSIVE."""
        stub_ctx = MagicMock()
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=stub_ctx))
        monkeypatch.setattr(
            "src.processor.Processor.heuristics",
            [_heuristic(suspicious=True, weight=1)]
            + [_heuristic(suspicious=False, weight=1)] * 4,
        )

        result = await Processor.classify("phish-testbrand.com")
        assert result is Verdict.INCONCLUSIVE

    async def test_no_signals_returns_inconclusive(self, monkeypatch):
        stub_ctx = MagicMock()
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=stub_ctx))
        monkeypatch.setattr(
            "src.processor.Processor.heuristics",
            [_heuristic()],  # neutral
        )

        result = await Processor.classify("phish-testbrand.com")
        assert result is Verdict.INCONCLUSIVE

    async def test_scam_definitive_stops_subsequent_heuristics(self, monkeypatch):
        """Heuristics after a scam-definitive one are not called."""
        stub_ctx = MagicMock()
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=stub_ctx))

        h_scam = _heuristic(scam=True)
        h_after = _heuristic(suspicious=True, weight=99)
        monkeypatch.setattr("src.processor.Processor.heuristics", [h_scam, h_after])

        result = await Processor.classify("phish-testbrand.com")

        assert result is Verdict.SCAM
        h_after.evaluate.assert_not_called()

    async def test_benign_definitive_stops_subsequent_heuristics(self, monkeypatch):
        """Heuristics after a benign-definitive one are not called."""
        stub_ctx = MagicMock()
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=stub_ctx))

        h_benign = _heuristic(benign=True)
        h_after = _heuristic(suspicious=True, weight=99)
        monkeypatch.setattr("src.processor.Processor.heuristics", [h_benign, h_after])

        result = await Processor.classify("phish-testbrand.com")

        assert result is Verdict.BENIGN
        h_after.evaluate.assert_not_called()

    async def test_scam_definitive_before_benign_returns_scam(self, monkeypatch):
        """Scam-definitive heuristic ordered before benign-definitive yields SCAM."""
        stub_ctx = MagicMock()
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=stub_ctx))

        monkeypatch.setattr(
            "src.processor.Processor.heuristics",
            [_heuristic(scam=True), _heuristic(benign=True)],
        )

        result = await Processor.classify("phish-testbrand.com")
        assert result is Verdict.SCAM

    async def test_weight_from_heuristic_weight_attribute(self, monkeypatch):
        """weight-3 + weight-1 both fire → score=1.0 ≥ threshold=0.4 → SCAM."""
        stub_ctx = MagicMock()
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=stub_ctx))
        monkeypatch.setattr(
            "src.processor.Processor.heuristics",
            [_heuristic(suspicious=True, weight=3), _heuristic(suspicious=True, weight=1)],
        )

        result = await Processor.classify("phish-testbrand.com")
        assert result is Verdict.SCAM

    async def test_neutral_heuristics_contribute_zero_weight(self, monkeypatch):
        """Neutral heuristics add 0 to the weight tally → INCONCLUSIVE."""
        stub_ctx = MagicMock()
        monkeypatch.setattr("src.processor.build_context", AsyncMock(return_value=stub_ctx))
        monkeypatch.setattr(
            "src.processor.Processor.heuristics",
            [_heuristic(weight=3)] * 5,  # all neutral, suspicious=False
        )

        result = await Processor.classify("phish-testbrand.com")
        assert result is Verdict.INCONCLUSIVE
