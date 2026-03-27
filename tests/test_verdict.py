"""Unit tests for src/verdict.py: Verdict enum membership."""

from src.verdict import Verdict


class TestVerdict:
    """Tests for the Verdict enum."""

    def test_scam_value(self):
        assert Verdict.SCAM.value == "scam"

    def test_inconclusive_value(self):
        assert Verdict.INCONCLUSIVE.value == "inconclusive"

    def test_benign_value(self):
        assert Verdict.BENIGN.value == "benign"

    def test_irrelevant_value(self):
        assert Verdict.IRRELEVANT.value == "irrelevant"

    def test_all_members_present(self):
        members = {v.value for v in Verdict}
        assert members == {"scam", "inconclusive", "benign", "irrelevant"}

    def test_lookup_by_value(self):
        assert Verdict("scam") is Verdict.SCAM
        assert Verdict("benign") is Verdict.BENIGN
