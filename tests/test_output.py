"""Unit tests for src/output.py: Output.write static method."""

import pytest

from src.output import Output
from src.verdict import Verdict


class TestOutputWrite:
    """Tests for Output.write static method."""

    # ------------------------------------------------------------------
    # Without brand (irrelevant / no-brand path)
    # ------------------------------------------------------------------

    def test_irrelevant_written_to_results_irrelevant_txt(self, tmp_path, monkeypatch):
        """No brand → file written directly under ``results/``."""
        monkeypatch.chdir(tmp_path)
        Output.write("unrelated.com", Verdict.IRRELEVANT)
        assert (tmp_path / "results" / "irrelevant.txt").exists()
        content = (tmp_path / "results" / "irrelevant.txt").read_text(encoding="utf-8")
        assert "unrelated.com\n" in content

    def test_no_brand_writes_under_results_root(self, tmp_path, monkeypatch):
        """``brand=None`` writes to ``results/<verdict>.txt`` (no sub-directory)."""
        monkeypatch.chdir(tmp_path)
        Output.write("evil.com", Verdict.SCAM, brand=None)
        assert (tmp_path / "results" / "scam.txt").exists()
        # No sub-directories should be created when brand is None
        entries = list((tmp_path / "results").iterdir())
        assert all(e.is_file() for e in entries)

    # ------------------------------------------------------------------
    # With brand (per-brand sub-directory path)
    # ------------------------------------------------------------------

    def test_scam_written_to_brand_subdir(self, tmp_path, monkeypatch):
        """Brand-matched scam domain goes to ``results/<brand>/scam.txt``."""
        monkeypatch.chdir(tmp_path)
        Output.write("evil.com", Verdict.SCAM, brand="TestBrand")
        content = (tmp_path / "results" / "TestBrand" / "scam.txt").read_text(encoding="utf-8")
        assert "evil.com\n" in content

    def test_benign_written_to_brand_subdir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Output.write("clean.com", Verdict.BENIGN, brand="TestBrand")
        assert (tmp_path / "results" / "TestBrand" / "benign.txt").exists()
        content = (tmp_path / "results" / "TestBrand" / "benign.txt").read_text(encoding="utf-8")
        assert "clean.com\n" in content

    def test_inconclusive_written_to_brand_subdir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Output.write("maybe.com", Verdict.INCONCLUSIVE, brand="TestBrand")
        assert (tmp_path / "results" / "TestBrand" / "inconclusive.txt").exists()

    def test_brand_directory_created_automatically(self, tmp_path, monkeypatch):
        """``results/<brand>/`` is created on first write if it does not exist."""
        monkeypatch.chdir(tmp_path)
        assert not (tmp_path / "results").exists()
        Output.write("evil.com", Verdict.SCAM, brand="MyBrand")
        assert (tmp_path / "results" / "MyBrand").is_dir()

    def test_different_brands_use_separate_subdirs(self, tmp_path, monkeypatch):
        """Each brand gets its own sub-directory under ``results/``."""
        monkeypatch.chdir(tmp_path)
        Output.write("dbs-evil.com", Verdict.SCAM, brand="DBS Bank")
        Output.write("uob-evil.com", Verdict.SCAM, brand="UOB Bank")
        assert (tmp_path / "results" / "DBS Bank" / "scam.txt").exists()
        assert (tmp_path / "results" / "UOB Bank" / "scam.txt").exists()

    # ------------------------------------------------------------------
    # General behaviour
    # ------------------------------------------------------------------

    def test_multiple_domains_each_on_new_line(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        domains = ["evil1.com", "evil2.com", "evil3.com"]
        for d in domains:
            Output.write(d, Verdict.SCAM, brand="TestBrand")
        content = (tmp_path / "results" / "TestBrand" / "scam.txt").read_text(encoding="utf-8")
        lines = [l for l in content.splitlines() if l]
        assert lines == domains

    def test_domain_stripped_before_write(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Output.write("  evil.com  ", Verdict.SCAM, brand="TestBrand")
        content = (tmp_path / "results" / "TestBrand" / "scam.txt").read_text(encoding="utf-8")
        assert content == "evil.com\n"

    def test_file_opened_in_append_mode(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "results" / "TestBrand").mkdir(parents=True)
        (tmp_path / "results" / "TestBrand" / "scam.txt").write_text(
            "existing.com\n", encoding="utf-8"
        )
        Output.write("new.com", Verdict.SCAM, brand="TestBrand")
        content = (tmp_path / "results" / "TestBrand" / "scam.txt").read_text(encoding="utf-8")
        assert "existing.com\n" in content
        assert "new.com\n" in content

    def test_verdict_value_determines_filename(self, tmp_path, monkeypatch):
        """Verify verdict.value is used as filename stem."""
        monkeypatch.chdir(tmp_path)
        Output.write("test.com", Verdict.INCONCLUSIVE, brand="TestBrand")
        assert (tmp_path / "results" / "TestBrand" / "inconclusive.txt").exists()
        assert not (tmp_path / "results" / "TestBrand" / "scam.txt").exists()
