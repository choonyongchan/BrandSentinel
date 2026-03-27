"""Unit tests for src/config.py: Config.load() with valid and invalid YAML."""

import textwrap
import pytest

from src.config import Config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_YAML = textwrap.dedent("""\
    ingester:
      enable:
        openphish: true
        phishtank: false
        urlhaus: true
        certstream: false
        manual: true
        certpolska: false
        phishingdatabase: false
        phishingarmy: false
        botvrij: false
        digitalside: false
        urlhaus_country: false
      urlhaus_country_codes: []
      intervals:
        openphish: 43200
        phishtank: 3600
        urlhaus: 300
        certpolska: 300
        phishingdatabase: 86400
        phishingarmy: 21600
        botvrij: 86400
        digitalside: 86400
        urlhaus_country: 600
        manual: 30

    processor:
      thresholds:
        scam: 0.4
        lookalike_max_distance: 10
        redirect_min_hops: 2
        cloaking_diff_ratio: 0.5
        cloaking_min_content_len: 500
        cert_age_days: 30
        brand_density_threshold: 0.05
        fast_flux_min_a: 5
        fast_flux_max_ttl: 300
        subdomain_min_depth: 3
        new_domain_days: 30
        ct_few_certs: 2
      suspicious_content_tokens: ["login", "verify"]
      parking_signatures: ["domain for sale"]
      kit_paths: ["/owa"]
      trusted_domain_substrings: ["pages.dev"]
      auto_scam_substrings: ["evilbank"]
      suspicious_tlds: ["xyz"]
      brand_favicon_hashes: []
      bulletproof_hosting_substrings: ["bulletproof"]

    brands:
      - name: TestBrand
        canonical_domains: ["testbrand.com"]
        domain_match_keywords: ["testbrand"]
        domain_exclude_keywords: []
""")


def write_config(tmp_path, content: str) -> str:
    p = tmp_path / "config.yaml"
    p.write_text(content, encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestConfigLoad:
    """Tests for Config.load() with various YAML inputs."""

    def test_load_valid_config(self, tmp_path):
        path = write_config(tmp_path, VALID_YAML)
        cfg = Config.load(path)

        assert cfg.ingester.enable.openphish is True
        assert cfg.ingester.enable.phishtank is False
        assert cfg.processor.thresholds.scam == 0.4
        assert len(cfg.brands) == 1
        assert cfg.brands[0].name == "TestBrand"
        assert cfg.brands[0].canonical_domains == ["testbrand.com"]

    def test_load_missing_file(self):
        with pytest.raises(FileNotFoundError):
            Config.load("/nonexistent/path/config.yaml")

    def test_load_missing_ingester_section(self, tmp_path):
        no_ingester = textwrap.dedent("""\
            processor:
              thresholds:
                scam: 0.4
                lookalike_max_distance: 10
                redirect_min_hops: 2
                cloaking_diff_ratio: 0.5
                cloaking_min_content_len: 500
                cert_age_days: 30
                brand_density_threshold: 0.05
                fast_flux_min_a: 5
                fast_flux_max_ttl: 300
                subdomain_min_depth: 3
                new_domain_days: 30
                ct_few_certs: 2
              suspicious_content_tokens: ["login"]
              parking_signatures: ["domain for sale"]
              kit_paths: ["/owa"]
              trusted_domain_substrings: ["pages.dev"]
              auto_scam_substrings: ["evilbank"]
              suspicious_tlds: ["xyz"]
              brand_favicon_hashes: []
              bulletproof_hosting_substrings: ["bulletproof"]
            brands:
              - name: TestBrand
                canonical_domains: ["testbrand.com"]
                domain_match_keywords: ["testbrand"]
                domain_exclude_keywords: []
        """)
        path = write_config(tmp_path, no_ingester)
        with pytest.raises(ValueError):
            Config.load(path)

    def test_load_missing_processor_thresholds(self, tmp_path):
        lines = []
        in_thresholds = False
        for line in VALID_YAML.splitlines(keepends=True):
            if line.rstrip() == "  thresholds:":
                in_thresholds = True
                continue
            if in_thresholds and line.startswith("    "):
                continue
            in_thresholds = False
            lines.append(line)
        path = write_config(tmp_path, "".join(lines))
        with pytest.raises(ValueError):
            Config.load(path)

    def test_load_missing_brands_section(self, tmp_path):
        yaml = "\n".join(
            line for line in VALID_YAML.splitlines()
            if not line.startswith("brands") and "TestBrand" not in line
            and "canonical_domains" not in line and "domain_match" not in line
            and "domain_exclude" not in line and "- name:" not in line
        )
        path = write_config(tmp_path, yaml)
        with pytest.raises(ValueError):
            Config.load(path)

    def test_load_empty_file(self, tmp_path):
        path = write_config(tmp_path, "")
        with pytest.raises((ValueError, FileNotFoundError, KeyError)):
            Config.load(path)

    def test_load_non_mapping_root(self, tmp_path):
        path = write_config(tmp_path, "- item1\n- item2\n")
        with pytest.raises(ValueError):
            Config.load(path)

    def test_load_brand_missing_canonical_domains(self, tmp_path):
        yaml = VALID_YAML.replace(
            "        canonical_domains: [\"testbrand.com\"]\n",
            "",
        ).replace(
            "    canonical_domains: [\"testbrand.com\"]\n",
            "",
        )
        path = write_config(tmp_path, yaml)
        with pytest.raises(ValueError):
            Config.load(path)

    def test_enable_flags_are_bool(self, tmp_path):
        path = write_config(tmp_path, VALID_YAML)
        cfg = Config.load(path)
        assert isinstance(cfg.ingester.enable.certstream, bool)
        assert isinstance(cfg.ingester.enable.openphish, bool)

    def test_scam_threshold_is_float(self, tmp_path):
        path = write_config(tmp_path, VALID_YAML)
        cfg = Config.load(path)
        assert isinstance(cfg.processor.thresholds.scam, float)

    def test_trusted_domain_substrings_is_list(self, tmp_path):
        path = write_config(tmp_path, VALID_YAML)
        cfg = Config.load(path)
        assert isinstance(cfg.processor.trusted_domain_substrings, list)

    def test_multiple_brands_parsed(self, tmp_path):
        two_brand_yaml = textwrap.dedent("""\
            ingester:
              enable:
                openphish: true
                phishtank: false
                urlhaus: true
                certstream: false
                manual: true
                certpolska: false
                phishingdatabase: false
                phishingarmy: false
                botvrij: false
                digitalside: false
                urlhaus_country: false
              urlhaus_country_codes: []
              intervals:
                openphish: 43200
                phishtank: 3600
                urlhaus: 300
                certpolska: 300
                phishingdatabase: 86400
                phishingarmy: 21600
                botvrij: 86400
                digitalside: 86400
                urlhaus_country: 600
                manual: 30

            processor:
              thresholds:
                scam: 0.4
                lookalike_max_distance: 10
                redirect_min_hops: 2
                cloaking_diff_ratio: 0.5
                cloaking_min_content_len: 500
                cert_age_days: 30
                brand_density_threshold: 0.05
                fast_flux_min_a: 5
                fast_flux_max_ttl: 300
                subdomain_min_depth: 3
                new_domain_days: 30
                ct_few_certs: 2
              suspicious_content_tokens: ["login"]
              parking_signatures: ["domain for sale"]
              kit_paths: ["/owa"]
              trusted_domain_substrings: ["pages.dev"]
              auto_scam_substrings: ["evilbank"]
              suspicious_tlds: ["xyz"]
              brand_favicon_hashes: []
              bulletproof_hosting_substrings: ["bulletproof"]

            brands:
              - name: TestBrand
                canonical_domains: ["testbrand.com"]
                domain_match_keywords: ["testbrand"]
                domain_exclude_keywords: []
              - name: AnotherBrand
                canonical_domains: ["another.com"]
                domain_match_keywords: ["another"]
                domain_exclude_keywords: []
        """)
        path = write_config(tmp_path, two_brand_yaml)
        cfg = Config.load(path)
        assert len(cfg.brands) == 2
        assert cfg.brands[1].name == "AnotherBrand"
