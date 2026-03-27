"""Shared pytest fixtures for BrandSentinel test suite.

Provides test-scoped CONFIG overrides, HTTP mocks, and domain context
factory helpers that are available to all test modules.
"""

from typing import Any, List, Optional
from unittest.mock import AsyncMock

import pytest

from src.config import (
    Brand,
    Config,
    IngestConfig,
    IngestEnable,
    IngestIntervals,
    ProcessorConfig,
    ProcessorThresholds,
)
from src.enricher import (
    CertInfo,
    CnameInfo,
    CtInfo,
    DNSInfo,
    DomainContext,
    FaviconInfo,
    FetchResults,
    RegistrationInfo,
)
from src.http_client import FetchResult


# ---------------------------------------------------------------------------
# Canonical test configuration (no file I/O — pure Python construction)
# ---------------------------------------------------------------------------

TEST_CONFIG: Config = Config(
    ingester=IngestConfig(
        enable=IngestEnable(
            openphish=False,
            phishtank=False,
            urlhaus=False,
            certstream=False,
            manual=False,
            certpolska=False,
            phishingdatabase=False,
            phishingarmy=False,
            botvrij=False,
            digitalside=False,
            urlhaus_country=False,
        ),
        urlhaus_country_codes=[],
        intervals=IngestIntervals(
            openphish=43200,
            phishtank=3600,
            urlhaus=300,
            certpolska=300,
            phishingdatabase=86400,
            phishingarmy=21600,
            botvrij=86400,
            digitalside=86400,
            urlhaus_country=600,
            manual=30,
        ),
    ),
    processor=ProcessorConfig(
        thresholds=ProcessorThresholds(
            scam=0.4,
            lookalike_max_distance=10,
            redirect_min_hops=2,
            cloaking_diff_ratio=0.5,
            cloaking_min_content_len=500,
            cert_age_days=30,
            brand_density_threshold=0.05,
            fast_flux_min_a=5,
            fast_flux_max_ttl=300,
            subdomain_min_depth=3,
            new_domain_days=30,
            ct_few_certs=2,
        ),
        trusted_domain_substrings=["pages.dev"],
        auto_scam_substrings=["evilbank"],
        suspicious_content_tokens=["login", "verify"],
        parking_signatures=["domain for sale"],
        kit_paths=["/owa"],
        suspicious_tlds=["xyz", "tk"],
        brand_favicon_hashes=[],
        bulletproof_hosting_substrings=["bulletproof-host"],
    ),
    brands=[
        Brand(
            name="TestBrand",
            canonical_domains=["testbrand.com"],
            domain_match_keywords=["testbrand"],
            domain_exclude_keywords=["legitimate"],
        )
    ],
)


# ---------------------------------------------------------------------------
# CONFIG patch — runs for every test function (autouse)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_config(monkeypatch):
    """Patch CONFIG in every module that caches it at import time.

    Also resets class-level attributes derived from CONFIG so individual
    tests are not affected by the values loaded from the real config.yaml.

    Returns:
        The TEST_CONFIG object, allowing tests to inspect or reference it.
    """
    import src.config
    import src.filter
    import src.heuristics
    import src.ingester
    import src.processor

    for mod in (
        src.config,
        src.filter,
        src.processor,
        src.heuristics,
        src.ingester,
    ):
        monkeypatch.setattr(mod, "CONFIG", TEST_CONFIG)

    # These class-level attributes are evaluated at class definition time
    # and therefore hold values from the real config.yaml unless reset.
    monkeypatch.setattr(
        "src.processor.Processor.scam_threshold",
        TEST_CONFIG.processor.thresholds.scam,
    )
    return TEST_CONFIG


# ---------------------------------------------------------------------------
# Singleton state resets — run for every test function (autouse)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_visited_domains():
    """Clear Source.VISITED_DOMAINS before and after each test.

    Prevents cross-test contamination from the global dedup set maintained
    by the Source base class.
    """
    from src.ingester import Source

    Source.VISITED_DOMAINS.clear()
    yield
    Source.VISITED_DOMAINS.clear()


# ---------------------------------------------------------------------------
# HTTP mock helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_http_fetch(monkeypatch):
    """Patch HTTPClient.fetch to return a default stub FetchResult.

    The returned AsyncMock's ``return_value`` can be overridden in individual
    tests to simulate different HTTP responses.

    Returns:
        The AsyncMock replacing HTTPClient.fetch.
    """
    import src.http_client

    default = FetchResult(
        url="http://testbrand-phish.com",
        status=200,
        headers={},
        html="",
        history=[],
        final_url="http://testbrand-phish.com",
        elapsed_ms=50.0,
    )
    mock_fetch = AsyncMock(return_value=default)
    monkeypatch.setattr(src.http_client.HTTPClient, "fetch", mock_fetch)
    return mock_fetch


# ---------------------------------------------------------------------------
# DomainContext factory
# ---------------------------------------------------------------------------

@pytest.fixture
def make_context():
    """Factory fixture that builds DomainContext objects with sensible defaults.

    Returns:
        A callable that accepts keyword arguments overriding any context field.
        The caller receives a fully populated ``DomainContext`` ready for
        heuristic evaluation.
    """

    def _factory(
        domain: str = "phish-testbrand.com",
        html: str = "",
        alt_html: str = "",
        status: int = 200,
        final_url: Optional[str] = None,
        history: Optional[List[int]] = None,
        headers: Optional[dict] = None,
        alt_headers: Optional[dict] = None,
        a_records: Optional[List[str]] = None,
        aaaa_records: Optional[List[str]] = None,
        mx: Optional[List[str]] = None,
        ns: Optional[List[str]] = None,
        spf: Optional[List[str]] = None,
        dmarc: Optional[List[str]] = None,
        ttl_min: Optional[int] = 300,
        dns_error: Optional[str] = None,
        ptr_records: Optional[List[str]] = None,
        cert_cn: Optional[str] = None,
        cert_org: Optional[str] = None,
        cert_san: Optional[List[str]] = None,
        cert_not_before: Optional[str] = None,
        cert_not_after: Optional[str] = None,
        cert_error: Optional[str] = None,
        host: Optional[str] = None,
        registrable: Optional[str] = None,
        dns: Optional[DNSInfo] = None,
        registration: Optional[RegistrationInfo] = None,
        favicon: Optional[FaviconInfo] = None,
        cname: Optional[CnameInfo] = None,
        ct: Optional[CtInfo] = None,
        robots_txt: Optional[str] = None,
    ) -> DomainContext:
        if host is None:
            host = domain
        if final_url is None:
            final_url = f"http://{host}"

        primary = FetchResult(
            url=f"http://{host}",
            status=status,
            headers=headers or {},
            html=html,
            history=history or [],
            final_url=final_url,
            elapsed_ms=50.0,
        )
        alternative = FetchResult(
            url=f"http://{host}",
            status=status,
            headers=alt_headers or {},
            html=alt_html,
            history=[],
            final_url=final_url,
            elapsed_ms=50.0,
        )

        if dns is None:
            dns = DNSInfo(
                a_records=a_records if a_records is not None else ["1.2.3.4"],
                aaaa_records=aaaa_records or [],
                mx=mx or [],
                ns=ns if ns is not None else ["ns1.example.com"],
                spf=spf or [],
                dmarc=dmarc or [],
                ttl_min=ttl_min,
                error=dns_error,
                ptr_records=ptr_records if ptr_records is not None else [],
            )

        cert = CertInfo(
            cn=cert_cn,
            san=cert_san or [],
            org=cert_org,
            not_before=cert_not_before,
            not_after=cert_not_after,
            error=cert_error,
        )

        return DomainContext(
            domain=domain,
            scheme_url=f"http://{host}",
            fetches=FetchResults(primary=primary, alternative=alternative),
            dns=dns,
            cert=cert,
            registrable=registrable or host,
            host=host,
            registration=registration,
            favicon=favicon,
            cname=cname,
            ct=ct,
            robots_txt=robots_txt,
        )

    return _factory
