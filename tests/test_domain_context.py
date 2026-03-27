"""Unit tests for src/enricher.py: get_dns_info, get_cert_info, build_context, and new enrichment functions."""

import ssl
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.enricher import (
    CertInfo,
    CnameInfo,
    CtInfo,
    DNSInfo,
    DomainContext,
    FaviconInfo,
    RegistrationInfo,
    build_context,
    get_cert_info,
    get_dns_info,
)


# ---------------------------------------------------------------------------
# DNS answer mock helpers
# ---------------------------------------------------------------------------

def make_dns_answer(values: List[str], ttl: int = 300, rdtype: str = "A"):
    """Build a mock dns.resolver answer object."""

    class MockRdata:
        def __init__(self, val):
            self._val = val

        def __str__(self):
            return self._val

        @property
        def exchange(self):
            # For MX records the exchange attribute is the hostname
            class Exch:
                def __str__(self_inner):
                    return self._val
            return Exch()

    class MockRRSet:
        def __init__(self, ttl):
            self.ttl = ttl

    class MockAnswer:
        def __init__(self, vals, ttl):
            self._rdatas = [MockRdata(v) for v in vals]
            self.rrset = MockRRSet(ttl)

        def __iter__(self):
            return iter(self._rdatas)

    return MockAnswer(values, ttl)


# ---------------------------------------------------------------------------
# get_dns_info
# ---------------------------------------------------------------------------

class TestGetDnsInfo:
    """Tests for the async get_dns_info function."""

    async def test_a_records_returned(self, monkeypatch):
        import dns.resolver

        answers = {
            "A": make_dns_answer(["1.2.3.4"], ttl=600),
        }

        async def fake_resolve_async(domain, rdtype):
            if rdtype in answers:
                return answers[rdtype]
            raise dns.resolver.NoAnswer

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(side_effect=fake_resolve_async)

        with patch("src.enricher.dns.asyncresolver.Resolver", return_value=mock_resolver):
            info = await get_dns_info("example.com")

        assert "1.2.3.4" in info.a_records
        assert info.error is None

    async def test_no_answer_for_aaaa_does_not_raise(self, monkeypatch):
        import dns.resolver

        async def fake_resolve_async(domain, rdtype):
            if rdtype == "A":
                return make_dns_answer(["1.2.3.4"])
            raise dns.resolver.NoAnswer

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(side_effect=fake_resolve_async)

        with patch("src.enricher.dns.asyncresolver.Resolver", return_value=mock_resolver):
            info = await get_dns_info("example.com")

        assert info.aaaa_records == []
        assert info.error is None

    async def test_spf_record_filtered_from_txt(self, monkeypatch):
        import dns.resolver

        async def fake_resolve_async(domain, rdtype):
            if rdtype == "TXT":
                return make_dns_answer(["v=spf1 include:example.com ~all", "some-other-txt"])
            raise dns.resolver.NoAnswer

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(side_effect=fake_resolve_async)

        with patch("src.enricher.dns.asyncresolver.Resolver", return_value=mock_resolver):
            info = await get_dns_info("example.com")

        assert len(info.spf) == 1
        assert "spf1" in info.spf[0].lower()

    async def test_dmarc_record_at_underscore_prefix(self, monkeypatch):
        import dns.resolver

        async def fake_resolve_async(domain, rdtype):
            if domain.startswith("_dmarc.") and rdtype == "TXT":
                return make_dns_answer(["v=DMARC1; p=none"])
            raise dns.resolver.NoAnswer

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(side_effect=fake_resolve_async)

        with patch("src.enricher.dns.asyncresolver.Resolver", return_value=mock_resolver):
            info = await get_dns_info("example.com")

        assert len(info.dmarc) == 1
        assert "DMARC1" in info.dmarc[0]

    async def test_ttl_min_tracks_minimum(self, monkeypatch):
        import dns.resolver

        async def fake_resolve_async(domain, rdtype):
            if rdtype == "A":
                return make_dns_answer(["1.2.3.4"], ttl=600)
            if rdtype == "AAAA":
                return make_dns_answer(["::1"], ttl=60)
            raise dns.resolver.NoAnswer

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(side_effect=fake_resolve_async)

        with patch("src.enricher.dns.asyncresolver.Resolver", return_value=mock_resolver):
            info = await get_dns_info("example.com")

        assert info.ttl_min == 60

    async def test_fatal_exception_sets_error_field(self, monkeypatch):
        with patch("src.enricher.dns.asyncresolver.Resolver", side_effect=Exception("NXDOMAIN")):
            info = await get_dns_info("nonexistent.example.com")

        assert info.error is not None
        assert info.a_records == []
        assert info.mx == []

    async def test_all_no_answer_returns_empty_lists(self, monkeypatch):
        import dns.resolver

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer)

        with patch("src.enricher.dns.asyncresolver.Resolver", return_value=mock_resolver):
            info = await get_dns_info("example.com")

        assert info.a_records == []
        assert info.aaaa_records == []
        assert info.mx == []
        assert info.ns == []
        assert info.spf == []
        assert info.dmarc == []
        assert info.error is None


# ---------------------------------------------------------------------------
# get_cert_info
# ---------------------------------------------------------------------------

class TestGetCertInfo:
    """Tests for the async get_cert_info function."""

    def _make_open_connection_mock(
        self,
        cn="example.com",
        org=None,
        san=None,
        not_before="Jan 01 00:00:00 2026 UTC",
        not_after="Jan 01 00:00:00 2027 UTC",
    ):
        subject = [(("commonName", cn),)]
        if org:
            subject.append((("organizationName", org),))

        cert_dict = {
            "subject": subject,
            "subjectAltName": [("DNS", s) for s in (san or [cn])],
            "notBefore": not_before,
            "notAfter": not_after,
        }

        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = cert_dict
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        mock_open_conn = AsyncMock(return_value=(AsyncMock(), mock_writer))
        return mock_open_conn, cert_dict

    async def test_valid_cert_parses_cn(self, monkeypatch):
        mock_open_conn, _ = self._make_open_connection_mock(cn="example.com", org="Example Corp")
        with patch("src.enricher.asyncio.open_connection", mock_open_conn):
            info = await get_cert_info("example.com")
        assert info.cn == "example.com"

    async def test_valid_cert_parses_org(self, monkeypatch):
        mock_open_conn, _ = self._make_open_connection_mock(cn="example.com", org="Example Corp")
        with patch("src.enricher.asyncio.open_connection", mock_open_conn):
            info = await get_cert_info("example.com")
        assert info.org == "Example Corp"

    async def test_cert_without_org_returns_none_org(self, monkeypatch):
        mock_open_conn, _ = self._make_open_connection_mock(cn="example.com", org=None)
        with patch("src.enricher.asyncio.open_connection", mock_open_conn):
            info = await get_cert_info("example.com")
        assert info.org is None

    async def test_cert_san_populated(self, monkeypatch):
        mock_open_conn, _ = self._make_open_connection_mock(cn="example.com", san=["example.com", "www.example.com"])
        with patch("src.enricher.asyncio.open_connection", mock_open_conn):
            info = await get_cert_info("example.com")
        assert "example.com" in info.san
        assert "www.example.com" in info.san

    async def test_connection_refused_sets_error_field(self, monkeypatch):
        mock_open_conn = AsyncMock(side_effect=ConnectionRefusedError("refused"))
        with patch("src.enricher.asyncio.open_connection", mock_open_conn):
            info = await get_cert_info("example.com")

        assert info.error is not None
        assert info.cn is None

    async def test_ssl_error_sets_error_field(self, monkeypatch):
        mock_open_conn = AsyncMock(side_effect=ssl.SSLError("ssl error"))
        with patch("src.enricher.asyncio.open_connection", mock_open_conn):
            info = await get_cert_info("example.com")

        assert info.error is not None
        assert info.cn is None

    async def test_not_before_not_after_populated(self, monkeypatch):
        mock_open_conn, _ = self._make_open_connection_mock(
            not_before="Jan 01 00:00:00 2026 UTC",
            not_after="Jan 01 00:00:00 2027 UTC",
        )
        with patch("src.enricher.asyncio.open_connection", mock_open_conn):
            info = await get_cert_info("example.com")
        assert "2026" in info.not_before
        assert "2027" in info.not_after


# ---------------------------------------------------------------------------
# build_context
# ---------------------------------------------------------------------------

class TestBuildContext:
    """Tests for the async build_context function."""

    def _stub_enrichers(self):
        """Return a dict of AsyncMock stubs for all enricher functions called by build_context."""
        return {
            "src.enricher.get_dns_info": AsyncMock(
                return_value=DNSInfo(a_records=["1.2.3.4"], aaaa_records=[], mx=[], ns=[], spf=[], dmarc=[], ttl_min=300, error=None)
            ),
            "src.enricher.get_cert_info": AsyncMock(
                return_value=CertInfo(cn=None, san=[], org=None, not_before=None, not_after=None, error=None)
            ),
            "src.enricher.get_rdap_info": AsyncMock(
                return_value=RegistrationInfo(created=None, registrar=None, error=None)
            ),
            "src.enricher.get_favicon_info": AsyncMock(
                return_value=FaviconInfo(sha1=None, error=None)
            ),
            "src.enricher.get_cname_info": AsyncMock(
                return_value=CnameInfo(chain=[], error=None)
            ),
            "src.enricher.get_ct_info": AsyncMock(
                return_value=CtInfo(cert_count=0, earliest_date=None, error=None)
            ),
        }

    async def test_build_context_assembles_all_fields(self, monkeypatch):
        from src.http_client import FetchResult

        primary_result = FetchResult(
            url="http://example.com",
            status=200,
            headers={},
            html="<html>Windows page</html>",
            history=[],
            final_url="http://example.com",
            elapsed_ms=50.0,
        )
        alt_result = FetchResult(
            url="http://example.com",
            status=200,
            headers={},
            html="<html>Mobile page</html>",
            history=[],
            final_url="http://example.com",
            elapsed_ms=50.0,
        )

        async def fake_fetch(url, headers=None, timeout=20):
            if "Windows" in (headers or {}).get("User-Agent", ""):
                return primary_result
            return alt_result

        import src.http_client
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch", fake_fetch)

        stubs = self._stub_enrichers()
        stubs["src.enricher.get_dns_info"] = AsyncMock(
            return_value=DNSInfo(a_records=["1.2.3.4"], aaaa_records=[], mx=[], ns=[], spf=[], dmarc=[], ttl_min=300, error=None)
        )
        with patch.multiple("src.enricher", **{k.split(".")[-1]: v for k, v in stubs.items()}):
            ctx = await build_context("example.com")

        assert ctx.domain == "example.com"
        assert ctx.host == "example.com"
        assert ctx.fetches.primary.html == "<html>Windows page</html>"
        assert ctx.fetches.alternative.html == "<html>Mobile page</html>"
        assert ctx.dns.a_records == ["1.2.3.4"]

    async def test_build_context_extracts_registrable(self, monkeypatch):
        from src.http_client import FetchResult

        stub_result = FetchResult(url="", status=200, headers={}, html="", history=[], final_url="", elapsed_ms=0.0)

        async def fake_fetch(url, headers=None, timeout=20):
            return stub_result

        import src.http_client
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch", fake_fetch)

        stubs = self._stub_enrichers()
        with patch.multiple("src.enricher", **{k.split(".")[-1]: v for k, v in stubs.items()}):
            ctx = await build_context("sub.example.com")

        assert ctx.registrable == "example.com"

    async def test_build_context_host_is_normalized(self, monkeypatch):
        from src.http_client import FetchResult

        stub_result = FetchResult(url="", status=200, headers={}, html="", history=[], final_url="", elapsed_ms=0.0)

        async def fake_fetch(url, headers=None, timeout=20):
            return stub_result

        import src.http_client
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch", fake_fetch)

        stubs = self._stub_enrichers()
        with patch.multiple("src.enricher", **{k.split(".")[-1]: v for k, v in stubs.items()}):
            ctx = await build_context("EXAMPLE.COM")

        assert ctx.host == "example.com"

    async def test_build_context_two_fetches_with_different_ua(self, monkeypatch):
        from src.http_client import FetchResult

        stub_result = FetchResult(url="", status=200, headers={}, html="", history=[], final_url="", elapsed_ms=0.0)
        ua_list = []

        async def fake_fetch(url, headers=None, timeout=20):
            ua_list.append((headers or {}).get("User-Agent", ""))
            return stub_result

        import src.http_client
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch", fake_fetch)

        stubs = self._stub_enrichers()
        with patch.multiple("src.enricher", **{k.split(".")[-1]: v for k, v in stubs.items()}):
            await build_context("example.com")

        # build_context fires 3 HTTPClient.fetch calls: primary, alternative, robots.txt
        assert any("Windows" in ua for ua in ua_list)
        assert any("iPhone" in ua for ua in ua_list)


# ---------------------------------------------------------------------------
# New enricher functions
# ---------------------------------------------------------------------------

class TestGetRdapInfo:
    """Tests for the async get_rdap_info function."""

    async def test_success_parses_created_date(self, monkeypatch):
        """Valid RDAP JSON with registration event returns created date."""
        import src.http_client
        rdap_json = b'{"events": [{"eventAction": "registration", "eventDate": "2024-01-15T10:00:00Z"}]}'
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch_bytes", AsyncMock(return_value=(200, rdap_json)))
        from src.enricher import get_rdap_info
        info = await get_rdap_info("example.com")
        assert info.created == "2024-01-15T10:00:00Z"
        assert info.error is None

    async def test_network_error_sets_error(self, monkeypatch):
        """A network failure results in error field set, created=None."""
        import src.http_client
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch_bytes", AsyncMock(side_effect=Exception("timeout")))
        from src.enricher import get_rdap_info
        info = await get_rdap_info("example.com")
        assert info.error is not None
        assert info.created is None

    async def test_non_200_response_sets_error(self, monkeypatch):
        """A 404 from RDAP sets the error field."""
        import src.http_client
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch_bytes", AsyncMock(return_value=(404, b"")))
        from src.enricher import get_rdap_info
        info = await get_rdap_info("example.com")
        assert info.error is not None

    async def test_missing_registration_event_returns_none_created(self, monkeypatch):
        """RDAP JSON with no registration event returns created=None without error."""
        import src.http_client
        rdap_json = b'{"events": [{"eventAction": "expiration", "eventDate": "2026-01-15"}]}'
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch_bytes", AsyncMock(return_value=(200, rdap_json)))
        from src.enricher import get_rdap_info
        info = await get_rdap_info("example.com")
        assert info.created is None
        assert info.error is None


class TestGetFaviconInfo:
    """Tests for the async get_favicon_info function."""

    async def test_200_with_content_returns_sha1(self, monkeypatch):
        """Fetching favicon bytes produces a valid SHA-1 hex string."""
        import src.http_client
        fake_bytes = b"\x89PNG" * 10
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch_bytes", AsyncMock(return_value=(200, fake_bytes)))
        from src.enricher import get_favicon_info
        info = await get_favicon_info("example.com")
        assert info.sha1 is not None
        assert len(info.sha1) == 40  # SHA-1 hex length
        assert info.error is None

    async def test_non_200_returns_none_sha1(self, monkeypatch):
        """A non-200 status for favicon results in sha1=None."""
        import src.http_client
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch_bytes", AsyncMock(return_value=(404, b"")))
        from src.enricher import get_favicon_info
        info = await get_favicon_info("example.com")
        assert info.sha1 is None

    async def test_empty_bytes_returns_none_sha1(self, monkeypatch):
        """Empty favicon body results in sha1=None."""
        import src.http_client
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch_bytes", AsyncMock(return_value=(200, b"")))
        from src.enricher import get_favicon_info
        info = await get_favicon_info("example.com")
        assert info.sha1 is None


class TestGetCnameInfo:
    """Tests for the async get_cname_info function."""

    async def test_cname_chain_returned(self, monkeypatch):
        """A CNAME response returns a non-empty chain."""
        import dns.resolver
        mock_resolver = MagicMock()

        class MockRdata:
            def __str__(self):
                return "alias.cdn.example.net."

        class MockAnswer:
            def __iter__(self):
                return iter([MockRdata()])

        mock_resolver.resolve = AsyncMock(return_value=MockAnswer())
        with patch("src.enricher.dns.asyncresolver.Resolver", return_value=mock_resolver):
            from src.enricher import get_cname_info
            info = await get_cname_info("example.com")
        assert len(info.chain) >= 1
        assert info.error is None

    async def test_nxdomain_returns_empty_chain(self, monkeypatch):
        """NXDOMAIN or NoAnswer results in empty chain without error."""
        import dns.resolver
        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer)
        with patch("src.enricher.dns.asyncresolver.Resolver", return_value=mock_resolver):
            from src.enricher import get_cname_info
            info = await get_cname_info("example.com")
        assert info.chain == []
        assert info.error is None


class TestGetCtInfo:
    """Tests for the async get_ct_info function."""

    async def test_valid_json_parsed(self, monkeypatch):
        """crt.sh JSON response produces a correct cert_count and earliest_date."""
        import src.http_client
        ct_json = b'[{"not_before": "2024-01-01"}, {"not_before": "2023-06-15"}]'
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch_bytes", AsyncMock(return_value=(200, ct_json)))
        from src.enricher import get_ct_info
        info = await get_ct_info("example.com")
        assert info.cert_count == 2
        assert info.earliest_date == "2023-06-15"
        assert info.error is None

    async def test_http_error_returns_zero_count(self, monkeypatch):
        """Non-200 HTTP response returns cert_count=0."""
        import src.http_client
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch_bytes", AsyncMock(return_value=(503, b"")))
        from src.enricher import get_ct_info
        info = await get_ct_info("example.com")
        assert info.cert_count == 0
        assert info.error is not None

    async def test_malformed_json_sets_error(self, monkeypatch):
        """Malformed JSON sets the error field and returns cert_count=0."""
        import src.http_client
        monkeypatch.setattr(src.http_client.HTTPClient, "fetch_bytes", AsyncMock(return_value=(200, b"not-json")))
        from src.enricher import get_ct_info
        info = await get_ct_info("example.com")
        assert info.cert_count == 0
        assert info.error is not None


class TestGetDnsInfoPtrRecords:
    """Tests for PTR record enrichment in get_dns_info."""

    async def test_ptr_records_populated(self, monkeypatch):
        """A successful PTR lookup populates ptr_records."""
        import dns.resolver

        async def fake_resolve(domain, rdtype):
            if rdtype == "A":
                return make_dns_answer(["1.2.3.4"])
            if rdtype == "PTR":
                return make_dns_answer(["mail.example.com."])
            raise dns.resolver.NoAnswer

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(side_effect=fake_resolve)
        with patch("src.enricher.dns.asyncresolver.Resolver", return_value=mock_resolver):
            info = await get_dns_info("example.com")
        assert len(info.ptr_records) >= 1

    async def test_ptr_lookup_failure_returns_empty_list(self, monkeypatch):
        """PTR lookup failure returns empty ptr_records without raising."""
        import dns.resolver

        async def fake_resolve(domain, rdtype):
            if rdtype == "A":
                return make_dns_answer(["1.2.3.4"])
            raise dns.resolver.NXDOMAIN

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(side_effect=fake_resolve)
        with patch("src.enricher.dns.asyncresolver.Resolver", return_value=mock_resolver):
            info = await get_dns_info("example.com")
        assert info.ptr_records == []
