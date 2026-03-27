"""Unit tests for src/http_client.py: FetchResult and HTTPClient."""

import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock

from src.http_client import FetchResult, HTTPClient


# ---------------------------------------------------------------------------
# FetchResult
# ---------------------------------------------------------------------------

class TestFetchResult:
    """Tests for the FetchResult dataclass."""

    def test_fields_stored_correctly(self):
        r = FetchResult(
            url="http://example.com",
            status=200,
            headers={"content-type": "text/html"},
            html="<html/>",
            history=[301],
            final_url="http://example.com/final",
            elapsed_ms=123.4,
        )
        assert r.url == "http://example.com"
        assert r.status == 200
        assert r.headers == {"content-type": "text/html"}
        assert r.html == "<html/>"
        assert r.history == [301]
        assert r.final_url == "http://example.com/final"
        assert r.elapsed_ms == 123.4

    def test_status_is_int(self):
        r = FetchResult(url="u", status=500, headers={}, html="", history=[], final_url="", elapsed_ms=0.0)
        assert isinstance(r.status, int)


# ---------------------------------------------------------------------------
# HTTPClient.normalize_host
# ---------------------------------------------------------------------------

class TestNormalizeHost:
    """Tests for HTTPClient.normalize_host static method."""

    @pytest.mark.parametrize("inp,expected", [
        ("example.com", "example.com"),
        ("https://Example.COM/path?q=1", "example.com"),
        ("*.example.com", "example.com"),
        ("example.com:8080", "example.com"),
        ("localhost", ""),
        ("", ""),
        ("   ", ""),
        ("exam ple.com", ""),
        ("EXAMPLE.COM", "example.com"),
        ("http://Sub.Example.COM/page", "sub.example.com"),
    ])
    def test_normalize(self, inp, expected):
        assert HTTPClient.normalize_host(inp) == expected

    def test_single_label_returns_empty(self):
        assert HTTPClient.normalize_host("nodot") == ""

    def test_url_with_port_stripped(self):
        assert HTTPClient.normalize_host("https://example.com:443/") == "example.com"


# ---------------------------------------------------------------------------
# HTTPClient.fetch
# ---------------------------------------------------------------------------

class TestHTTPClientFetch:
    """Tests for HTTPClient.fetch static method."""

    async def test_fetch_returns_fetch_result_on_200(self, monkeypatch):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = "<html>body</html>"
        mock_response.history = []
        mock_response.url = "http://example.com"

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.get = AsyncMock(return_value=mock_response)
        monkeypatch.setattr(HTTPClient, "CLIENT", mock_client)

        result = await HTTPClient.fetch("http://example.com")

        assert result.status == 200
        assert result.html == "<html>body</html>"
        assert result.headers.get("content-type") == "text/html"

    async def test_fetch_returns_500_on_network_error(self, monkeypatch):
        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        monkeypatch.setattr(HTTPClient, "CLIENT", mock_client)

        result = await HTTPClient.fetch("http://example.com")

        assert result.status == 500
        assert result.html == ""
        assert result.history == []

    async def test_fetch_captures_redirect_history(self, monkeypatch):
        r1 = MagicMock()
        r1.status_code = 301
        r2 = MagicMock()
        r2.status_code = 302

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = ""
        mock_response.history = [r1, r2]
        mock_response.url = "http://final.com"

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.get = AsyncMock(return_value=mock_response)
        monkeypatch.setattr(HTTPClient, "CLIENT", mock_client)

        result = await HTTPClient.fetch("http://example.com")

        assert result.history == [301, 302]

    async def test_fetch_headers_lowercased(self, monkeypatch):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"X-Custom-Header": "value", "Content-Type": "text/html"}
        mock_response.text = ""
        mock_response.history = []
        mock_response.url = "http://example.com"

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.get = AsyncMock(return_value=mock_response)
        monkeypatch.setattr(HTTPClient, "CLIENT", mock_client)

        result = await HTTPClient.fetch("http://example.com")

        assert "content-type" in result.headers
        assert "x-custom-header" in result.headers

    async def test_fetch_sets_final_url(self, monkeypatch):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = ""
        mock_response.history = []
        mock_response.url = "http://final.example.com/page"

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.get = AsyncMock(return_value=mock_response)
        monkeypatch.setattr(HTTPClient, "CLIENT", mock_client)

        result = await HTTPClient.fetch("http://example.com")

        assert result.final_url == "http://final.example.com/page"
