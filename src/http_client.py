"""Shared HTTP client singleton and FetchResult dataclass.

All network fetches in the pipeline go through ``HTTPClient`` so the
connection pool is reused across the full run.  The single ``CLIENT``
instance is closed once at application shutdown by ``main.py``.

Typical usage::

    from .http_client import FetchResult, HTTPClient

    result: FetchResult = await HTTPClient.fetch("https://example.com")
"""

from dataclasses import dataclass
import re
import time
from typing import Optional

import httpx


@dataclass
class FetchResult:
    """Snapshot of a single HTTP response.

    Attributes:
        url: The originally requested URL.
        status: HTTP response status code (500 on network error).
        headers: Response headers with lowercase keys.
        html: Decoded response body text.
        history: Ordered list of redirect status codes leading to the final response.
        final_url: The URL of the final response after all redirects.
        elapsed_ms: Total round-trip time in milliseconds.
    """

    url: str
    status: int
    headers: dict[str, str]
    html: str
    history: list[int]
    final_url: str
    elapsed_ms: float


class HTTPClient:
    """Singleton accessor for the shared async HTTP client.

    All network fetches go through this class so the connection pool is reused
    across the pipeline.  The single ``CLIENT`` instance is closed once at
    application shutdown by ``main.py``.

    Attributes:
        CLIENT: The shared ``httpx.AsyncClient`` with HTTP/2 enabled.
        DOMAIN_RE: Compiled regex used by ``normalize_host`` to validate hostnames.
    """

    CLIENT: httpx.AsyncClient = httpx.AsyncClient(
        http2=True,
        timeout=httpx.Timeout(5.0, connect=3.0, read=5.0),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        follow_redirects=True,
    )

    DOMAIN_RE = re.compile(r"^(?:\*\.)?([a-z0-9.-]+)$", re.IGNORECASE)

    @staticmethod
    def get() -> httpx.AsyncClient:
        """Return the shared HTTP client after verifying it is open.

        Returns:
            The live ``httpx.AsyncClient`` instance.

        Raises:
            ConnectionError: If the client has already been closed.
        """
        if HTTPClient.CLIENT.is_closed:
            raise ConnectionError("HTTP client is not connected")
        return HTTPClient.CLIENT

    @staticmethod
    async def close() -> None:
        """Close the shared HTTP client and release all connections."""
        await HTTPClient.CLIENT.aclose()

    @staticmethod
    async def fetch(url: str, headers: dict[str, str] = {}, timeout: int = 20) -> FetchResult:
        """Perform an HTTP GET request and return a normalised ``FetchResult``.

        On any network or protocol error a synthetic ``FetchResult`` with
        ``status=500`` and empty body fields is returned so callers never
        need to handle exceptions.

        Args:
            url: The URL to fetch.
            headers: Additional request headers (e.g. ``User-Agent``).
            timeout: Per-request timeout in seconds.

        Returns:
            A ``FetchResult`` populated from the HTTP response, or a stub
            ``FetchResult`` with ``status=500`` on failure.
        """
        t0: float = time.time()
        client: httpx.AsyncClient = HTTPClient.get()
        try:
            resp = await client.get(url, headers=headers, timeout=timeout, follow_redirects=True)
            return FetchResult(
                url=url,
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                html=resp.text,
                history=[h.status_code for h in getattr(resp, "history", [])],
                final_url=str(resp.url),
                elapsed_ms=round((time.time() - t0) * 1000, 1),
            )
        except Exception:
            return FetchResult(
                url=url,
                status=500,
                headers={},
                html="",
                history=[],
                final_url="",
                elapsed_ms=round((time.time() - t0) * 1000, 1),
            )

    @staticmethod
    async def fetch_bytes(url: str, timeout: int = 10) -> tuple[int, bytes]:
        """Perform an HTTP GET request and return the raw response bytes.

        Used when binary content (e.g. favicon images) must be processed
        without text decoding.  On any network or protocol error, returns
        ``(500, b"")``.

        Args:
            url: The URL to fetch.
            timeout: Per-request timeout in seconds.

        Returns:
            A ``(status_code, content)`` tuple.  ``status_code`` is 500 and
            ``content`` is ``b""`` on failure.
        """
        client: httpx.AsyncClient = HTTPClient.get()
        try:
            resp = await client.get(url, timeout=timeout, follow_redirects=True)
            return resp.status_code, resp.content
        except Exception:
            return 500, b""

    @staticmethod
    def normalize_host(s: str) -> str:
        """Return a canonical lowercase hostname from any reasonable input form.

        Handles bare hostnames, wildcard prefixes (``*.example.com``), full
        URLs (``https://example.com/path``), and host:port pairs
        (``example.com:8080``).  Returns an empty string for inputs that are
        empty, lack a dot, or fail the domain regex check.

        Args:
            s: Raw input string — URL, hostname, or wildcard domain.

        Returns:
            A lowercase, stripped hostname, or ``""`` for invalid input.
        """
        if not s:
            return ""
        s = s.strip().lower()
        if s.startswith("*."):
            s = s[2:]
        if "://" in s:
            try:
                s = s.split("://", 1)[1].split("/", 1)[0]
            except Exception:
                pass
        if ":" in s:
            s = s.split(":", 1)[0]
        if not s or "." not in s:
            return ""
        if not HTTPClient.DOMAIN_RE.match(s):
            return ""
        return s
