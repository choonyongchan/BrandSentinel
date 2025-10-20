"""Shared pipeline primitives: channels, Redis/HTTP clients, and Module base class."""

from dataclasses import dataclass
from enum import Enum
import time
from typing import AsyncGenerator, Optional

import httpx
import re
import redis.asyncio as redis

class Channel(Enum):    
    """Pipeline stages"""
    # Filter
    FILTER = "filter"
    # Processing
    PROCESS = "process"
    # Results
    SCAM = "scam"
    INCONCLUSIVE = "inconclusive"
    BENIGN = "benign"
    IRRELEVANT = "irrelevant"

class RedisClient:
    """Singleton async Redis client accessor"""
        
    CLIENT: redis.Redis = redis.Redis(
        host="localhost",
        port=6379,
        db=0,
        decode_responses=False
    )
    
    @staticmethod
    async def get() -> redis.Redis:
        """Return a shared async Redis client"""
        if not await RedisClient.CLIENT.ping():
            raise ConnectionError("Redis client is not connected")
        return RedisClient.CLIENT

    @staticmethod
    async def close() -> None:
        """Close the shared Redis client, if open."""
        await RedisClient.CLIENT.aclose()

    @staticmethod
    async def subscribe(listening_channel: Channel) -> AsyncGenerator[str, None]:
        """Subscribe to the module's listening channel and invoke act_fn for messages.

        Args:
            fn: Async function called with each domain string from Redis.

        Raises:
            ValueError: If no listening channel is configured.
        """
        if not listening_channel:
            raise ValueError("No listening channel configured for this module.")

        r: redis.Redis = await RedisClient.get()
        pubsub: redis.client.PubSub = r.pubsub()
        channel_name: str = listening_channel.value
        await pubsub.subscribe(channel_name)
        async for msg in pubsub.listen(): # Infinite Loop
            if msg.get("type") != "message":
                continue
            data: Optional[bytes] = msg.get("data")
            domain: str = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else str(data)
            yield domain
        await pubsub.close() # Defensive Coding

    @staticmethod
    async def publish(target_channel: Channel, domain: str) -> None:
        """Publish a domain to a target pipeline channel.

        Args:
            target_channel: Channel to publish to.
            domain: Domain string payload.
        """
        if not target_channel:
            raise ValueError("No target channel specified for publish.")
        if not domain:
            raise ValueError("No domain specified for publish.")

        r: redis.Redis = await RedisClient.get()
        channel_name: str = target_channel.value
        await r.publish(channel_name, domain)

@dataclass
class FetchResult:
    """HTTP fetch result for a given URL."""
    url: str
    status: int
    headers: dict[str, str]
    html: str
    history: list[int]
    final_url: str
    elapsed_ms: float

class HTTPClient:
    """Singleton async HTTP client accessor."""

    CLIENT: httpx.AsyncClient = httpx.AsyncClient(
        http2=True,
        timeout=httpx.Timeout(5.0, connect=3.0, read=5.0),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        follow_redirects=True
    )

    @staticmethod
    def get() -> httpx.AsyncClient:
        """Return a shared async HTTP client."""
        if HTTPClient.CLIENT.is_closed:
            raise ConnectionError("HTTP client is not connected")
        return HTTPClient.CLIENT

    @staticmethod
    async def close() -> None:
        """Close the shared async HTTP client, if open."""
        await HTTPClient.CLIENT.aclose()

    @staticmethod
    async def fetch(url: str, headers: dict[str, str] = {}, timeout: int = 20) -> FetchResult:
        t0: float = time.time()
        client: httpx.AsyncClient = HTTPClient.get()
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


    # Streaming sources can override run() instead of poll().
    DOMAIN_RE = re.compile(r"^(?:\*\.)?([a-z0-9.-]+)$", re.IGNORECASE)

    @staticmethod
    def normalize_host(s: str) -> str:
        """
        Accepts a bare domain/hostname, a wildcard-prefixed host ("*.example.com"),
        a full URL ("https://example.com/path"), or a host:port pair ("example.com:8080").
        Returns a canonical, lowercase hostname with any leading wildcard, URL scheme/path,
        and port removed. If the input is empty, does not contain a dot, or fails the
        module's domain regex check, returns None.
        """
        if not s:
            return ""
        s = s.strip().lower()
        if s.startswith("*."):
            s = s[2:]
        # Basic host extraction from URL
        if "://" in s:
            try:
                s = s.split("://", 1)[1].split("/", 1)[0]
            except Exception:
                pass
        # Strip port
        if ":" in s:
            s = s.split(":", 1)[0]
        if not s or "." not in s:
            return ""
        if not HTTPClient.DOMAIN_RE.match(s):
            return ""
        return s