"""Shared pipeline primitives: channels, Redis/HTTP clients, and Module base class."""

from enum import Enum
from typing import Awaitable, Callable, Optional

import httpx
from typing import Optional
from .config import Config
import redis.asyncio as redis


class Channel(Enum):
    """Pipeline stages"""
    # Inputs
    INCOMING = "incoming"
    # Processing
    PROCESS = "process"
    # Outputs
    SCAM = "result.scam"
    INCONCLUSIVE = "result.inconclusive"
    BENIGN = "result.benign"

class RedisClient:
    """Singleton async Redis client accessor using a Config object.

    Usage:
        RedisClient.configure(config)  # provide a Config instance before first use
        r = RedisClient.get_redis()
        await RedisClient.close_redis()
    """
        
    _client: Optional[redis.Redis] = None
    _config: "Config" = Config.load()

    @staticmethod
    def get() -> redis.Redis:
        """Return a shared async Redis client configured from the Config instance.

        Raises:
            RuntimeError: If RedisClient.configure(...) was not called with a Config.
        """
        # Default Parameters
        if not RedisClient._client:
            RedisClient._client = redis.Redis(
                host="localhost",
                port=6379,
                db=0,
                decode_responses=False
            )
        return RedisClient._client

    @staticmethod
    async def close() -> None:
        """Close the shared Redis client, if open."""
        if not RedisClient._client:
            return
        try:
            await RedisClient._client.aclose()
        finally:
            RedisClient._client = None


class HTTPClient:
    """Singleton async HTTP client accessor.

    Usage:
        client = HTTPClient.get_http_client()
        await HTTPClient.close_http_client()
    """

    _http_client: Optional[httpx.AsyncClient] = None

    @staticmethod
    def get() -> httpx.AsyncClient:
        """Return a shared async HTTP client.

        Returns:
            httpx.AsyncClient: Reused HTTP client with connection pooling.
        """
        # Default Parameters
        if not HTTPClient._http_client:
            HTTPClient._http_client = httpx.AsyncClient(
                http2=True,
                timeout=httpx.Timeout(5.0, connect=3.0, read=5.0),
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
                follow_redirects=True,
            )
        return HTTPClient._http_client

    @staticmethod
    async def close() -> None:
        """Close the shared async HTTP client, if open."""
        if not HTTPClient._http_client:
            return
        try:
            await HTTPClient._http_client.aclose()
        finally:
            HTTPClient._http_client = None

class RedisModule:
    """Base class for pipeline modules with Redis pub/sub helpers."""

    def __init__(self, listening_channel: Optional[Channel] = None) -> None:
        """Initialize a module with an optional listening channel.

        Args:
            listening_channel: Channel to subscribe to for incoming domains.
        """
        self.listening_channel = listening_channel

    async def start(self) -> None:
        """Start the module.

        Subclasses must implement this to set up subscriptions or kick off work.
        """
        raise NotImplementedError

    async def subscribe(self, fn: Callable[[str], Awaitable[None]]) -> None:
        """Subscribe to the module's listening channel and invoke act_fn for messages.

        Args:
            fn: Async function called with each domain string from Redis.

        Raises:
            ValueError: If no listening channel is configured.
        """
        r: redis.Redis = RedisClient.get()
        pubsub: redis.client.PubSub = r.pubsub()
        await pubsub.subscribe(self.listening_channel.value)
        try:
            async for msg in pubsub.listen():
                if msg.get("type") != "message":
                    continue
                data: Optional[bytes] = msg.get("data")
                domain: str = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else str(data)
                await fn(domain)
        finally:
            try:
                await pubsub.unsubscribe(self.listening_channel.value)
            finally:
                await pubsub.close()

    async def publish(self, target_channel: Channel, domain: str) -> None:
        """Publish a domain to a target pipeline channel.

        Args:
            target_channel: Channel to publish to.
            domain: Domain string payload.
        """
        r: redis.Redis = RedisClient.get()
        await r.publish(target_channel.value, domain)