"""Refactored Ingester: Source handles processing; Ingester only enables sources and provides client/config."""
import threading
from .commons import Channel, FetchResult, HTTPClient, RedisClient
from .config import CONFIG
from typing import Iterable, Optional, Set, List, Dict, Any, cast

import asyncio
import certstream
import json
import os

# ---- Base Source ----

class Source:
    key: str  # enable flag key in YAML

    # Global dedup across all sources
    VISITED_DOMAINS: Set[str] = set()
    TARGET_CHANNEL: Channel = Channel.FILTER

    def __init__(self, interval_s: int = 300) -> None:
        self.interval_s: int = interval_s

    async def start(self) -> Optional[asyncio.Task[Any]]:
        return asyncio.create_task(self.search(), name=f"src:{self.key}")

    async def search(self) -> None:
        while True:
            try:
                domains: Iterable[str] = await self.get()
                await self.publish(domains)
            finally:
                await asyncio.sleep(self.interval_s)

    async def get(self) -> Iterable[str]:
        # To be implemented by periodic sources
        raise NotImplementedError()

    @staticmethod
    async def publish(domains: Iterable[str]) -> None:
        for d in domains:
            if (not d) or (d in Source.VISITED_DOMAINS):
                continue
            Source.VISITED_DOMAINS.add(d)
            await RedisClient.publish(Source.TARGET_CHANNEL, d)


# ---- Concrete Sources ---

class OpenPhish(Source):
    key = "openphish"

    def __init__(self, interval_s: int = 43200) -> None:
        # Free feed refresh ~12h; verified feed requires subscription.
        super().__init__(interval_s)
        self.feed_url: str = "https://openphish.com/feed.txt"

    async def get(self) -> Iterable[str]:
        fetchresult: FetchResult = await HTTPClient.fetch(self.feed_url)
        txt = fetchresult.html
        if not txt:
            return []
        hosts: Set[str] = set()
        for line in txt.splitlines():
            h = HTTPClient.normalize_host(line)
            if h:
                hosts.add(h)
        return hosts


class PhishTank(Source):
    key = "phishtank"

    def __init__(self, interval_s: int = 3600, api_key: Optional[str] = None) -> None:
        super().__init__(interval_s)
        # Public JSON feed
        self.feed_url = (f"http://data.phishtank.com/data/{api_key}/online-valid.json" 
                         if api_key 
                         else "http://data.phishtank.com/data/online-valid.json")

    async def get(self) -> Iterable[str]:
        fetchresult: FetchResult = await HTTPClient.fetch(self.feed_url)
        txt = fetchresult.html
        if not txt:
            return []
        try:
            data_any: Any = json.loads(txt)
        except Exception:
            return []
        hosts: Set[str] = set()
        if isinstance(data_any, list):
            items: List[Dict[str, Any]] = cast(List[Dict[str, Any]], data_any)
            for item in items:
                u = item.get("url")
                if not u:
                    continue
                h = HTTPClient.normalize_host(str(u))
                if h:
                    hosts.add(h)
        return hosts


class URLhaus(Source):
    key = "urlhaus"

    def __init__(self, interval_s: int = 300) -> None:
        super().__init__(interval_s)
        self.feed_url = "https://urlhaus.abuse.ch/downloads/text_online/"

    async def get(self) -> Iterable[str]:
        fetchresult: FetchResult = await HTTPClient.fetch(self.feed_url)
        txt = fetchresult.html
        if not txt:
            return []
        hosts: Set[str] = set()
        for line in txt.splitlines():
            if not line or line.startswith("#"):
                continue
            h = HTTPClient.normalize_host(line)
            if h:
                hosts.add(h)
        return hosts

class CertStream(Source):
    key = "certstream"

    def __init__(self, interval_s: int = 5) -> None:
        super().__init__(interval_s)
        self._buffer: Set[str] = set()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._start_listener_thread()

    def _start_listener_thread(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        def target() -> None:
            try:
                certstream.listen_for_events(self._cert_callback, url="wss://certstream.calidog.io/")
            except Exception:
                # listener thread should not crash the whole process; just exit the thread
                return

        self._thread = threading.Thread(target=target, daemon=True)
        self._thread.start()

    def _cert_callback(self, message: Any, _context: Any) -> None:
        """Synchronous callback executed in the certstream listener thread.
        Collect normalized domains into an in-memory buffer protected by a lock.
        """
        try:
            if not isinstance(message, dict) or message.get("message_type") != "certificate_update":
                return

            data = message.get("data", {})
            if not isinstance(data, dict):
                return

            leaf_cert = data.get("leaf_cert", {})
            if not isinstance(leaf_cert, dict):
                return

            all_domains = leaf_cert.get("all_domains", [])
            if not isinstance(all_domains, list):
                return

            hosts = [HTTPClient.normalize_host(str(d)) for d in all_domains if isinstance(d, str)]
            if not hosts:
                return

            with self._lock:
                self._buffer.update(hosts)

        except Exception:
            # swallow exceptions in thread callback to keep listener running
            return

    async def get(self) -> Iterable[str]:
        """Return and purge buffered domains collected by the listener thread."""
        with self._lock:
            if not self._buffer:
                return []
            items = set(self._buffer)
            self._buffer.clear()
        return items

class ManualImport(Source):
    key = "manual"

    def __init__(self, interval_s: int = 30) -> None:
        # Poll a local file for new domains
        super().__init__(interval_s)
        self.path = "data/manual_domains.txt"
        self.seen_domains: Set[str] = set()

    async def get(self) -> Iterable[str]:
        try:
            if not os.path.exists(self.path):
                return []
            hosts: Set[str] = set()
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    h = HTTPClient.normalize_host(line)
                    if h and h not in self.seen_domains:
                        hosts.add(h)
            self.seen_domains.update(hosts)
            return hosts
        except Exception:
            return []

# ---- Orchestrator ----

class Ingester:
    """Orchestrates all sources and publishes to Redis via Source helpers."""

    AVAILABLE_SOURCES: list[Source] = [OpenPhish(), PhishTank(), URLhaus(), CertStream(), ManualImport()]
    ENABLED_SOURCES: list[Source] = [
            src 
            for src in AVAILABLE_SOURCES
            if bool(getattr(CONFIG.ingester.enable, src.key, False))
        ]
    
    @staticmethod
    async def start() -> None:
        await asyncio.gather(*(src.start() for src in Ingester.ENABLED_SOURCES))