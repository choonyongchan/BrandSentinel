"""Domain ingester that seeds the pipeline from open threat intel sources."""
import asyncio
import re
import time
from typing import Iterable, Optional, Set
from unittest import result
from urllib.parse import urlparse

from h11 import Response
import tldextract

from .commons import Channel, HTTPClient, RedisModule
from .config import Config


class DomainIngester(RedisModule):
    """Ingester that continuously polls multiple sources and publishes domains."""

    def __init__(self) -> None:
        """Initialize the ingester and configuration."""
        super().__init__()
        self.cfg: Config = Config.load()
        self.client: HTTPClient = HTTPClient.get()

        # API keys
        self.OTX_API_KEY: str = self.cfg.ingester.api_keys.otx
        self.URLSCAN_API_KEY: str = self.cfg.ingester.api_keys.urlscan

        # Enable/disable sources from YAML
        en: Config.Ingester.Enable = self.cfg.ingester.enable
        self.ENABLE_CRTSH: bool = en.crtsh
        self.ENABLE_URLHAUS: bool = en.urlhaus
        self.ENABLE_OPENPHISH: bool = en.openphish
        self.ENABLE_URLSCAN: bool = en.urlscan and bool(self.URLSCAN_API_KEY)
        self.ENABLE_PHISHSTATS: bool = en.phishstats
        self.ENABLE_THREATFOX: bool = en.threatfox
        self.ENABLE_OTX: bool = en.otx and bool(self.OTX_API_KEY)

        # Intervals
        iv: Config.Ingester.Intervals = self.cfg.ingester.intervals
        self.INTERVAL_CRTSH: int = iv.crtsh
        self.INTERVAL_URLHAUS: int = iv.urlhaus
        self.INTERVAL_OPENPHISH: int = iv.openphish
        self.INTERVAL_URLSCAN: int = iv.urlscan
        self.INTERVAL_PHISHSTATS: int = iv.phishstats
        self.INTERVAL_THREATFOX: int = iv.threatfox
        self.INTERVAL_OTX: int = iv.otx

        # Dedup
        self._seen_regs: Set[str] = set()
        self._lock: asyncio.Lock = asyncio.Lock()

        # State
        self._crtsh_last_id: int = 0
        self._phishstats_last_id: int = 0
        self._threatfox_last_id: int = 0

        # Blacklisted Words (for CRT SH filtering)
        self._blacklist_keywords: list[str] = self.cfg.processor.blacklist_keywords or []

        # Target channel
        self.target_channel: Channel = Channel.PROCESS

    async def start(self) -> None:
        """Start polling all enabled sources."""
        tasks: list[asyncio.Task] = []
        if self.ENABLE_CRTSH:
            tasks.append(asyncio.create_task(self._run_forever(self._poll_crtsh, self.INTERVAL_CRTSH, "crt.sh")))
        if self.ENABLE_URLHAUS:
            tasks.append(asyncio.create_task(self._run_forever(self._poll_urlhaus, self.INTERVAL_URLHAUS, "urlhaus")))
        if self.ENABLE_OPENPHISH:
            tasks.append(asyncio.create_task(self._run_forever(self._poll_openphish, self.INTERVAL_OPENPHISH, "openphish")))
        if self.ENABLE_URLSCAN:
            tasks.append(asyncio.create_task(self._run_forever(self._poll_urlscan, self.INTERVAL_URLSCAN, "urlscan")))
        if self.ENABLE_PHISHSTATS:
            tasks.append(asyncio.create_task(self._run_forever(self._poll_phishstats, self.INTERVAL_PHISHSTATS, "phishstats")))
        if self.ENABLE_THREATFOX:
            tasks.append(asyncio.create_task(self._run_forever(self._poll_threatfox, self.INTERVAL_THREATFOX, "threatfox")))
        if self.ENABLE_OTX:
            tasks.append(asyncio.create_task(self._run_forever(self._poll_otx, self.INTERVAL_OTX, "otx")))

        if not tasks:
            print("Ingester: no sources enabled.")
            return

        print(f"Ingester started with {len(tasks)} source(s).")
        await asyncio.gather(*tasks)


    async def _run_forever(self, fn, interval: int, name: str) -> None:
        """Run the given async function in a loop with the specified interval."""
        while True:
            t0: float = time.time()
            try:
                await fn()
            except Exception as e:
                print(f"[{name}] error: {e}")
            await asyncio.sleep(max(1, interval - int(time.time() - t0)))

    def _is_whitelisted(self, host: str) -> bool:
        """Check if the host matches any configured whitelist keywords."""
        wl: list[str] = self.cfg.processor.whitelist_keywords or []
        host_l: str = host.lower()
        return any(k for k in wl if k and k.lower() in host_l)

    async def _publish_domains(self, domains: Iterable[str], source: str) -> None:
        """Publish unique registrable domains, dropping whitelisted ones early."""
        new_count: int = 0
        async with self._lock:
            for d in domains:
                host: Optional[str] = DomainIngester.extract_host(d)
                if not host or self._is_whitelisted(host):
                    continue
                reg: str = DomainIngester.registrable(host)
                if reg not in self._seen_regs:
                    self._seen_regs.add(reg)
                    await self.publish(self.target_channel, reg)
                    new_count += 1
        if new_count:
            print(f"[{source}] published {new_count} new domains")

    # ---- Helpers ----
    @staticmethod
    def extract_host(s: str) -> Optional[str]:
        """Extract the hostname from a URL or domain string.

        This function accepts a URL or bare domain string and returns a cleaned,
        lowercased hostname without trailing dots. If the input has no scheme,
        "http://" will be prefixed before parsing. Hostnames that contain
        characters outside of [a-z0-9.-] or empty/invalid inputs will result in None.

        Args:
            s (str): The URL or domain string to extract the hostname from.

        Returns:
            Optional[str]: The extracted hostname in lowercase with trailing dots removed,
            or None if the input is empty, invalid, or could not be parsed.
        """
        if not s:
            raise ValueError("Input string is empty")
        s = s.strip()
        if "://" not in s:
            s = f"http://{s}"
        host: str = (urlparse(s).hostname or "").strip(".").lower()
        if host and re.match(r"^[a-z0-9.-]+$", host):
            return host
        return None

    @staticmethod
    def registrable(host: str) -> str:
        """Return the registrable eTLD+1 for deduplication.

        Extracts the effective top-level domain plus one label (eTLD+1) from the given host
        using tldextract. This is useful for normalizing and deduplicating hosts that share
        the same registrable domain.

        Args:
            host (str): The hostname to extract the registrable domain from.

        Returns:
            str: The registrable eTLD+1 (for example, "example.co.uk"). If extraction yields no
            domain/suffix, returns the original host.
        """
        ext: tldextract.ExtractResult = tldextract.extract(host)
        return ".".join(p for p in (ext.domain, ext.suffix) if p) or host
    
    @staticmethod
    def dedup_wildcards(words: list[str]) -> list[str]:
        """Keep only minimal strings: if a is substring of b, drop b.

        Deduplicates input and processes words shortest-first so that any longer
        word containing an already-kept shorter word is skipped.
        """
        uniq = sorted(words, key=len)  # drop empties, dedup, shortest first
        kept: list[str] = []
        for w in uniq:
            # If any already-kept (shorter) word is inside w, w would be removed -> skip it
            if any(k in w for k in kept):
                continue
            kept.append(w)
        return kept

    # ---- Source pollers (kept simple) ----

    async def _poll_crtsh(self) -> None:
        blacklist: list[str] = self.dedup_wildcards(self._blacklist_keywords)
        for kw in blacklist:
            # Get all domains with the keyword in the subdomain
            url: str = f"https://crt.sh/?q=%25{kw}%25.%25&output=json"
            r: Response = await self.client.get(url, timeout=300) # It is a big file
            if r.status_code != 200:
                continue
            try:
                data: list[dict] = r.json()
            except Exception:
                continue
            max_id: int = self._crtsh_last_id
            domains: Set[str] = set()
            for row in data:
                cid: int = row.get("id", 0)
                if cid <= self._crtsh_last_id:
                    continue # ID is sorted descending
                name_value: str = row.get("name_value", "").lower()
                for name in name_value.splitlines():
                    if name and "*" not in name:
                        host: Optional[str] = DomainIngester.extract_host(name)
                        if host:
                            domains.add(host)
                max_id = max(max_id, cid)
            if domains:
                await self._publish_domains(domains, "crt.sh")
                self._crtsh_last_id = max_id

    async def _poll_urlhaus(self) -> None:
        url: str = "https://urlhaus.abuse.ch/downloads/text_online/"
        r = await self.client.get(url, timeout=20)
        if r.status_code != 200:
            return
        data: str = r.text or ""
        urls: list[str] = [l.strip() for l in data.splitlines()]
        hosts: list[str] = [DomainIngester.extract_host(u) for u in urls]
        await self._publish_domains([h for h in hosts if h], "urlhaus")

    async def _poll_openphish(self) -> None:
        # Once every 12 hours.
        url: str = "https://openphish.com/feed.txt"
        r = await self.client.get(url, timeout=20)
        if r.status_code != 200:
            return
        data: str = r.text or ""
        urls: list[str] = [l.strip() for l in data.splitlines()]
        hosts: list[str] = [DomainIngester.extract_host(u) for u in urls]
        await self._publish_domains([h for h in hosts if h], "openphish")

    async def _poll_urlscan(self) -> None:
        # NEED API KEY. UNTESTED.
        url: str = "https://urlscan.io/api/v1/search/?q=page.domain.keyword:*&size=100&sort=desc"
        headers: dict[str, str] = {"API-Key": self.URLSCAN_API_KEY}
        r = await self.client.get(url, headers=headers, timeout=20)
        if r.status_code != 200:
            return
        data = r.json()
        domains: Set[str] = set()
        for res in data.get("results", []):
            page = res.get("page") or {}
            d = page.get("domain") or page.get("apexDomain")
            if d:
                domains.add(DomainIngester.extract_host(d))
        await self._publish_domains(domains, "urlscan")

    async def _poll_phishstats(self) -> None:
        url = "https://api.phishstats.info/api/phishing?_sort=-date"
        r = await self.client.get(url, timeout=20)
        if r.status_code != 200:
            return
        try:
            data = r.json()
        except Exception:
            return
        max_id: int = self._phishstats_last_id
        domains: Set[str] = set()
        for row in data:
            cid: int = row.get("id", 0)
            if cid <= self._phishstats_last_id:
                break # ID is sorted descending
            url = row.get("url", "").lower()
            domains.add(DomainIngester.extract_host(url))
            max_id = max(max_id, cid)
        if domains:
            await self._publish_domains(domains, "phishstats")
            self._phishstats_last_id = max_id

    async def _poll_threatfox(self) -> None:
        url = "https://threatfox.abuse.ch/export/json/domains/recent/"
        r = await self.client.post(url, timeout=20)
        if r.status_code != 200:
            return
        try:
            data = r.json()
        except Exception:
            return
        max_id: int = self._threatfox_last_id
        domains: Set[str] = set()
        for cid, item in data.items():
            url = item[0].get("ioc_value", "").lower()
            domains.add(DomainIngester.extract_host(url))
            max_id = max(max_id, int(cid))
        if domains:
            await self._publish_domains(domains, "threatfox")
            self._threatfox_last_id = max_id

    async def _poll_otx(self) -> None:
        # UNTESTED.
        headers = {"X-OTX-API-KEY": self.OTX_API_KEY}
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed?page=1"
        r = await self.client.get(url, headers=headers, timeout=20)
        if r.status_code != 200:
            return
        data = r.json()
        domains: Set[str] = set()
        for p in data.get("results", []) or []:
            for ind in p.get("indicators", []) or []:
                if ind.get("type", "").lower() in ("domain", "hostname", "url"):
                    h = DomainIngester.extract_host(ind.get("indicator") or "")
                    if h:
                        domains.add(h)
        await self._publish_domains(domains, "otx")