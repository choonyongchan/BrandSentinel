"""Ingestion sources: push domains from threat-intelligence feeds and CT logs into a queue.

Each ``Source`` subclass implements ``async def run(queue)`` — an infinite-loop
coroutine that pushes normalised hostname strings into a shared ``asyncio.Queue``
whenever new data is available.

HTTP sources (``OpenPhish``, ``PhishTank``, ``URLhaus``) fetch once per
``interval_s`` seconds using ``asyncio.sleep``.  ``CertStream`` pushes domains
from its daemon thread via ``loop.call_soon_threadsafe``.  ``ManualImport``
polls a local file using ``asyncio.sleep``.

Deduplication happens at the push site: ``Ingester.enqueue`` only enqueues a
domain if it is not already in ``Source.VISITED_DOMAINS``.

``Ingester.enabled_sources`` returns the subset of ``AVAILABLE_SOURCES`` whose
config enable flag is ``True``.
"""

import asyncio
import csv
import io
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional, Set, cast

import certstream

from .config import CONFIG
from .http_client import FetchResult, HTTPClient


# ---- Base Source ----

class Source:
    """Base class for all threat-intelligence ingestion sources.

    Subclasses set ``key`` to the YAML enable-flag name and implement
    ``run(queue)`` — an infinite-loop coroutine that pushes domains into the
    shared queue.

    Attributes:
        key: Enable-flag key in ``config.yaml`` under ``ingester.enable``.
        VISITED_DOMAINS: Global set of domain strings already published in
            this process run.  Shared across all source instances to prevent
            duplicate processing.
        interval_s: Seconds to sleep between successive fetch/poll cycles.
    """

    key: str

    VISITED_DOMAINS: Set[str] = set()

    def __init__(self, interval_s: int = 300) -> None:
        """Initialise the source with a poll interval.

        Args:
            interval_s: Seconds to sleep between poll cycles.
        """
        self.interval_s: int = interval_s


# ---- Concrete Sources ----

class OpenPhish(Source):
    """OpenPhish free-tier text feed: one URL per line.

    Attributes:
        key: YAML enable flag ``"openphish"``.
        feed_url: OpenPhish plaintext feed endpoint.
    """

    key = "openphish"

    def __init__(self, interval_s: int = 43200) -> None:
        """Initialise with a 12-hour poll interval (free feed refresh rate).

        Args:
            interval_s: Poll interval in seconds.
        """
        super().__init__(interval_s)
        self.feed_url: str = "https://openphish.com/feed.txt"

    async def run(self, queue: "asyncio.Queue[str]") -> None:
        """Fetch the OpenPhish feed in a loop, pushing new hostnames into the queue.

        Fetches the feed once per ``interval_s`` seconds.  Each normalised
        hostname is passed to ``Ingester.enqueue`` for dedup-checked insertion.

        Args:
            queue: Shared domain queue to push into.
        """
        while True:
            fetchresult: FetchResult = await HTTPClient.fetch(self.feed_url)
            txt = fetchresult.html
            if txt:
                hosts: Set[str] = set()
                for line in txt.splitlines():
                    h = HTTPClient.normalize_host(line)
                    if h:
                        hosts.add(h)
                for host in hosts:
                    Ingester.enqueue(host, queue, self.key)
            await asyncio.sleep(self.interval_s)


class PhishTank(Source):
    """PhishTank JSON feed: one object per verified phishing URL.

    Attributes:
        key: YAML enable flag ``"phishtank"``.
        feed_url: PhishTank JSON feed endpoint (public or API-key variant).
    """

    key = "phishtank"

    def __init__(self, interval_s: int = 3600, api_key: Optional[str] = None) -> None:
        """Initialise with a 1-hour interval and optional API key.

        Args:
            interval_s: Poll interval in seconds.
            api_key: Optional PhishTank API key for the authenticated feed URL.
        """
        super().__init__(interval_s)
        self.feed_url = (
            f"http://data.phishtank.com/data/{api_key}/online-valid.json"
            if api_key
            else "http://data.phishtank.com/data/online-valid.json"
        )

    async def run(self, queue: "asyncio.Queue[str]") -> None:
        """Fetch the PhishTank JSON feed in a loop, pushing new hostnames into the queue.

        Fetches once per ``interval_s`` seconds.  Parses the JSON ``url`` field
        from each entry and passes normalised hostnames to ``Ingester.enqueue``.

        Args:
            queue: Shared domain queue to push into.
        """
        while True:
            fetchresult: FetchResult = await HTTPClient.fetch(self.feed_url)
            txt = fetchresult.html
            if txt:
                hosts: Set[str] = set()
                try:
                    data_any: Any = json.loads(txt)
                except Exception:
                    data_any = None
                if isinstance(data_any, list):
                    items: List[Dict[str, Any]] = cast(List[Dict[str, Any]], data_any)
                    for item in items:
                        u = item.get("url")
                        if not u:
                            continue
                        h = HTTPClient.normalize_host(str(u))
                        if h:
                            hosts.add(h)
                    for host in hosts:
                        Ingester.enqueue(host, queue, self.key)
            await asyncio.sleep(self.interval_s)


class URLhaus(Source):
    """URLhaus text feed: one URL per line, comment lines prefixed with ``#``.

    Attributes:
        key: YAML enable flag ``"urlhaus"``.
        feed_url: URLhaus plaintext feed endpoint.
    """

    key = "urlhaus"

    def __init__(self, interval_s: int = 300) -> None:
        """Initialise with a 5-minute poll interval.

        Args:
            interval_s: Poll interval in seconds.
        """
        super().__init__(interval_s)
        self.feed_url = "https://urlhaus.abuse.ch/downloads/text_online/"

    async def run(self, queue: "asyncio.Queue[str]") -> None:
        """Fetch the URLhaus feed in a loop, pushing new hostnames into the queue.

        Fetches once per ``interval_s`` seconds.  Skips comment and blank lines.
        Passes normalised hostnames to ``Ingester.enqueue``.

        Args:
            queue: Shared domain queue to push into.
        """
        while True:
            fetchresult: FetchResult = await HTTPClient.fetch(self.feed_url)
            txt = fetchresult.html
            if txt:
                hosts: Set[str] = set()
                for line in txt.splitlines():
                    if not line or line.startswith("#"):
                        continue
                    h = HTTPClient.normalize_host(line)
                    if h:
                        hosts.add(h)
                for host in hosts:
                    Ingester.enqueue(host, queue, self.key)
            await asyncio.sleep(self.interval_s)

class CertStream(Source):
    """Real-time Certificate Transparency log source via the certstream library.

    The certstream library manages the WebSocket connection and JSON parsing.
    A daemon thread runs the blocking ``certstream.listen_for_events`` call;
    each certificate event is forwarded to the asyncio queue via
    ``loop.call_soon_threadsafe``.  The thread retries automatically on
    disconnect or error so the stream stays live indefinitely.

    Attributes:
        key: YAML enable flag ``"certstream"``.
        _URL: certstream WebSocket endpoint.
    """

    key = "certstream"
    _URL: str = "wss://certstream.calidog.io/"

    def __init__(self, interval_s: int = 0) -> None:
        """Initialise the source.

        Args:
            interval_s: Unused; present for ``Source`` interface compatibility.
        """
        super().__init__(interval_s)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._queue: Optional["asyncio.Queue[str]"] = None

    @staticmethod
    def _parse_ct_domains(message: Any) -> List[str]:
        """Extract and normalise hostnames from a certstream ``certificate_update`` message.

        Parses the ``data.leaf_cert.all_domains`` field and returns only non-empty,
        normalised hostname strings.  All other message types (e.g. heartbeats) and
        any malformed structures return an empty list.

        Args:
            message: Parsed certificate event dict from the certstream library.

        Returns:
            List of normalised hostname strings.  Empty list for heartbeats,
            non-dict input, or any missing/malformed field.
        """
        if not isinstance(message, dict) or message.get("message_type") != "certificate_update":
            return []
        data = message.get("data") or {}
        if not isinstance(data, dict):
            return []
        leaf_cert = data.get("leaf_cert") or {}
        if not isinstance(leaf_cert, dict):
            return []
        all_domains = leaf_cert.get("all_domains") or []
        if not isinstance(all_domains, list):
            return []
        return [
            host for d in all_domains
            if isinstance(d, str)
            for host in (HTTPClient.normalize_host(d),)
            if host
        ]

    def _on_message(self, message: Any, context: Any) -> None:
        """Forward a certstream certificate event to the asyncio queue.

        Called by the certstream library from the listener thread for every
        incoming WebSocket message.  Parses certificate domains and forwards
        each to ``Ingester.enqueue`` via ``loop.call_soon_threadsafe`` so the
        enqueue operation executes on the event loop thread.

        Args:
            message: Parsed certificate event dict from certstream.
            context: WebSocket context provided by certstream (unused).
        """
        if self._loop is None or self._queue is None:
            return
        for host in self._parse_ct_domains(message):
            self._loop.call_soon_threadsafe(Ingester.enqueue, host, self._queue, self.key)

    def _on_error(self, exc: Exception) -> None:
        """Log a WebSocket error reported by the certstream library.

        Called by ``certstream.CertStreamClient`` as ``on_error_handler(ex)``
        — a single-argument callback (no ``instance`` parameter).

        Args:
            exc: Exception raised by the underlying WebSocket connection.
        """
        print(f"[certstream] connection error: {exc!r}")

    def _run_listener(self) -> None:
        """Thread target: run the certstream listener with automatic reconnection.

        Calls ``certstream.listen_for_events`` in a retry loop.  On clean
        disconnect (function returns) or any unexpected exception, waits 30
        seconds before reconnecting so transient outages are handled gracefully.
        """
        while True:
            try:
                certstream.listen_for_events(
                    self._on_message,
                    url=self._URL,
                    on_error=self._on_error,
                )
                print("[certstream] connection closed, retrying in 30 s")
            except Exception as exc:
                print(f"[certstream] unexpected error: {exc!r}, retrying in 30 s")
            time.sleep(30)

    async def run(self, queue: "asyncio.Queue[str]") -> None:
        """Start the certstream listener thread and suspend indefinitely.

        Stores the running event loop and queue so that the daemon thread can
        forward domains via ``call_soon_threadsafe``, then starts the thread
        and waits forever (the thread drives all further activity).

        Args:
            queue: Shared domain queue to push into.
        """
        self._loop = asyncio.get_running_loop()
        self._queue = queue
        thread = threading.Thread(target=self._run_listener, daemon=True)
        thread.start()
        print("[certstream] listener thread started")
        await asyncio.Event().wait()


class CERTPolska(Source):
    """CERT Polska (NASK) warning list: one domain per line, updated every 5 minutes.

    Operated by Poland's national CERT (NASK) with 24/7 coverage.  All entries
    are human-vetted and focused on financial phishing and credential-theft domains.
    Entries expire after 6 months.

    Attributes:
        key: YAML enable flag ``"certpolska"``.
        feed_url: CERT Polska v2 plain-text domain list endpoint.
    """

    key = "certpolska"

    def __init__(self, interval_s: int = 300) -> None:
        """Initialise with a 5-minute poll interval matching the feed refresh cadence.

        Args:
            interval_s: Poll interval in seconds.
        """
        super().__init__(interval_s)
        self.feed_url: str = "https://hole.cert.pl/domains/v2/domains.txt"

    async def run(self, queue: "asyncio.Queue[str]") -> None:
        """Fetch the CERT Polska domain list in a loop, pushing hostnames into the queue.

        Fetches once per ``interval_s`` seconds.  Skips blank and comment lines.
        Passes normalised hostnames to ``Ingester.enqueue``.

        Args:
            queue: Shared domain queue to push into.
        """
        while True:
            fetchresult: FetchResult = await HTTPClient.fetch(self.feed_url)
            txt = fetchresult.html
            if txt:
                hosts: Set[str] = set()
                for line in txt.splitlines():
                    if not line or line.startswith("#"):
                        continue
                    h = HTTPClient.normalize_host(line)
                    if h:
                        hosts.add(h)
                for host in hosts:
                    Ingester.enqueue(host, queue, self.key)
            await asyncio.sleep(self.interval_s)


class PhishingDatabase(Source):
    """Phishing.Database GitHub feed: PyFunceble-validated active phishing domains.

    Only domains that are currently resolving are kept in the feed — stale entries
    are continuously retested and pruned.  MIT-licensed.  Polled daily to stay
    within GitHub's rate limits.

    Attributes:
        key: YAML enable flag ``"phishingdatabase"``.
        feed_url: GitHub raw endpoint for the active-domains file.
    """

    key = "phishingdatabase"

    def __init__(self, interval_s: int = 86400) -> None:
        """Initialise with a 24-hour poll interval.

        Args:
            interval_s: Poll interval in seconds.
        """
        super().__init__(interval_s)
        self.feed_url: str = (
            "https://raw.githubusercontent.com/Phishing-Database/"
            "Phishing.Database/master/phishing-domains-ACTIVE.txt"
        )

    async def run(self, queue: "asyncio.Queue[str]") -> None:
        """Fetch the Phishing.Database active-domain list in a loop.

        Fetches once per ``interval_s`` seconds.  Skips blank and comment lines.
        Passes normalised hostnames to ``Ingester.enqueue``.

        Args:
            queue: Shared domain queue to push into.
        """
        while True:
            fetchresult: FetchResult = await HTTPClient.fetch(self.feed_url)
            txt = fetchresult.html
            if txt:
                hosts: Set[str] = set()
                for line in txt.splitlines():
                    if not line or line.startswith("#"):
                        continue
                    h = HTTPClient.normalize_host(line)
                    if h:
                        hosts.add(h)
                for host in hosts:
                    Ingester.enqueue(host, queue, self.key)
            await asyncio.sleep(self.interval_s)


class PhishingArmy(Source):
    """Phishing Army extended blocklist: aggregated feed refreshed every 6 hours.

    Aggregates PhishTank, OpenPhish, CERT.pl, PhishFindR, urlscan.io, and
    phishunt.io into a single deduplicated list.  Integrated into NextDNS.
    Licensed under CC BY-NC 4.0 — non-commercial use only.

    Attributes:
        key: YAML enable flag ``"phishingarmy"``.
        feed_url: Phishing Army extended blocklist endpoint.
    """

    key = "phishingarmy"

    def __init__(self, interval_s: int = 21600) -> None:
        """Initialise with a 6-hour poll interval matching the feed refresh cadence.

        Args:
            interval_s: Poll interval in seconds.
        """
        super().__init__(interval_s)
        self.feed_url: str = (
            "https://phishing.army/download/phishing_army_blocklist_extended.txt"
        )

    async def run(self, queue: "asyncio.Queue[str]") -> None:
        """Fetch the Phishing Army blocklist in a loop, pushing hostnames into the queue.

        Fetches once per ``interval_s`` seconds.  Skips blank and comment lines.
        Passes normalised hostnames to ``Ingester.enqueue``.

        Args:
            queue: Shared domain queue to push into.
        """
        while True:
            fetchresult: FetchResult = await HTTPClient.fetch(self.feed_url)
            txt = fetchresult.html
            if txt:
                hosts: Set[str] = set()
                for line in txt.splitlines():
                    if not line or line.startswith("#"):
                        continue
                    h = HTTPClient.normalize_host(line)
                    if h:
                        hosts.add(h)
                for host in hosts:
                    Ingester.enqueue(host, queue, self.key)
            await asyncio.sleep(self.interval_s)


class Botvrij(Source):
    """Botvrij.eu raw domain IOC list: independent Dutch threat intelligence project.

    Sourced from malware analysis, honeypots, and community contributions.
    Listed as a MISP default feed.  Low overlap with URLhaus and CERT Polska,
    providing independent signal.  Polled daily.

    Attributes:
        key: YAML enable flag ``"botvrij"``.
        feed_url: Botvrij.eu raw domain IOC endpoint.
    """

    key = "botvrij"

    def __init__(self, interval_s: int = 86400) -> None:
        """Initialise with a 24-hour poll interval.

        Args:
            interval_s: Poll interval in seconds.
        """
        super().__init__(interval_s)
        self.feed_url: str = "https://www.botvrij.eu/data/ioclist.domain.raw"

    async def run(self, queue: "asyncio.Queue[str]") -> None:
        """Fetch the Botvrij.eu domain IOC list in a loop, pushing hostnames into the queue.

        Fetches once per ``interval_s`` seconds.  Skips blank and comment lines.
        Passes normalised hostnames to ``Ingester.enqueue``.

        Args:
            queue: Shared domain queue to push into.
        """
        while True:
            fetchresult: FetchResult = await HTTPClient.fetch(self.feed_url)
            txt = fetchresult.html
            if txt:
                hosts: Set[str] = set()
                for line in txt.splitlines():
                    if not line or line.startswith("#"):
                        continue
                    h = HTTPClient.normalize_host(line)
                    if h:
                        hosts.add(h)
                for host in hosts:
                    Ingester.enqueue(host, queue, self.key)
            await asyncio.sleep(self.interval_s)


class DigitalSide(Source):
    """DigitalSide Threat-Intel OSINT domain list: community-maintained malware analysis feed.

    Independent sourcing from malware analysis, listed as a MISP default feed since 2019.
    Primary endpoint is osint.digitalside.it; falls back to the GitHub raw mirror if
    the primary is unreachable.  Polled daily.

    Attributes:
        key: YAML enable flag ``"digitalside"``.
        feed_url: Primary DigitalSide domain list endpoint.
        fallback_url: GitHub raw mirror used when the primary is unavailable.
    """

    key = "digitalside"

    def __init__(self, interval_s: int = 86400) -> None:
        """Initialise with a 24-hour poll interval.

        Args:
            interval_s: Poll interval in seconds.
        """
        super().__init__(interval_s)
        self.feed_url: str = (
            "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt"
        )
        self.fallback_url: str = (
            "https://raw.githubusercontent.com/davidonzo/Threat-Intel/"
            "master/lists/latestdomains.txt"
        )

    async def run(self, queue: "asyncio.Queue[str]") -> None:
        """Fetch the DigitalSide domain list in a loop, pushing hostnames into the queue.

        Tries the primary endpoint first; falls back to the GitHub raw mirror if the
        primary returns no content.  Fetches once per ``interval_s`` seconds.  Skips
        blank and comment lines.  Passes normalised hostnames to ``Ingester.enqueue``.

        Args:
            queue: Shared domain queue to push into.
        """
        while True:
            fetchresult: FetchResult = await HTTPClient.fetch(self.feed_url)
            txt = fetchresult.html
            if not txt:
                fetchresult = await HTTPClient.fetch(self.fallback_url)
                txt = fetchresult.html
            if txt:
                hosts: Set[str] = set()
                for line in txt.splitlines():
                    if not line or line.startswith("#"):
                        continue
                    h = HTTPClient.normalize_host(line)
                    if h:
                        hosts.add(h)
                for host in hosts:
                    Ingester.enqueue(host, queue, self.key)
            await asyncio.sleep(self.interval_s)


class URLhausCountry(Source):
    """URLhaus per-country malware URL feeds for targeted regional coverage.

    Polls the URLhaus country feed for each ISO 3166-1 alpha-2 code listed in
    ``CONFIG.ingester.urlhaus_country_codes``.  The feed endpoint returns a CSV
    with columns ``Dateadded,URL,URL_status,Threat,Host,IPaddress,ASnumber,Country``;
    the ``Host`` column (index 4) carries the hostname to enqueue.

    URLhaus asks that feeds are not polled more than once every 10 minutes.
    Defaults to a 10-minute interval covering all configured country codes per cycle.

    Attributes:
        key: YAML enable flag ``"urlhaus_country"``.
        _BASE: URL template for the URLhaus country feed; ``{cc}`` is replaced
            with the uppercase ISO country code.
    """

    key = "urlhaus_country"
    _BASE: str = "https://urlhaus.abuse.ch/feeds/country/{cc}/"

    def __init__(self, interval_s: int = 600) -> None:
        """Initialise with a 10-minute poll interval.

        Args:
            interval_s: Seconds to sleep between full country-code cycles.
        """
        super().__init__(interval_s)

    async def run(self, queue: "asyncio.Queue[str]") -> None:
        """Fetch the URLhaus country feed for each configured country code in a loop.

        Iterates over ``CONFIG.ingester.urlhaus_country_codes``, fetching the CSV
        feed for each country, parsing the ``Host`` column, and passing normalised
        hostnames to ``Ingester.enqueue``.  Sleeps for ``interval_s`` seconds after
        completing one full pass over all configured country codes.

        Args:
            queue: Shared domain queue to push into.
        """
        while True:
            for cc in CONFIG.ingester.urlhaus_country_codes:
                url = self._BASE.format(cc=cc.upper())
                fetchresult: FetchResult = await HTTPClient.fetch(url)
                txt = fetchresult.html
                if txt:
                    hosts: Set[str] = set()
                    reader = csv.reader(io.StringIO(txt))
                    for row in reader:
                        if not row or row[0].startswith("#"):
                            continue
                        if len(row) > 4:
                            h = HTTPClient.normalize_host(row[4])
                            if h:
                                hosts.add(h)
                    for host in hosts:
                        Ingester.enqueue(host, queue, f"{self.key}:{cc.upper()}")
            await asyncio.sleep(self.interval_s)


class ManualImport(Source):
    """Manual domain import: polls a local plaintext file every 30 seconds.

    Tracks previously seen domains in ``seen_domains`` so that re-reading the
    same file does not yield duplicates.

    Attributes:
        key: YAML enable flag ``"manual"``.
        path: Path to the local domain list file.
        seen_domains: Per-instance set of already-yielded domain strings.
    """

    key = "manual"

    def __init__(self, interval_s: int = 30) -> None:
        """Initialise with the default manual import file path.

        Args:
            interval_s: Poll interval in seconds.
        """
        super().__init__(interval_s)
        self.path = "data/manual_domains.txt"
        self.seen_domains: Set[str] = set()

    async def run(self, queue: "asyncio.Queue[str]") -> None:
        """Poll the manual import file in a loop, pushing new hostnames into the queue.

        Reads the file once per ``interval_s`` seconds.  Only domains not
        previously seen by this instance are passed to ``Ingester.enqueue``.

        Args:
            queue: Shared domain queue to push into.
        """
        while True:
            try:
                if os.path.exists(self.path):
                    hosts: Set[str] = set()
                    with open(self.path, "r", encoding="utf-8") as f:
                        for line in f:
                            h = HTTPClient.normalize_host(line)
                            if h and h not in self.seen_domains:
                                hosts.add(h)
                    self.seen_domains.update(hosts)
                    for host in hosts:
                        Ingester.enqueue(host, queue, self.key)
            except Exception:
                pass
            await asyncio.sleep(self.interval_s)


# ---- Orchestrator ----

class Ingester:
    """Manages source workers and provides shared deduplication-aware enqueue.

    ``enabled_sources()`` builds and returns enabled source instances, each
    configured with its poll interval from ``CONFIG.ingester.intervals``.
    ``enqueue`` is the single push point: it checks ``Source.VISITED_DOMAINS``
    before inserting a domain into the queue.
    """

    @staticmethod
    def enabled_sources() -> List[Source]:
        """Return source instances for each source whose config enable flag is ``True``.

        Intervals are sourced from ``CONFIG.ingester.intervals`` so that operators
        can tune poll cadence without touching source code.

        Returns:
            List of ``Source`` instances for all enabled feeds, each initialised
            with its configured poll interval.
        """
        iv = CONFIG.ingester.intervals
        enable = CONFIG.ingester.enable

        source_map: List[tuple] = [
            ("openphish",       lambda: OpenPhish(interval_s=iv.openphish)),
            ("phishtank",       lambda: PhishTank(interval_s=iv.phishtank)),
            ("urlhaus",         lambda: URLhaus(interval_s=iv.urlhaus)),
            ("certstream",      lambda: CertStream()),
            ("manual",          lambda: ManualImport(interval_s=iv.manual)),
            ("certpolska",      lambda: CERTPolska(interval_s=iv.certpolska)),
            ("phishingdatabase",lambda: PhishingDatabase(interval_s=iv.phishingdatabase)),
            ("phishingarmy",    lambda: PhishingArmy(interval_s=iv.phishingarmy)),
            ("botvrij",         lambda: Botvrij(interval_s=iv.botvrij)),
            ("digitalside",     lambda: DigitalSide(interval_s=iv.digitalside)),
            ("urlhaus_country", lambda: URLhausCountry(interval_s=iv.urlhaus_country)),
        ]
        return [factory() for key, factory in source_map if bool(getattr(enable, key, False))]

    @staticmethod
    def enqueue(domain: str, queue: "asyncio.Queue[str]", source: str = "") -> None:
        """Enqueue a domain if not already seen; update ``VISITED_DOMAINS``.

        Safe to call from a non-async thread via ``loop.call_soon_threadsafe``.

        Args:
            domain: Normalised hostname string to conditionally enqueue.
            queue: Shared domain queue to push into.
            source: Originating source identifier (retained for API compatibility).
        """
        if domain and domain not in Source.VISITED_DOMAINS:
            Source.VISITED_DOMAINS.add(domain)
            queue.put_nowait(domain)

