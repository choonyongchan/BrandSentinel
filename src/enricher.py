"""Domain context assembly: dataclasses and async functions for enriching HTTP, DNS, TLS, and registration data.

This module is the Extract-and-Enrich step of the pipeline.  Given a raw domain
string, ``build_context`` performs all network I/O concurrently and returns a
fully populated ``DomainContext`` ready for heuristic evaluation.

Enrichment sources:
- HTTP: Two fetches (desktop + mobile User-Agent), plus ``/robots.txt``.
- DNS: A, AAAA, MX, NS, SPF, DMARC, TTL, plus reverse-DNS PTR per A record,
  plus CNAME chain.
- TLS: Certificate CN, SAN, org, validity dates.
- RDAP: Registration date and registrar via ``https://rdap.org/domain/{registrable}``.
- Favicon: SHA-1 hash of ``/favicon.ico`` for brand fingerprint matching.
- Certificate Transparency: Cert count and earliest issuance date via ``crt.sh``.
"""

from __future__ import annotations

import asyncio
import dns.asyncresolver
import dns.resolver
import dns.reversename
import hashlib
import json
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .http_client import FetchResult, HTTPClient


# ---------- Data Transfer Objects ----------

@dataclass
class DNSInfo:
    """Snapshot of DNS records, email-authentication posture, and reverse-DNS for a domain.

    Attributes:
        a_records: IPv4 addresses from A records.
        aaaa_records: IPv6 addresses from AAAA records.
        mx: Mail-exchanger hostnames from MX records.
        ns: Nameserver hostnames from NS records.
        spf: TXT records that contain ``spf1``.
        dmarc: TXT records found at ``_dmarc.<domain>``.
        ttl_min: Lowest TTL (seconds) observed across all queried record sets,
            or ``None`` if no records were returned.
        error: String representation of any unhandled exception, or ``None``
            on success.
        ptr_records: Reverse-DNS PTR hostnames for each resolved A record IP.
            Empty if no A records or all PTR lookups fail.
    """

    a_records: List[str]
    aaaa_records: List[str]
    mx: List[str]
    ns: List[str]
    spf: List[str]
    dmarc: List[str]
    ttl_min: Optional[int]
    error: Optional[str]
    ptr_records: List[str] = field(default_factory=list)


@dataclass
class CertInfo:
    """Summary of the TLS certificate presented on port 443.

    Attributes:
        cn: Common Name from the Subject field, or ``None``.
        san: Subject Alternative Names (DNS entries only).
        org: Organisation name from the Subject field, or ``None``.
            Its presence indicates an OV or EV certificate.
        not_before: Certificate validity start date as a string.
        not_after: Certificate validity end date as a string.
        error: String representation of any exception during the TLS handshake,
            or ``None`` on success.
    """

    cn: Optional[str]
    san: List[str]
    org: Optional[str]
    not_before: Optional[str]
    not_after: Optional[str]
    error: Optional[str]


@dataclass
class FetchResults:
    """Pair of HTTP responses captured with different User-Agent strings.

    Fetching with two distinct User-Agents allows heuristics to detect
    user-agent cloaking (where bots and mobile users see different content).

    Attributes:
        primary: Response obtained with a desktop (Windows/Chrome) User-Agent.
        alternative: Response obtained with a mobile (iPhone/Safari) User-Agent.
    """

    primary: FetchResult
    alternative: FetchResult


@dataclass
class RegistrationInfo:
    """RDAP-sourced domain registration metadata.

    Attributes:
        created: ISO 8601 registration date string (e.g. ``"2024-01-15T10:00:00Z"``),
            or ``None`` if the event was not reported.
        registrar: Human-readable registrar name, or ``None`` if not present in the
            RDAP response.
        error: String representation of any network or parse error, or ``None``
            on success.
    """

    created: Optional[str]
    registrar: Optional[str]
    error: Optional[str]


@dataclass
class FaviconInfo:
    """SHA-1 fingerprint of the domain's ``/favicon.ico``.

    Attributes:
        sha1: Hex-encoded SHA-1 hash of the raw favicon bytes, or ``None`` if
            the fetch failed or returned no content.
        error: String representation of any fetch error, or ``None`` on success.
    """

    sha1: Optional[str]
    error: Optional[str]


@dataclass
class CnameInfo:
    """DNS CNAME chain for the domain.

    Attributes:
        chain: Ordered list of CNAME targets (e.g. ``["alias.cdn.net.", "cdn.net."]``).
            Empty if the domain has no CNAME records.
        error: String representation of any DNS error, or ``None`` on success.
    """

    chain: List[str]
    error: Optional[str]


@dataclass
class CtInfo:
    """Certificate Transparency history sourced from crt.sh.

    Attributes:
        cert_count: Total number of certificates ever issued for the registrable domain.
            Zero if the domain has no CT log entries or the query failed.
        earliest_date: ISO 8601 ``not_before`` date of the oldest certificate, or
            ``None`` if no certs were found.
        error: String representation of any network or parse error, or ``None``
            on success.
    """

    cert_count: int
    earliest_date: Optional[str]
    error: Optional[str]


@dataclass
class DomainContext:
    """All gathered intelligence for a single domain under evaluation.

    This is the central data object consumed by every heuristic.  It is built
    once per domain in ``build_context`` so that heuristics share results
    without repeating network calls.

    Attributes:
        domain: The original domain string as received from the pipeline.
        scheme_url: The ``http://`` URL used for fetching.
        fetches: Paired HTTP responses (desktop UA and mobile UA).
        dns: DNS records snapshot.
        cert: TLS certificate summary.
        registrable: The eTLD+1 registrable domain (e.g. ``example.com``).
        host: The normalised bare hostname (no scheme, path, or port).
        registration: RDAP registration metadata, or ``None`` if not fetched.
        favicon: Favicon SHA-1 fingerprint, or ``None`` if not fetched.
        cname: DNS CNAME chain, or ``None`` if not fetched.
        ct: Certificate Transparency history, or ``None`` if not fetched.
        robots_txt: Raw content of ``/robots.txt`` if status 200, else ``None``.
    """

    domain: str
    scheme_url: str
    fetches: FetchResults
    dns: Optional[DNSInfo]
    cert: Optional[CertInfo]
    registrable: Optional[str]
    host: Optional[str]
    registration: Optional[RegistrationInfo] = None
    favicon: Optional[FaviconInfo] = None
    cname: Optional[CnameInfo] = None
    ct: Optional[CtInfo] = None
    robots_txt: Optional[str] = None


# ---------- Private helpers ----------

async def _dns_safe(resolver: dns.asyncresolver.Resolver, qname: str, rdtype: str):
    """Resolve a DNS record type, suppressing ``NoAnswer`` silently.

    Args:
        resolver: An async DNS resolver instance.
        qname: The fully-qualified domain name to query.
        rdtype: DNS record type (e.g. ``"A"``, ``"MX"``).

    Returns:
        The resolver answer object, or ``None`` if ``NoAnswer`` was raised.
    """
    try:
        return await resolver.resolve(qname, rdtype)
    except dns.resolver.NoAnswer:
        return None


def _make_resolver(timeout: float = 3.0) -> dns.asyncresolver.Resolver:
    """Create a configured async DNS resolver with a fixed timeout.

    Args:
        timeout: Per-query and lifetime timeout in seconds.

    Returns:
        A ``dns.asyncresolver.Resolver`` with ``timeout`` and ``lifetime`` set.
    """
    r = dns.asyncresolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    return r


def _parse_iso_date(date_str: str) -> Optional[datetime]:
    """Parse an ISO 8601 date string to a timezone-aware datetime.

    Handles the ``Z`` UTC suffix and ``+HH:MM`` offsets.

    Args:
        date_str: An ISO 8601 date string.

    Returns:
        A ``datetime`` with UTC timezone on success, or ``None`` on parse failure.
    """
    try:
        normalised = date_str.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(normalised).astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None


# ---------- Context-gathering functions ----------

async def get_dns_info(domain: str) -> DNSInfo:
    """Query DNS records, email-authentication posture, and reverse-DNS for ``domain``.

    Performs A, AAAA, MX, NS, SPF (TXT), and DMARC queries concurrently with a
    3-second timeout.  PTR lookups are then performed concurrently for all
    resolved A record IPs.  Individual ``NoAnswer`` exceptions per record type
    are suppressed; any other exception returns a ``DNSInfo`` with ``error``
    populated.

    Args:
        domain: Bare hostname to query (no scheme or path).

    Returns:
        A ``DNSInfo`` containing whatever records could be fetched, with
        ``error`` set if a fatal exception occurred.
    """
    try:
        resolver = _make_resolver()

        a_ans, aaaa_ans, mx_ans, ns_ans, txt_ans, dmarc_ans = await asyncio.gather(
            _dns_safe(resolver, domain, "A"),
            _dns_safe(resolver, domain, "AAAA"),
            _dns_safe(resolver, domain, "MX"),
            _dns_safe(resolver, domain, "NS"),
            _dns_safe(resolver, domain, "TXT"),
            _dns_safe(resolver, f"_dmarc.{domain}", "TXT"),
        )

        a_records: List[str] = [str(r) for r in a_ans] if a_ans else []
        aaaa_records: List[str] = [str(r) for r in aaaa_ans] if aaaa_ans else []
        mx_records: List[str] = [str(r.exchange) for r in mx_ans] if mx_ans else []
        ns_records: List[str] = [str(r) for r in ns_ans] if ns_ans else []
        spf_records: List[str] = [str(r) for r in txt_ans if "spf1" in str(r).lower()] if txt_ans else []
        dmarc_records: List[str] = [str(r) for r in dmarc_ans if "DMARC1" in str(r)] if dmarc_ans else []

        min_ttl: Optional[int] = None
        if a_ans and a_ans.rrset:
            min_ttl = a_ans.rrset.ttl
        if aaaa_ans and aaaa_ans.rrset:
            min_ttl = aaaa_ans.rrset.ttl if min_ttl is None else min(min_ttl, aaaa_ans.rrset.ttl)

        ptr_records = await _get_ptr_records(resolver, a_records)

        return DNSInfo(
            a_records=a_records,
            aaaa_records=aaaa_records,
            mx=mx_records,
            ns=ns_records,
            spf=spf_records,
            dmarc=dmarc_records,
            ttl_min=min_ttl,
            error=None,
            ptr_records=ptr_records,
        )

    except Exception as e:
        return DNSInfo(
            a_records=[],
            aaaa_records=[],
            mx=[],
            ns=[],
            spf=[],
            dmarc=[],
            ttl_min=None,
            error=str(e),
            ptr_records=[],
        )


async def _get_ptr_records(resolver: dns.asyncresolver.Resolver, a_records: List[str]) -> List[str]:
    """Perform reverse-DNS PTR lookups for a list of IPv4 addresses.

    Lookups run concurrently; individual failures are silently ignored.

    Args:
        resolver: An async DNS resolver instance.
        a_records: List of IPv4 address strings to look up.

    Returns:
        A deduplicated list of PTR hostnames across all provided IPs.
    """
    if not a_records:
        return []

    async def _ptr_for_ip(ip: str) -> List[str]:
        try:
            rev = dns.reversename.from_address(ip)
            ans = await resolver.resolve(str(rev), "PTR")
            return [str(r) for r in ans]
        except Exception:
            return []

    results = await asyncio.gather(*(_ptr_for_ip(ip) for ip in a_records))
    seen: set[str] = set()
    ptrs: List[str] = []
    for batch in results:
        for ptr in batch:
            if ptr not in seen:
                seen.add(ptr)
                ptrs.append(ptr)
    return ptrs


async def get_cert_info(domain: str) -> CertInfo:
    """Retrieve and parse the TLS certificate presented on port 443.

    Opens an async SSL connection with a 3-second timeout.  The ``org`` field
    is populated only for OV/EV certificates that include an ``organizationName``
    in the Subject.

    Args:
        domain: Bare hostname to connect to (no scheme or port).

    Returns:
        A ``CertInfo`` with parsed fields on success, or a ``CertInfo`` with
        all fields ``None``/empty and ``error`` populated on failure.
    """
    writer = None
    try:
        ssl_ctx = ssl.create_default_context()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=ssl_ctx),
            timeout=3.0,
        )
        cert = writer.get_extra_info("peercert")

        cn: Optional[str] = next(
            (f[0][1] for f in cert.get("subject", []) if f[0][0] == "commonName"),
            None,
        )
        san: List[str] = [x[1] for x in cert.get("subjectAltName", [])]
        org: Optional[str] = next(
            (f[0][1] for f in cert.get("subject", []) if f[0][0] == "organizationName"),
            None,
        )

        return CertInfo(
            cn=cn,
            san=san,
            org=org,
            not_before=cert.get("notBefore"),
            not_after=cert.get("notAfter"),
            error=None,
        )

    except Exception as e:
        return CertInfo(cn=None, san=[], org=None, not_before=None, not_after=None, error=str(e))

    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()


async def get_rdap_info(registrable: str) -> RegistrationInfo:
    """Fetch domain registration metadata from RDAP.

    Queries ``https://rdap.org/domain/{registrable}`` for registration date
    and registrar name.  Gracefully handles timeouts and malformed responses.

    Args:
        registrable: The eTLD+1 registrable domain (e.g. ``"example.com"``).

    Returns:
        A ``RegistrationInfo`` with ``created`` and ``registrar`` on success,
        or with ``error`` populated on failure.
    """
    try:
        status, raw = await HTTPClient.fetch_bytes(
            f"https://rdap.org/domain/{registrable}", timeout=5
        )
        if status != 200 or not raw:
            return RegistrationInfo(created=None, registrar=None, error=f"http_status={status}")

        data = json.loads(raw)

        created: Optional[str] = next(
            (e.get("eventDate") for e in data.get("events", []) if e.get("eventAction") == "registration"),
            None,
        )

        registrar: Optional[str] = None
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    registrar = next(
                        (f[3] for f in vcard[1] if f[0] == "fn"),
                        None,
                    )
                break

        return RegistrationInfo(created=created, registrar=registrar, error=None)

    except Exception as e:
        return RegistrationInfo(created=None, registrar=None, error=str(e))


async def get_favicon_info(host: str) -> FaviconInfo:
    """Fetch ``/favicon.ico`` and compute its SHA-1 fingerprint.

    Used by ``FaviconBrandMismatchHeuristic`` to detect sites serving an exact
    copy of a known brand's favicon.

    Args:
        host: Bare hostname (no scheme or path).

    Returns:
        A ``FaviconInfo`` with ``sha1`` set on success, or ``error`` populated
        on failure (including HTTP non-200 or empty body).
    """
    try:
        status, content = await HTTPClient.fetch_bytes(f"http://{host}/favicon.ico", timeout=5)
        if status != 200 or not content:
            return FaviconInfo(sha1=None, error=f"http_status={status}")
        return FaviconInfo(sha1=hashlib.sha1(content).hexdigest(), error=None)
    except Exception as e:
        return FaviconInfo(sha1=None, error=str(e))


async def get_cname_info(host: str) -> CnameInfo:
    """Resolve the CNAME chain for ``host`` up to ten hops.

    Used by ``BulletproofHostHeuristic`` to identify domains aliased to
    known bulletproof hosting infrastructure.

    Args:
        host: Bare hostname to start the CNAME traversal from.

    Returns:
        A ``CnameInfo`` with the ordered ``chain`` of CNAME targets, or
        ``error`` populated if the DNS resolver itself raises.
    """
    try:
        resolver = _make_resolver()
        chain: List[str] = []
        current = host
        for _ in range(10):
            try:
                ans = await resolver.resolve(current, "CNAME")
                target = str(next(iter(ans)))
                chain.append(target)
                current = target.rstrip(".")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                break
        return CnameInfo(chain=chain, error=None)
    except Exception as e:
        return CnameInfo(chain=[], error=str(e))


async def get_ct_info(registrable: str) -> CtInfo:
    """Query crt.sh for the Certificate Transparency history of ``registrable``.

    Returns the total number of certificates ever issued and the earliest
    ``not_before`` date.  Used by ``CtHistoryHeuristic`` to detect
    newly-established campaign domains.

    Args:
        registrable: The eTLD+1 registrable domain (e.g. ``"example.com"``).

    Returns:
        A ``CtInfo`` with ``cert_count`` and ``earliest_date`` on success,
        or ``error`` populated on failure.
    """
    try:
        status, raw = await HTTPClient.fetch_bytes(
            f"https://crt.sh/?q={registrable}&output=json", timeout=10
        )
        if status != 200 or not raw:
            return CtInfo(cert_count=0, earliest_date=None, error=f"http_status={status}")

        certs = json.loads(raw)
        if not isinstance(certs, list) or not certs:
            return CtInfo(cert_count=0, earliest_date=None, error=None)

        dates = [c.get("not_before") or c.get("entry_timestamp") for c in certs]
        dates = [d for d in dates if d]
        earliest = min(dates) if dates else None
        return CtInfo(cert_count=len(certs), earliest_date=earliest, error=None)

    except Exception as e:
        return CtInfo(cert_count=0, earliest_date=None, error=str(e))


# User-Agent strings used for dual-perspective HTTP fetches.
_UA_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36"
)
_UA_IPHONE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.0 Mobile/15E148 Safari/604.1"
)


async def build_context(domain: str) -> DomainContext:
    """Assemble a ``DomainContext`` by performing all enrichment I/O for ``domain``.

    All network calls run concurrently via ``asyncio.gather``:
    two HTTP fetches (desktop + mobile UA), a ``/robots.txt`` fetch,
    DNS (A/AAAA/MX/NS/SPF/DMARC/PTR), TLS certificate inspection,
    RDAP registration lookup, favicon SHA-1, CNAME chain, and
    Certificate Transparency history.

    Heuristics must not make additional network calls; all data is provided
    through the returned ``DomainContext``.

    Args:
        domain: The domain string received from the pipeline queue.

    Returns:
        A fully populated ``DomainContext`` ready for heuristic evaluation.
    """
    import tldextract

    host: str = HTTPClient.normalize_host(domain)
    ext = tldextract.extract(host)
    reg: str = ".".join(p for p in [ext.domain, ext.suffix] if p) or host
    url: str = f"http://{host}"

    (
        primary, alternative, robots_result,
        dns_info, cert_info,
        rdap_info, favicon_info, cname_info, ct_info,
    ) = await asyncio.gather(
        HTTPClient.fetch(url, headers={"User-Agent": _UA_WINDOWS, "Accept-Language": "en-US,en;q=0.9"}),
        HTTPClient.fetch(url, headers={"User-Agent": _UA_IPHONE, "Accept-Language": "en-US,en;q=0.9"}),
        HTTPClient.fetch(f"{url}/robots.txt"),
        get_dns_info(host),
        get_cert_info(host),
        get_rdap_info(reg),
        get_favicon_info(host),
        get_cname_info(host),
        get_ct_info(reg),
    )

    robots_txt: Optional[str] = (
        robots_result.html if robots_result.status == 200 and robots_result.html else None
    )

    return DomainContext(
        domain=domain,
        scheme_url=url,
        fetches=FetchResults(primary=primary, alternative=alternative),
        dns=dns_info,
        cert=cert_info,
        registrable=reg,
        host=host,
        registration=rdap_info,
        favicon=favicon_info,
        cname=cname_info,
        ct=ct_info,
        robots_txt=robots_txt,
    )
