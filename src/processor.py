"""Processing RedisModules: logger, inactive remover, and interest classifier.

This RedisModule provides:
- Heuristic utilities and dataclasses for domain evaluation.
- HeuristicBase and concrete heuristic implementations.
- Processor: orchestrates context gathering, runs heuristics in parallel,
  aggregates results, and publishes to Redis channels.

Assumptions:
- dnspython and tldextract are installed and available.
"""
from .commons import Channel, HTTPClient, RedisClient, FetchResult
from .config import CONFIG

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import base64
import re
import tldextract
import unicodedata
import dns.resolver
import ssl
import socket


@dataclass
class DNSInfo:
    """DNS resolution snapshot and email posture."""
    a_records: List[str]
    aaaa_records: List[str]
    mx: List[str]
    ns: List[str]
    spf: List[str]
    dmarc: List[str]
    ttl_min: Optional[int]
    error: Optional[str]


@dataclass
class CertInfo:
    """TLS certificate summary for a host."""
    cn: Optional[str]
    san: List[str]
    org: Optional[str]
    not_before: Optional[str]
    not_after: Optional[str]
    error: Optional[str]

@dataclass
class FetchResults:
    primary: FetchResult
    alternative: FetchResult

@dataclass
class DomainContext:
    """Aggregated context for a domain under evaluation."""
    domain: str
    scheme_url: str
    fetches: FetchResults
    dns: Optional[DNSInfo]
    cert: Optional[CertInfo]
    registrable: Optional[str]
    host: Optional[str]

@dataclass
class HeuristicResults:
    """Aggregated heuristic results for a domain."""
    name: str
    status: Channel
    score: float
    evidence: str


# ---------- Shared config and utilities for heuristics ----------

class HeuristicUtils:
    """Reusable utility helpers for heuristics."""

    @staticmethod
    def to_ascii(host: str) -> str:
        """Convert a host to IDNA ASCII if possible.

        Args:
            host: Hostname.

        Returns:
            str: ASCII-encoded hostname or original on failure.
        """
        try:
            return host.encode("idna").decode("ascii")
        except Exception:
            return host

    @staticmethod
    def extract_host(domain_or_url: str) -> str:
        """Extract the host from a domain or URL string.

        Args:
            domain_or_url: Input possibly including scheme and path.

        Returns:
            str: Hostname without scheme or path.
        """
        d: str = domain_or_url.strip()
        d = d.replace("http://", "").replace("https://", "")
        d = d.split("/")[0].strip().strip(".")
        return d

    @staticmethod
    def looks_base64(s: str) -> bool:
        """Check if a string looks like valid base64.

        Args:
            s: Input string.

        Returns:
            bool: True if the string decodes as base64.
        """
        if len(s) % 4 != 0:
            return False
        try:
            base64.b64decode(s, validate=True)
            return True
        except Exception:
            return False

    @staticmethod
    def content_diff_ratio(a: str, b: str) -> float:
        """Compute a coarse content difference ratio using token Jaccard.

        Args:
            a: First HTML/text content.
            b: Second HTML/text content.

        Returns:
            float: Ratio in [0,1], higher means more different.
        """
        if not a and not b:
            return 0.0
        if not a or not b:
            return 1.0
        a_tokens: set[str] = set(re.findall(r"\w+", a.lower()))
        b_tokens: set[str] = set(re.findall(r"\w+", b.lower()))
        if not a_tokens and not b_tokens:
            return 0.0
        inter: int = len(a_tokens & b_tokens)
        union: int = len(a_tokens | b_tokens)
        return 1.0 - (inter / union if union else 1.0)

    @staticmethod
    def levenshtein(s1: str, s2: str) -> int:
        """Compute Levenshtein distance between two strings.

        Args:
            s1: First string.
            s2: Second string.

        Returns:
            int: Edit distance.
        """
        if s1 == s2:
            return 0
        if not s1:
            return len(s2)
        if not s2:
            return len(s1)
        if len(s1) < len(s2):
            s1, s2 = s2, s1
        previous_row: list[int] = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1, 1):
            current_row: list[int] = [i]
            for j, c2 in enumerate(s2, 1):
                insertions: int = previous_row[j] + 1
                deletions: int = current_row[j - 1] + 1
                substitutions: int = previous_row[j - 1] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    @staticmethod
    def confusable_distance(a: str, b: str) -> int:
        """Compute distance with a simple Unicode confusable skeleton.

        Args:
            a: First string.
            b: Second string.

        Returns:
            int: Confusable-aware distance.
        """
        def skel(x: str) -> str:
            x = unicodedata.normalize("NFKD", x)
            x = "".join(ch for ch in x if not unicodedata.combining(ch))
            repl = {
                "0": "o", "1": "l", "3": "e", "@": "a", "$": "s",
                "¡": "i", "ı": "i", "ɩ": "i",
                "а": "a", "е": "e", "о": "o", "ѕ": "s", "і": "i", "ӏ": "l",
                "β": "b", "ɡ": "g",
            }
            x = "".join(repl.get(ch, ch) for ch in x.lower())
            return x
        return HeuristicUtils.levenshtein(skel(a), skel(b))

    @staticmethod
    def registrable(host: str) -> str:
        """Return registrable eTLD+1 for a host.

        Args:
            host: Hostname.

        Returns:
            str: eTLD+1 using tldextract (domain.suffix), or host if absent.
        """
        ext: tldextract.ExtractResult = tldextract.extract(host)
        return ".".join(p for p in [ext.domain, ext.suffix] if p) or host

    @staticmethod
    def domain_belongs_to_brand(host: str, brand: Dict[str, Any]) -> bool:
        """Return True if host registrable matches brand's known domains.

        Args:
            host: Hostname to check.
            brand: Brand dictionary with 'domains' entries.

        Returns:
            bool: True if host registrable equals any brand registrable.
        """
        regs: list[str] = [HeuristicUtils.registrable(h.lower()) for h in brand.get("valid_domains", [])]
        hreg: str = HeuristicUtils.registrable(host.lower())
        return hreg in regs


# ---------- Heuristic base and implementations ----------

class HeuristicBase:
    """Base class for all heuristics."""

    name: str = "heuristic"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Evaluate the heuristic against the given domain context.

        Args:
            ctx: Domain context built by the processor.

        Returns:
            Dict[str, Any]: Heuristic result with name, score, evidence, and optional auto flags.
        """
        raise NotImplementedError


class InactiveHeuristic(HeuristicBase):
    """Detect inactive or unresolved domains (non-scam)."""

    name: str = "inactive_domain"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Mark domains as non-scam if HTTP down and/or no DNS.

        Args:
            ctx: DomainContext.

        Returns:
            Dict[str, Any]: Result dict.
        """
        inactive: bool = False
        reason: str = ""

        pri: FetchResult = ctx.fetches.primary
        if pri and not (200 <= pri.status < 300):
            inactive = True
            reason = f"http_status={pri.status}"
        elif ctx.dns and not (ctx.dns.a_records or ctx.dns.aaaa_records) and not (ctx.dns.mx or ctx.dns.ns):
            inactive = True
            reason = "dns_no_records"

        if inactive:
            return HeuristicResults(name=self.name, status=Channel.BENIGN, score=0, evidence=reason)
        return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=0.5, evidence="")


class ParkingHeuristic(HeuristicBase):
    """Detect parking/for-sale pages (non-scam)."""

    name: str = "parking_detect"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Detect parked content via signatures or server headers.

        Args:
            ctx: DomainContext.

        Returns:
            Dict[str, Any]: Result dict.
        """
        pri: FetchResult = ctx.fetches.primary
        text: str = (pri.html or "").lower()
        headers: dict[str, str] = pri.headers
        sig_hit: bool = any(sig in text for sig in CONFIG.processor.parking_signatures)
        server: str = headers.get("server", "").lower()
        powered: str = headers.get("x-powered-by", "").lower()
        parked_server: bool = any(x in server for x in ["parking", "bodis", "sedo"]) or "parking" in powered
        if sig_hit or parked_server:
            return HeuristicResults(name=self.name, status=Channel.BENIGN, score=0, evidence="parking_signature")
        return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=0.5, evidence="")

class PunycodeHeuristic(HeuristicBase):

    name: str = "punycode"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        host: str = HeuristicUtils.to_ascii(ctx.host or "")

        if host.startswith("xn--") or ".xn--" in host:
            return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=0.9, evidence="punycode_detected")
        return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=0.5, evidence="")
    
class BrandLookalikeHeuristic(HeuristicBase):
    """Detect IDN/typosquat lookalikes and risky host tokens."""

    name: str = "brand_lookalike"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Score domains that look visually similar to known brands.

        Args:
            ctx: DomainContext.

        Returns:
            Dict[str, Any]: Result dict.
        """
        host: str = HeuristicUtils.to_ascii(ctx.host or "")
        registrable: str = ctx.registrable or host

        best_hit: Optional[Dict[str, Any]] = None
        min_dist: int= 999
        for brand in CONFIG.brands:
            name: str = brand.name.lower()
            domains: list[str] = [d.lower() for d in brand.valid_domains]
            candidates: list[str] = [host.lower(), registrable.lower()]
            for cand in candidates:
                if name:
                    d: int = HeuristicUtils.confusable_distance(cand, name)
                    if d < min_dist:
                        min_dist = d
                        best_hit = {"type": "name", "target": name}
                for bd in domains:
                    bd_host: str = bd.split(".")[0]
                    d: int = HeuristicUtils.confusable_distance(cand.split(".")[0], bd_host)
                    if d < min_dist:
                        min_dist = d
                        best_hit = {"type": "domain", "target": bd_host}
        if best_hit and min_dist <= 10:
            return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=0.8, evidence=f"lookalike_to_{best_hit['type']}:{best_hit['target']}")
        return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=0.5, evidence="")

class ForbiddenTokensHeuristic(HeuristicBase):
    """Detect forbidden/risky tokens in host/content."""

    name: str = "forbidden_tokens"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Score presence of sensitive tokens.

        Args:
            ctx: DomainContext.

        Returns:
            Dict[str, Any]: Result dict.
        """
        pri: FetchResult = ctx.fetches.primary
        text: str = (pri.html or "").lower()
        host: str = (ctx.host or "").lower()
        tokens: list[str] = CONFIG.processor.forbidden_keywords
        host_hit: bool = any(tok in host for tok in tokens)
        content_hit: bool = any(tok in text for tok in tokens)
        score: float = 0.5
        if host_hit:
            score += 0.2
        if content_hit:
            score += 0.25
        return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=score, evidence=f"host_hit={host_hit},content_hit={content_hit}")


class FormsExfilHeuristic(HeuristicBase):
    """Detect credential/payment capture and exfil patterns (scam)."""

    name: str = "forms_and_exfil"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Detect forms, cross-domain posts, and exfil endpoints.

        Args:
            ctx: DomainContext.

        Returns:
            Dict[str, Any]: Result dict, with auto_scam if strong indicators present.
        """
        pri: FetchResult = ctx.fetches.primary

        html: str = pri.html or ""
        host: str = ctx.host or ""

        has_password, has_otp, has_cc = self._find_credential_payment_indicators(html)
        cross_domain_post: bool = self._has_cross_domain_post(html, host)
        exfil: bool = self._has_exfil_endpoints(html)
        js_obf, high_entropy = self._has_js_obfuscation(html)
        wallet_hooks: bool = self._has_wallet_hooks(html)
        clipboard_hijack: bool = self._has_clipboard_hijack(html)

        evidence: Dict[str, Any] = {
            "has_password": has_password,
            "has_otp": has_otp,
            "has_cc": has_cc,
            "cross_domain_post": cross_domain_post,
            "exfil": exfil,
            "js_obf": js_obf or high_entropy,
            "wallet_hooks": wallet_hooks,
            "clipboard_hijack": clipboard_hijack,
        }

        score: float = 0.5
        if any((has_password, has_otp, has_cc)):
            score += 0.35
        if cross_domain_post:
            score += 0.3
        if exfil:
            score += 0.3
        if js_obf or high_entropy:
            score += 0.1
        if wallet_hooks or clipboard_hijack:
            score += 0.15

        auto_scam: bool = (has_password or has_cc) and (cross_domain_post or exfil)
        status: Channel = Channel.SCAM if auto_scam else Channel.INCONCLUSIVE
        score = 1.0 if auto_scam else min(1.0, score)

        return HeuristicResults(name=self.name, status=status, score=score, evidence=str(evidence))

    def _find_credential_payment_indicators(self, html: str) -> tuple[bool, bool, bool]:
        """Find indications of credential or payment fields.

        Args:
            html: HTML content.

        Returns:
            Dict[str, bool]: Flags for password, OTP, and card fields.
        """
        has_pwd: bool = bool(re.search(r'type=["\']?password["\']?', html, flags=re.IGNORECASE))
        has_otp: bool = bool(re.search(r'(2fa|otp|one[-\s]?time)', html, flags=re.IGNORECASE))
        has_cc: bool = bool(re.search(r'(card number|ccnum|cvv|cvc)', html, flags=re.IGNORECASE))
        return has_pwd, has_otp, has_cc

    def _has_cross_domain_post(self, html: str, host: str) -> bool:
        """Check whether any form posts to a different host.

        Args:
            html: HTML content.
            host: Current host.

        Returns:
            bool: True if a form action posts off-domain.
        """
        actions: list[str] = re.findall(r"<form[^>]*action=[\"']?([^\"'>\s]+)", html, flags=re.IGNORECASE)
        for act in actions:
            act_host = HeuristicUtils.extract_host(act) if "://" in act else host
            if act_host and host and act_host != host and not act.startswith("#"):
                return True
        return False

    def _has_exfil_endpoints(self, html: str) -> bool:
        """Detect common exfiltration endpoints.

        Args:
            html: HTML content.

        Returns:
            bool: True if exfiltration patterns observed.
        """
        if re.search(r"(mailto:|sendmail\.php|wp-mail|phpmail|smtp)", html, re.IGNORECASE):
            return True
        if re.search(r"(t\.me/|telegram\.(me|org)|bot_token|api\.telegram\.org)", html, re.IGNORECASE):
            return True
        if re.search(r"(discord\.gg|discord\.com/api/webhooks)", html, re.IGNORECASE):
            return True
        return False

    JS_OBFUSCATION_REGEX = re.compile(r"\b(atob|eval|Function\()|fromCharCode\(")
    def _has_js_obfuscation(self, html: str) -> Tuple[bool, bool]:
        """Detect JavaScript obfuscation traits.

        Args:
            html: HTML content.

        Returns:
            Tuple[bool, bool]: (has_obfuscation_calls, has_high_entropy_chunks)
        """
        js_obf: bool = bool(self.JS_OBFUSCATION_REGEX.search(html))
        high_entropy: bool = any(len(s) > 64 and HeuristicUtils.looks_base64(s) for s in re.findall(r"[A-Za-z0-9+/=]{40,}", html))
        return js_obf, high_entropy

    WALLET_HOOKS_REGEX = re.compile(r"(window\.ethereum|eth_requestAccounts|web3|eth_sign|walletconnect)")
    def _has_wallet_hooks(self, html: str) -> bool:
        """Detect web3 wallet hooks.

        Args:
            html: HTML content.

        Returns:
            bool: True if wallet APIs used.
        """
        return bool(self.WALLET_HOOKS_REGEX.search(html))

    REPLACEMENT_REGEX = re.compile(r"(replace|execCommand|writeText)")
    def _has_clipboard_hijack(self, html: str) -> bool:
        """Detect clipboard manipulation likely used for crypto scams.

        Args:
            html: HTML content.

        Returns:
            bool: True if clipboard hijack indicators present.
        """
        return "clipboard" in html.lower() and bool(self.REPLACEMENT_REGEX.search(html))


class RedirectCloakingHeuristic(HeuristicBase):
    """Detect multi-hop redirects and user-agent cloaking."""

    name: str = "redirect_and_cloaking"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Score redirects and content diffs across UAs.

        Args:
            ctx: DomainContext.

        Returns:
            Dict[str, Any]: Result dict.
        """
        pri: Optional[FetchResult] = ctx.fetches.primary
        alt: Optional[FetchResult] = ctx.fetches.alternative
        score: float = 0
        evidence: Dict[str, Any] = {}
        multi_redirect: bool = len(pri.history) >= 2
        evidence["redirects"] = pri.history
        diff_ratio: float = HeuristicUtils.content_diff_ratio(pri.html, alt.html)
        evidence["ua_diff_ratio"] = diff_ratio
        cloaking: bool = diff_ratio > 0.5 and (len(pri.html) > 500 or len(alt.html) > 500)
        if multi_redirect:
            score += 0.1
        if cloaking:
            score += 0.2
        return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=score, evidence=str(evidence))


class PhishingKitHeuristic(HeuristicBase):
    """Detect common phishing kit paths and code comments/signatures."""

    name: str = "phishing_kit"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Search for known phishing kit fingerprints and paths."""
        pri: Optional[FetchResult] = ctx.fetches.primary
        html: str = pri.html.lower()
        path_hit: bool = any(p in pri.final_url.lower() for p in CONFIG.processor.kit_paths)
        kit_comments: bool = bool(re.search(r"(phishing kit|by .* phisher|tg://|t\.me/)", html))
        evidence: Dict[str, Any] = {"path_hit": path_hit, "kit_comments": kit_comments}
        score: float = 0.5
        if path_hit:
            score += 0.2
        if kit_comments:
            score += 0.25
        return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=score, evidence=str(evidence))


class DnsEmailPostureHeuristic(HeuristicBase):
    """Evaluate DNS fast-flux patterns and weak email authentication."""

    name: str = "dns_email_posture"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Score indicators of fast-flux and weak SPF/DMARC with MX."""
        info: Optional[DNSInfo] = ctx.dns
        if not info:
            return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=0.5, evidence="no_dns_info")
        score: float = 0.5
        many_a: bool = len(info.a_records) >= 5
        low_ttl: bool = info.ttl_min is not None and info.ttl_min < 300
        if many_a:
            score += 0.1
        if low_ttl:
            score += 0.1
        has_mx: bool = len(info.mx) > 0
        spf_weak: bool = any(("+all" in s.lower()) or ("~all" in s.lower()) for s in info.spf)
        dmarc_weak: bool = len(info.dmarc) == 0 or any(("p=none" in s.lower()) for s in info.dmarc)
        if has_mx and (spf_weak or dmarc_weak):
            score += 0.2
        evidence: Dict[str, Any] = {
            "a_records": len(info.a_records),
            "ttl_min": info.ttl_min,
            "has_mx": has_mx,
            "spf_weak": spf_weak,
            "dmarc_weak": dmarc_weak,
        }
            
        return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=score, evidence=str(evidence))


class TlsCertHeuristic(HeuristicBase):
    """Use TLS certificate org/name signals as weak features."""

    name: str = "tls_cert"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Lean benign on OV/EV org presence; flag CN brand mismatches."""
        cert: Optional[CertInfo] = ctx.cert
        if not cert or cert.error:
            evidence: Dict[str, Any] = {"error": cert.error if cert else "no_cert"}
            return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=0, evidence=str(evidence))
        score: float = 0.5
        evidence: Dict[str, Any] = {"cn": cert.cn, "san_count": len(cert.san), "org": cert.org}
        if cert.org:
            score -= 0.10  # potential OV/EV signal
            evidence["org_present"] = True
        host: str = ctx.host or ""
        brand_names: list[str] = [b.name.lower() for b in CONFIG.brands]
        cn: str = (cert.cn or "").lower()
        if cn and any(b in cn for b in brand_names) and not any(
            HeuristicUtils.domain_belongs_to_brand(host, b) for b in CONFIG.brands
        ):
            score += 0.2
            evidence["cn_brand_mismatch"] = True
        return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=score, evidence=str(evidence))


class LongLivedVerifiedHeuristic(HeuristicBase):
    """Benign-leaning signals: HSTS, OV/EV + branded NS alignment."""

    name: str = "long_lived_or_verified"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Mark strong org as auto non-scam; HSTS slightly benign."""
        pri: FetchResult = ctx.fetches.primary
        cert: Optional[CertInfo] = ctx.cert
        score: float = 0.5
        evidence: Dict[str, Any] = {}
        hsts: bool = bool(pri and "strict-transport-security" in pri.headers)
        if hsts:
            score -= 0.3
            evidence["hsts"] = True
        if cert and cert.org:
            evidence["ov_ev_and_brand_ns"] = True
            return HeuristicResults(name=self.name, status=Channel.BENIGN, score=0, evidence=str(evidence))
        return HeuristicResults(name=self.name, status=Channel.INCONCLUSIVE, score=score, evidence=str(evidence))


class Processor:
    """Run heuristics to classify domains; prefilter by whitelist/blacklist."""

    scam_threshold: int = CONFIG.processor.thresholds.scam
    non_scam_threshold: int = CONFIG.processor.thresholds.non_scam
    heuristics: List[HeuristicBase] = [
        InactiveHeuristic(),
        ParkingHeuristic(),
        BrandLookalikeHeuristic(),
        PunycodeHeuristic(),
        ForbiddenTokensHeuristic(),
        FormsExfilHeuristic(),
        RedirectCloakingHeuristic(),
        PhishingKitHeuristic(),
        DnsEmailPostureHeuristic(),
        TlsCertHeuristic(),
        LongLivedVerifiedHeuristic(),
    ]  

    @staticmethod
    def is_whitelisted(host: str) -> bool:
        wl: list[str] = CONFIG.processor.whitelist_keywords or []
        host_l: str = host.lower()
        return any(k for k in wl if k and k.lower() in host_l)

    @staticmethod
    def is_blacklisted(host: str) -> bool:
        bl: list[str] = CONFIG.processor.blacklist_keywords or []
        host_l: str = host.lower()
        return any(k for k in bl if k and k.lower() in host_l)

    @staticmethod
    async def fetch(url: str, ua: str) -> FetchResult:
        headers: dict[str, str] = {"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9"}
        return await HTTPClient.fetch(url=url, headers=headers)

    @staticmethod
    def get_dns_info(domain: str) -> Optional[DNSInfo]:
        """Gather DNS records and email authentication posture for a domain.
        
        Args:
            domain: Domain to query.
            
        Returns:
            Optional[DNSInfo]: DNS context or None on error.
        """
        try:
            # Create a resolver with a short timeout
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            # Query different record types
            a_records = []
            aaaa_records = []
            mx_records = []
            ns_records = []
            spf_records = []
            dmarc_records = []
            min_ttl = None
            
            # A records
            try:
                answers = resolver.resolve(domain, 'A')
                a_records = [str(rdata) for rdata in answers]
                if min_ttl is None or answers.rrset.ttl < min_ttl:
                    min_ttl = answers.rrset.ttl
            except dns.resolver.NoAnswer:
                pass
                
            # AAAA records
            try:
                answers = resolver.resolve(domain, 'AAAA')
                aaaa_records = [str(rdata) for rdata in answers]
                if min_ttl is None or answers.rrset.ttl < min_ttl:
                    min_ttl = answers.rrset.ttl
            except dns.resolver.NoAnswer:
                pass
                
            # MX records
            try:
                answers = resolver.resolve(domain, 'MX')
                mx_records = [str(rdata.exchange) for rdata in answers]
            except dns.resolver.NoAnswer:
                pass
                
            # NS records  
            try:
                answers = resolver.resolve(domain, 'NS')
                ns_records = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                pass
                
            # SPF (TXT records containing spf1)
            try:
                answers = resolver.resolve(domain, 'TXT')
                spf_records = [str(rdata) for rdata in answers if 'spf1' in str(rdata).lower()]
            except dns.resolver.NoAnswer:
                pass
                
            # DMARC 
            try:
                answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
                dmarc_records = [str(rdata) for rdata in answers if 'DMARC1' in str(rdata)]
            except dns.resolver.NoAnswer:
                pass
                
            return DNSInfo(
                a_records=a_records,
                aaaa_records=aaaa_records,
                mx=mx_records,
                ns=ns_records,
                spf=spf_records,
                dmarc=dmarc_records,
                ttl_min=min_ttl,
                error=None
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
                error=str(e)
            )

    @staticmethod
    def get_cert_info(domain: str) -> Optional[CertInfo]:
        """Get TLS certificate information for a domain.
        
        Args:
            domain: Domain to check.
            
        Returns:
            Optional[CertInfo]: Certificate info or None on error.
        """
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=domain
            )
            conn.settimeout(3.0)
            
            # Connect and get cert
            conn.connect((domain, 443))
            cert = conn.getpeercert()
            
            # Parse certificate fields
            cn = None
            san = []
            org = None
            not_before = None
            not_after = None
            
            # Get Subject CN
            for field in cert.get('subject', []):
                if field[0][0] == 'commonName':
                    cn = field[0][1]
                    break
                    
            # Get SAN
            san = [x[1] for x in cert.get('subjectAltName', [])]
            
            # Get Organization
            for field in cert.get('subject', []):
                if field[0][0] == 'organizationName':
                    org = field[0][1]
                    break
                    
            # Get validity period
            not_before = cert.get('notBefore')
            not_after = cert.get('notAfter')
            
            return CertInfo(
                cn=cn,
                san=san,
                org=org,
                not_before=not_before,
                not_after=not_after,
                error=None
            )
            
        except Exception as e:
            return CertInfo(
                cn=None,
                san=[],
                org=None,
                not_before=None,
                not_after=None,
                error=str(e)
            )

    @staticmethod
    async def _build_context(domain: str) -> DomainContext:
        host: str = HeuristicUtils.extract_host(domain)
        reg: str = HeuristicUtils.registrable(host)
        url: str = f"http://{host}"
        
        # Windows
        windows_ua: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
        primary: FetchResult = await Processor.fetch(url, windows_ua)
        
        # iPhone
        iphone_ua: str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
        alt: FetchResult = await Processor.fetch(url, iphone_ua)
        
        # Get DNS and cert info
        dns_info = Processor.get_dns_info(host)
        cert_info = Processor.get_cert_info(host)
        
        fetchresults: FetchResults = FetchResults(primary=primary, alternative=alt)
        return DomainContext(
            domain=domain, 
            scheme_url=url, 
            fetches=fetchresults,
            dns=dns_info,
            cert=cert_info, 
            registrable=reg, 
            host=host
        )

    @staticmethod
    async def start(listening_channel: Channel = Channel.PROCESS) -> None:
        async for domain in RedisClient.subscribe(listening_channel=listening_channel):
            dom: str = str(domain).strip()
            host: str = HeuristicUtils.extract_host(dom)

            # 1) Drop irrelevant (whitelisted) early
            if Processor.is_whitelisted(host):
                continue

            # 2) Auto-scam for blacklisted
            hit = Processor.is_blacklisted(host)
            if hit:
                await RedisClient.publish(Channel.SCAM, dom)
                continue

            # 3) Build minimal context and run heuristics
            ctx: DomainContext = await Processor._build_context(domain)
            results: list[HeuristicResults] = [h.evaluate(ctx) for h in Processor.heuristics]

            auto_scam: bool = any(r.status == Channel.SCAM for r in results)
            if auto_scam:
                await RedisClient.publish(Channel.SCAM, domain)
                continue

            auto_benign: bool = any(r.status == Channel.BENIGN for r in results)
            if auto_benign:
                await RedisClient.publish(Channel.BENIGN, domain)
                continue

            # 4) Aggregate
            score: float = sum(r.score for r in results) / len(results) if results else 0.5
            if score >= Processor.scam_threshold:
                channel = Channel.SCAM
            elif score <= Processor.non_scam_threshold:
                channel = Channel.BENIGN
            else:
                channel = Channel.INCONCLUSIVE

            await RedisClient.publish(channel, domain)