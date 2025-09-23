"""Processing RedisModules: logger, inactive remover, and interest classifier.

This RedisModule provides:
- Heuristic utilities and dataclasses for domain evaluation.
- HeuristicBase and concrete heuristic implementations.
- Processor: orchestrates context gathering, runs heuristics in parallel,
  aggregates results, and publishes to Redis channels.

Assumptions:
- dnspython and tldextract are installed and available.
"""

import asyncio
import re
import time
import base64
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx
import tldextract

from .commons import Channel, HTTPClient, RedisModule
from .config import Config, ProcessorThresholds


@dataclass
class FetchResult:
    """HTTP fetch result for a given URL."""
    url: str
    status: int
    headers: Dict[str, str]
    html: str
    history: List[int]
    final_url: str
    elapsed_ms: float


@dataclass
class DNSInfo:
    """DNS resolution snapshot and email posture."""
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx: List[str] = field(default_factory=list)
    ns: List[str] = field(default_factory=list)
    spf: List[str] = field(default_factory=list)
    dmarc: List[str] = field(default_factory=list)
    ttl_min: Optional[int] = None
    error: Optional[str] = None


@dataclass
class CertInfo:
    """TLS certificate summary for a host."""
    cn: Optional[str] = None
    san: List[str] = field(default_factory=list)
    org: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DomainContext:
    """Aggregated context for a domain under evaluation."""
    domain: str
    scheme_url: str
    fetches: Dict[str, FetchResult] = field(default_factory=dict)
    dns: Optional[DNSInfo] = None
    cert: Optional[CertInfo] = None
    registrable: Optional[str] = None
    host: Optional[str] = None


# ---------- Shared config and utilities for heuristics ----------

@dataclass
class HeuristicConfig:
    """Configuration shared across heuristics."""
    brands: List[Dict[str, Any]]
    forbidden_keywords: List[str]
    parking_signatures: List[str]
    kit_paths: List[str]
    # added brand-scoped lists
    whitelist_keywords: List[str] = field(default_factory=list)
    blacklist_keywords: List[str] = field(default_factory=list)


class HeuristicUtils:
    """Reusable utility helpers for heuristics."""

    def __init__(self, timeout_s: float) -> None:
        """Initialize utils.

        Args:
            timeout_s: Default timeout for blocking operations that use threads.
        """
        self.timeout_s: float = timeout_s

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
        regs: list[str] = [HeuristicUtils.registrable(h.lower()) for h in brand.get("domains", [])]
        hreg: str = HeuristicUtils.registrable(host.lower())
        return hreg in regs


# ---------- Heuristic base and implementations ----------

class HeuristicBase:
    """Base class for all heuristics."""

    name: str = "heuristic"

    def __init__(self, cfg: HeuristicConfig, utils: HeuristicUtils) -> None:
        """Initialize heuristic.

        Args:
            cfg: Shared heuristic configuration.
            utils: Shared utility functions.
        """
        self.cfg: HeuristicConfig = cfg
        self.utils: HeuristicUtils = utils

    async def evaluate(self, ctx: DomainContext) -> Dict[str, Any]:
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

    async def evaluate(self, ctx: DomainContext) -> Dict[str, Any]:
        """Mark domains as non-scam if HTTP down and/or no DNS.

        Args:
            ctx: DomainContext.

        Returns:
            Dict[str, Any]: Result dict.
        """
        pri: FetchResult = ctx.fetches.get("primary")
        inactive: bool = False
        reason: str = ""
        if pri and (pri.status == 0 or not (200 <= pri.status < 300)):
            inactive = True
            reason = f"http_status={pri.status}"
        if ctx.dns and not (ctx.dns.a_records or ctx.dns.aaaa_records) and not (ctx.dns.mx or ctx.dns.ns):
            inactive = True
            reason = reason or "dns_no_records"
        if inactive:
            return {"name": self.name, "status": "non_scam", "score": -30, "auto_non_scam": True, "evidence": reason}
        return {"name": self.name, "status": "inconclusive", "score": 0}


class ParkingHeuristic(HeuristicBase):
    """Detect parking/for-sale pages (non-scam)."""

    name: str = "parking_detect"

    async def evaluate(self, ctx: DomainContext) -> Dict[str, Any]:
        """Detect parked content via signatures or server headers.

        Args:
            ctx: DomainContext.

        Returns:
            Dict[str, Any]: Result dict.
        """
        pri: FetchResult = ctx.fetches.get("primary")
        if not pri:
            return {"name": self.name, "status": "inconclusive", "score": 0}
        text: str = (pri.html or "").lower()
        headers: dict[str, str] = pri.headers
        sig_hit: bool = any(sig in text for sig in self.cfg.parking_signatures)
        server: str = headers.get("server", "").lower()
        powered: str = headers.get("x-powered-by", "").lower()
        parked_server: bool = any(x in server for x in ["parking", "bodis", "sedo"]) or "parking" in powered
        if sig_hit or parked_server:
            return {"name": self.name, "status": "non_scam", "score": -40, "auto_non_scam": True, "evidence": "parking_signature"}
        return {"name": self.name, "status": "inconclusive", "score": 0}


class BrandLookalikeHeuristic(HeuristicBase):
    """Detect IDN/typosquat lookalikes and risky host tokens."""

    name: str = "brand_lookalike"

    async def evaluate(self, ctx: DomainContext) -> Dict[str, Any]:
        """Score domains that look visually similar to known brands.

        Args:
            ctx: DomainContext.

        Returns:
            Dict[str, Any]: Result dict.
        """
        host: str = ctx.host or ""
        registrable: str = ctx.registrable or host
        host_ascii: str = self.utils.to_ascii(host)
        score: int = 0
        evidence: Dict[str, Any] = {}

        if host_ascii.startswith("xn--") or ".xn--" in host_ascii:
            score += 40
            evidence["punycode"] = True

        best_hit: Optional[Dict[str, Any]] = None
        min_dist: int= 999
        for brand in self.cfg.brands:
            name: str = brand.get("name", "").lower()
            domains: list[str] = [d.lower() for d in brand.get("domains", [])]
            candidates: list[str] = [host_ascii.lower(), registrable.lower()]
            for cand in candidates:
                if name:
                    d: int = self.utils.confusable_distance(cand, name)
                    if d < min_dist:
                        min_dist = d
                        best_hit = {"type": "name", "target": name}
                for bd in domains:
                    bd_host: str = bd.split(".")[0]
                    d: int = self.utils.confusable_distance(cand.split(".")[0], bd_host)
                    if d < min_dist:
                        min_dist = d
                        best_hit = {"type": "domain", "target": bd_host}
        if best_hit and min_dist <= 2:
            score += 35
            evidence["lookalike"] = {"hit": best_hit, "distance": min_dist}

        if any(tok in host_ascii.lower() for tok in self.cfg.forbidden_keywords):
            score += 15
            evidence["risky_tokens_in_host"] = True

        return {"name": self.name, "status": "inconclusive", "score": score, "evidence": evidence}


class ForbiddenTokensHeuristic(HeuristicBase):
    """Detect forbidden/risky tokens in host/content."""

    name: str = "forbidden_tokens"

    async def evaluate(self, ctx: DomainContext) -> Dict[str, Any]:
        """Score presence of sensitive tokens.

        Args:
            ctx: DomainContext.

        Returns:
            Dict[str, Any]: Result dict.
        """
        pri: Optional[FetchResult] = ctx.fetches.get("primary")
        if not pri:
            return {"name": self.name, "status": "inconclusive", "score": 0}
        text: str = (pri.html or "").lower()
        host: str = (ctx.host or "").lower()
        tokens: list[str] = self.cfg.forbidden_keywords
        host_hit: bool = any(tok in host for tok in tokens)
        content_hit: bool = any(tok in text for tok in tokens)
        score: int = 0
        if host_hit:
            score += 20
        if content_hit:
            score += 25
        return {"name": self.name, "status": "inconclusive", "score": score, "evidence": {"host": host_hit, "content": content_hit}}


class FormsExfilHeuristic(HeuristicBase):
    """Detect credential/payment capture and exfil patterns (scam)."""

    name: str = "forms_and_exfil"

    async def evaluate(self, ctx: DomainContext) -> Dict[str, Any]:
        """Detect forms, cross-domain posts, and exfil endpoints.

        Args:
            ctx: DomainContext.

        Returns:
            Dict[str, Any]: Result dict, with auto_scam if strong indicators present.
        """
        pri: Optional[FetchResult] = ctx.fetches.get("primary")
        if not pri:
            return {"name": self.name, "status": "inconclusive", "score": 0}

        html: str = pri.html or ""
        host: str = ctx.host or ""
        evidence: Dict[str, Any] = {}

        creds_payment: Dict[str, bool] = self._find_credential_payment_indicators(html)
        cross_domain_post: bool = self._has_cross_domain_post(html, host)
        exfil: bool = self._has_exfil_endpoints(html)
        js_obf, high_entropy = self._has_js_obfuscation(html)
        wallet_hooks: bool = self._has_wallet_hooks(html)
        clipboard_hijack: bool = self._has_clipboard_hijack(html)

        evidence.update({
            "has_password": creds_payment["has_pwd"],
            "has_otp": creds_payment["has_otp"],
            "has_cc": creds_payment["has_cc"],
            "cross_domain_post": cross_domain_post,
            "exfil": exfil,
            "js_obf": js_obf or high_entropy,
            "wallet_hooks": wallet_hooks,
            "clipboard_hijack": clipboard_hijack,
        })

        score: int = 0
        if any(creds_payment.values()):
            score += 35
        if cross_domain_post:
            score += 30
        if exfil:
            score += 30
        if js_obf or high_entropy:
            score += 10
        if wallet_hooks or clipboard_hijack:
            score += 15

        auto_scam: bool = (creds_payment["has_pwd"] or creds_payment["has_cc"]) and (cross_domain_post or exfil)
        status: str = "scam" if auto_scam else "inconclusive"

        return {"name": self.name, "status": status, "score": score, "auto_scam": auto_scam, "evidence": evidence}

    def _find_credential_payment_indicators(self, html: str) -> Dict[str, bool]:
        """Find indications of credential or payment fields.

        Args:
            html: HTML content.

        Returns:
            Dict[str, bool]: Flags for password, OTP, and card fields.
        """
        has_pwd: bool = bool(re.search(r'type=["\']?password["\']?', html, flags=re.IGNORECASE))
        has_otp: bool = bool(re.search(r'(2fa|otp|one[-\s]?time)', html, flags=re.IGNORECASE))
        has_cc: bool = bool(re.search(r'(card number|ccnum|cvv|cvc)', html, flags=re.IGNORECASE))
        return {"has_pwd": has_pwd, "has_otp": has_otp, "has_cc": has_cc}

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
            act_host = self.utils.extract_host(act) if "://" in act else host
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

    def _has_js_obfuscation(self, html: str) -> Tuple[bool, bool]:
        """Detect JavaScript obfuscation traits.

        Args:
            html: HTML content.

        Returns:
            Tuple[bool, bool]: (has_obfuscation_calls, has_high_entropy_chunks)
        """
        js_obf: bool = bool(re.search(r"\b(atob|eval|Function\()|fromCharCode\(", html))
        high_entropy: bool = any(len(s) > 64 and HeuristicUtils.looks_base64(s) for s in re.findall(r"[A-Za-z0-9+/=]{40,}", html))
        return js_obf, high_entropy

    def _has_wallet_hooks(self, html: str) -> bool:
        """Detect web3 wallet hooks.

        Args:
            html: HTML content.

        Returns:
            bool: True if wallet APIs used.
        """
        return bool(re.search(r"(window\.ethereum|eth_requestAccounts|web3|eth_sign|walletconnect)", html, re.IGNORECASE))

    def _has_clipboard_hijack(self, html: str) -> bool:
        """Detect clipboard manipulation likely used for crypto scams.

        Args:
            html: HTML content.

        Returns:
            bool: True if clipboard hijack indicators present.
        """
        return "clipboard" in html.lower() and bool(re.search(r"(replace|execCommand|writeText)", html, re.IGNORECASE))


class RedirectCloakingHeuristic(HeuristicBase):
    """Detect multi-hop redirects and user-agent cloaking."""

    name: str = "redirect_and_cloaking"

    async def evaluate(self, ctx: DomainContext) -> Dict[str, Any]:
        """Score redirects and content diffs across UAs.

        Args:
            ctx: DomainContext.

        Returns:
            Dict[str, Any]: Result dict.
        """
        pri: Optional[FetchResult] = ctx.fetches.get("primary")
        alt: Optional[FetchResult] = ctx.fetches.get("alt")
        if not pri or not alt:
            return {"name": self.name, "status": "inconclusive", "score": 0}
        score: int = 0
        evidence: Dict[str, Any] = {}
        multi_redirect: bool = len(pri.history) >= 2
        evidence["redirects"] = pri.history
        diff_ratio: float = self.utils.content_diff_ratio(pri.html, alt.html)
        evidence["ua_diff_ratio"] = diff_ratio
        cloaking: bool = diff_ratio > 0.5 and (len(pri.html) > 500 or len(alt.html) > 500)
        if multi_redirect:
            score += 10
        if cloaking:
            score += 20
        return {"name": self.name, "status": "inconclusive", "score": score, "evidence": evidence}


class PhishingKitHeuristic(HeuristicBase):
    """Detect common phishing kit paths and code comments/signatures."""

    name: str = "phishing_kit"

    async def evaluate(self, ctx: DomainContext) -> Dict[str, Any]:
        """Search for known phishing kit fingerprints and paths."""
        pri: Optional[FetchResult] = ctx.fetches.get("primary")
        if not pri:
            return {"name": self.name, "status": "inconclusive", "score": 0}
        html: str = pri.html.lower()
        path_hit: bool = any(p in pri.final_url.lower() for p in self.cfg.kit_paths)
        kit_comments: bool = bool(re.search(r"(phishing kit|by .* phisher|tg://|t\.me/)", html))
        score: int = 0
        if path_hit:
            score += 20
        if kit_comments:
            score += 25
        return {"name": self.name, "status": "inconclusive", "score": score, "evidence": {"path_hit": path_hit, "kit_comments": kit_comments}}


class DnsEmailPostureHeuristic(HeuristicBase):
    """Evaluate DNS fast-flux patterns and weak email authentication."""

    name: str = "dns_email_posture"

    async def evaluate(self, ctx: DomainContext) -> Dict[str, Any]:
        """Score indicators of fast-flux and weak SPF/DMARC with MX."""
        info: Optional[DnsInfo] = ctx.dns
        if not info:
            return {"name": self.name, "status": "inconclusive", "score": 0}
        score: int = 0
        many_a: bool = len(info.a_records) >= 5
        low_ttl: bool = info.ttl_min is not None and info.ttl_min < 300
        if many_a:
            score += 10
        if low_ttl:
            score += 10
        has_mx: bool = len(info.mx) > 0
        spf_weak: bool = any(("+all" in s.lower()) or ("~all" in s.lower()) for s in info.spf)
        dmarc_weak: bool = len(info.dmarc) == 0 or any(("p=none" in s.lower()) for s in info.dmarc)
        if has_mx and (spf_weak or dmarc_weak):
            score += 20
        return {
            "name": self.name,
            "status": "inconclusive",
            "score": score,
            "evidence": {
                "a_records": len(info.a_records),
                "ttl_min": info.ttl_min,
                "has_mx": has_mx,
                "spf_weak": bool(spf_weak),
                "dmarc_weak": bool(dmarc_weak),
            },
        }


class TlsCertHeuristic(HeuristicBase):
    """Use TLS certificate org/name signals as weak features."""

    name: str = "tls_cert"

    async def evaluate(self, ctx: DomainContext) -> Dict[str, Any]:
        """Lean benign on OV/EV org presence; flag CN brand mismatches."""
        cert: Optional[str] = ctx.cert
        if not cert or cert.error:
            return {"name": self.name, "status": "inconclusive", "score": 0, "evidence": {"error": cert.error if cert else "no_cert"}}
        score: int = 0
        evidence: Dict[str, Any] = {"cn": cert.cn, "san_count": len(cert.san), "org": cert.org}
        if cert.org:
            score -= 10  # potential OV/EV signal
            evidence["org_present"] = True
        host: str = ctx.host or ""
        brand_names: list[str] = [b["name"].lower() for b in self.cfg.brands if "name" in b]
        cn: str = (cert.cn or "").lower()
        if cn and any(b in cn for b in brand_names) and not any(
            HeuristicUtils.domain_belongs_to_brand(host, b) for b in self.cfg.brands
        ):
            score += 20
            evidence["cn_brand_mismatch"] = True
        return {"name": self.name, "status": "inconclusive", "score": score, "evidence": evidence}


class LongLivedVerifiedHeuristic(HeuristicBase):
    """Benign-leaning signals: HSTS, OV/EV + branded NS alignment."""

    name: str = "long_lived_or_verified"

    async def evaluate(self, ctx: DomainContext) -> Dict[str, Any]:
        """Mark strong org+NS alignment as auto non-scam; HSTS slightly benign."""
        pri: Optional[FetchResult] = ctx.fetches.get("primary")
        cert: str = ctx.cert
        dns: str = ctx.dns
        score: int = 0
        auto_non: bool = False
        evidence: Dict[str, Any] = {}
        hsts: bool = bool(pri and "strict-transport-security" in pri.headers)
        if hsts:
            score -= 5
            evidence["hsts"] = True
        branded_ns: bool = False
        if dns and dns.ns:
            ns_join: str = " ".join(dns.ns).lower()
            for b in self.cfg.brands:
                for ns in b.get("ns", []):
                    if ns.lower() in ns_join:
                        branded_ns = True
                        break
        if cert and cert.org and branded_ns:
            score -= 30
            auto_non = True
            evidence["ov_ev_and_brand_ns"] = True
        return {"name": self.name, "status": "inconclusive", "score": score, "auto_non_scam": auto_non, "evidence": evidence}


class Processor(RedisModule):
    """Run heuristics to classify domains; prefilter by whitelist/blacklist."""

    def __init__(self) -> None:
        super().__init__(listening_channel=Channel.PROCESS)

        # Load YAML config
        cfg: Config = Config.load()

        # Simplified: set shared utils/config for heuristics
        self.utils: HeuristicUtils = HeuristicUtils(timeout_s=cfg.processor.timeout_s)
        self.cfg: HeuristicConfig = HeuristicConfig(
            brands=[{"name": b.name or "", "domains": b.domains} for b in cfg.brands],
            forbidden_keywords=cfg.processor.forbidden_keywords,
            parking_signatures=cfg.processor.parking_signatures,
            kit_paths=cfg.processor.kit_paths,
            whitelist_keywords=cfg.processor.whitelist_keywords,
            blacklist_keywords=cfg.processor.blacklist_keywords,
        )

        th: ProcessorThresholds = cfg.processor.thresholds
        self.SCAM_SCORE: int = th.scam
        self.NON_SCAM_SCORE: int = th.non_scam
        self.max_content_bytes: int = cfg.processor.max_content_bytes
        self.timeout_s: float = cfg.processor.timeout_s

        # Minimal heuristic suite (keep it lean)
        self.heuristics: List[HeuristicBase] = [
            InactiveHeuristic(self.cfg, self.utils),
            ParkingHeuristic(self.cfg, self.utils),
            BrandLookalikeHeuristic(self.cfg, self.utils),
            ForbiddenTokensHeuristic(self.cfg, self.utils),
            FormsExfilHeuristic(self.cfg, self.utils),
            RedirectCloakingHeuristic(self.cfg, self.utils),
            PhishingKitHeuristic(self.cfg, self.utils),
            DnsEmailPostureHeuristic(self.cfg, self.utils),
            TlsCertHeuristic(self.cfg, self.utils),
            LongLivedVerifiedHeuristic(self.cfg, self.utils),
        ]

    def _is_whitelisted(self, host: str) -> bool:
        wl: list[str] = self.cfg.whitelist_keywords or []
        host_l: str = host.lower()
        return any(k for k in wl if k and k.lower() in host_l)

    def _is_blacklisted(self, host: str) -> Optional[str]:
        bl: list[str] = self.cfg.blacklist_keywords or []
        host_l: str = host.lower()
        for k in bl:
            if k and k.lower() in host_l:
                return k
        return None

    async def _safe_eval(self, heuristic: HeuristicBase, ctx: DomainContext) -> Dict[str, Any]:
        try:
            return await asyncio.wait_for(heuristic.evaluate(ctx), timeout=self.timeout_s)
        except Exception as e:
            return {"name": heuristic.name, "status": "error", "evidence": str(e), "score": 0}

    async def _fetch(self, url: str, ua: str) -> FetchResult:
        client: HTTPClient = HTTPClient.get()
        headers: dict[str, str] = {"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9"}
        t0: float = time.time()
        try:
            resp: httpx.Response = await client.get(url)
            html: str = (resp.text or "")[: self.max_content_bytes]
            return FetchResult(
                url=url,
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                html=html,
                history=[h.status_code for h in getattr(resp, "history", [])],
                final_url=str(resp.url),
                elapsed_ms=round((time.time() - t0) * 1000, 1),
            )
        except Exception:
            return FetchResult(url=url, status=0, headers={}, html="", history=[], final_url=url, elapsed_ms=round((time.time() - t0) * 1000, 1))

    async def _build_context(self, domain: str) -> DomainContext:
        host: str = HeuristicUtils.extract_host(domain)
        reg: bool = HeuristicUtils.registrable(host)
        url: str = f"http://{host}"
        # two UAs only, keep simple
        # Windows
        primary: FetchResult = await self._fetch(url, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
        # iPhone 
        alt: FetchResult = await self._fetch(url, "Mozilla/5.0 (Linux; Android 15; SM-S931B Build/AP3A.240905.015.A2; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/127.0.6533.103 Mobile Safari/537.36")
        return DomainContext(domain=domain, scheme_url=url, fetches={"primary": primary, "alt": alt}, registrable=reg, host=host)

    async def act(self, domain: str) -> None:
        domain: str = str(domain).strip()
        host: str = HeuristicUtils.extract_host(domain)

        # 1) Drop irrelevant (whitelisted) early
        if self._is_whitelisted(host):
            return

        # 2) Auto-scam for blacklisted
        hit = self._is_blacklisted(host)
        if hit:
            #payload: dict[str, Any] = {"domain": domain, "status": "scam", "score": 999, "reason": f"blacklist_keyword:{hit}"}
            await self.publish(Channel.SCAM, domain)
            return

        # 3) Build minimal context and run heuristics
        ctx: DomainContext = await self._build_context(domain)
        results: list[Dict[str, Any]] = await asyncio.gather(*[self._safe_eval(h, ctx) for h in self.heuristics])

        # 4) Aggregate
        score: int = sum(r.get("score", 0) for r in results)
        auto_scam: bool = any(r.get("auto_scam") for r in results)
        auto_non_scam: bool = any(r.get("auto_non_scam") for r in results)

        if auto_scam or score >= self.SCAM_SCORE:
            channel = Channel.SCAM
        elif auto_non_scam or score <= self.NON_SCAM_SCORE:
            channel = Channel.BENIGN
        else:
            channel = Channel.INCONCLUSIVE

        await self.publish(channel, domain)

    async def start(self):
        await self.subscribe(self.act)