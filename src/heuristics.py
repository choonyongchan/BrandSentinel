"""Heuristic engine: result dataclass, base class, and all concrete heuristic implementations.

## Classification model

Each heuristic returns a ``HeuristicResults`` with exactly one of three flags set:

- ``is_scam_definitive=True`` — Unambiguous, high-confidence scam signature.
  The ``Processor`` short-circuits to SCAM immediately.
- ``is_benign_definitive=True`` — The domain is definitively not an active threat.
  The ``Processor`` short-circuits to BENIGN.
- ``suspicious=True`` — The heuristic fired but is not individually conclusive.
  The heuristic's ``weight`` (1–3) is added to a running tally.  The final
  normalised score (tally / max possible weight) is compared against
  ``CONFIG.processor.thresholds.scam``; if it meets the threshold the domain
  is classified as SCAM, otherwise INCONCLUSIVE.

## Heuristic weights

| Weight | Meaning | Example heuristics |
|--------|---------|-------------------|
| 3 | Strong — paired with anything → threshold often met | BrandLookalike, FormsExfil (partial) |
| 2 | Moderate — two together → threshold met | Punycode, ForbiddenTokens, CertAge |
| 1 | Weak — supporting evidence only | DnsEmailPosture, TlsCert, SubdomainDepth |

## Adding a new heuristic

1. Subclass ``HeuristicBase``.
2. Set ``name`` and ``weight`` class attributes.
3. Override ``evaluate(ctx) -> HeuristicResults``.
4. Append an instance to ``Processor.heuristics`` in ``src/processor.py``.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import tldextract

from .http_client import HTTPClient
from .config import CONFIG
from .enricher import CertInfo, DNSInfo, DomainContext, FetchResult, RegistrationInfo, _parse_iso_date


# ---------- Result dataclass ----------

@dataclass
class HeuristicResults:
    """Output produced by a single heuristic evaluation.

    Exactly one of ``is_scam_definitive``, ``is_benign_definitive``, or
    ``suspicious`` should be ``True``; the other two should be ``False``.

    Attributes:
        name: Identifier of the heuristic that produced this result.
        is_scam_definitive: ``True`` if this heuristic found an unambiguous scam
            signature.  The Processor routes the domain to SCAM immediately,
            regardless of other heuristic results.
        is_benign_definitive: ``True`` if this heuristic conclusively determined
            the domain is not an active threat.  The Processor routes to BENIGN
            (unless a scam-definitive result was also produced).
        suspicious: ``True`` if this heuristic fired and its ``weight`` should be
            added to the suspicious-score tally.  Does not alone determine the
            final verdict.
        evidence: Human-readable summary of what triggered this result.
    """

    name: str
    is_scam_definitive: bool
    is_benign_definitive: bool
    suspicious: bool
    evidence: str


# ---------- Helpers ----------

def _neutral(name: str) -> HeuristicResults:
    """Return a no-signal result (heuristic did not fire).

    Args:
        name: The heuristic name to embed in the result.

    Returns:
        A ``HeuristicResults`` with all flags ``False``.
    """
    return HeuristicResults(name=name, is_scam_definitive=False, is_benign_definitive=False, suspicious=False, evidence="")


def _benign(name: str, evidence: str) -> HeuristicResults:
    """Return a definitively-benign result.

    Args:
        name: The heuristic name.
        evidence: Short description of the benign signal detected.

    Returns:
        A ``HeuristicResults`` with ``is_benign_definitive=True``.
    """
    return HeuristicResults(name=name, is_scam_definitive=False, is_benign_definitive=True, suspicious=False, evidence=evidence)


def _scam(name: str, evidence: str) -> HeuristicResults:
    """Return a definitively-scam result.

    Args:
        name: The heuristic name.
        evidence: Short description of the definitive scam signal detected.

    Returns:
        A ``HeuristicResults`` with ``is_scam_definitive=True``.
    """
    return HeuristicResults(name=name, is_scam_definitive=True, is_benign_definitive=False, suspicious=False, evidence=evidence)


def _suspicious(name: str, evidence: str) -> HeuristicResults:
    """Return a suspicious result (contributes weight to the tally).

    Args:
        name: The heuristic name.
        evidence: Short description of the suspicious signal detected.

    Returns:
        A ``HeuristicResults`` with ``suspicious=True``.
    """
    return HeuristicResults(name=name, is_scam_definitive=False, is_benign_definitive=False, suspicious=True, evidence=evidence)


# ---------- Shared utilities ----------

class HeuristicUtils:
    """Reusable static helpers shared across heuristic implementations."""

    @staticmethod
    def to_ascii(host: str) -> str:
        """Convert a hostname to its IDNA ASCII representation.

        Args:
            host: Unicode or ASCII hostname.

        Returns:
            The IDNA-encoded ASCII hostname, or the original string if
            encoding fails.
        """
        try:
            return host.encode("idna").decode("ascii")
        except Exception:
            return host

    @staticmethod
    def looks_base64(s: str) -> bool:
        """Return ``True`` if ``s`` appears to be valid Base64-encoded data.

        Args:
            s: Candidate string.

        Returns:
            ``True`` if the string length is a multiple of 4 and it decodes
            without error using strict Base64 validation.
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
        """Compute a coarse content-difference ratio using token Jaccard similarity.

        A ratio of 0.0 means the two texts are identical; 1.0 means they share
        no tokens at all.

        Args:
            a: First HTML or text body.
            b: Second HTML or text body.

        Returns:
            Difference ratio in [0.0, 1.0].  Higher means more different.
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
        """Compute the Levenshtein (edit) distance between two strings.

        Args:
            s1: First string.
            s2: Second string.

        Returns:
            Minimum number of single-character edits needed to transform
            ``s1`` into ``s2``.
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
        """Compute a Unicode-confusable-aware edit distance between two strings.

        Applies a lightweight skeleton mapping (digit/symbol/Cyrillic
        lookalikes → their Latin equivalents) before computing Levenshtein
        distance, so that e.g. ``dbs`` and ``ԁbs`` (Cyrillic ``ԁ``) score 0.

        Args:
            a: First string.
            b: Second string.

        Returns:
            Confusable-normalised Levenshtein distance.
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
            return "".join(repl.get(ch, ch) for ch in x.lower())

        return HeuristicUtils.levenshtein(skel(a), skel(b))

    @staticmethod
    def registrable(host: str) -> str:
        """Return the eTLD+1 registrable domain for ``host``.

        Args:
            host: Bare hostname (e.g. ``sub.example.co.uk``).

        Returns:
            The registrable domain (e.g. ``example.co.uk``), or ``host``
            itself if tldextract cannot determine a suffix.
        """
        ext: tldextract.ExtractResult = tldextract.extract(host)
        return ".".join(p for p in [ext.domain, ext.suffix] if p) or host

    @staticmethod
    def domain_belongs_to_brand(host: str, brand: Any) -> bool:
        """Return ``True`` if ``host`` resolves to one of ``brand``'s known domains.

        Compares the eTLD+1 of ``host`` against the eTLD+1 of each entry in
        ``brand.canonical_domains``.

        Args:
            host: Hostname to check.
            brand: A ``Brand`` config object with a ``canonical_domains`` list.

        Returns:
            ``True`` if the host's registrable domain matches any of the
            brand's registered domains.
        """
        regs: list[str] = [HeuristicUtils.registrable(h.lower()) for h in brand.canonical_domains]
        hreg: str = HeuristicUtils.registrable(host.lower())
        return hreg in regs


# ---------- Abstract base ----------

class HeuristicBase:
    """Abstract base class for all domain-evaluation heuristics.

    Attributes:
        name: Short identifier embedded in ``HeuristicResults`` and log output.
        weight: Suspicion weight added to the score tally when ``suspicious=True``.
            Valid values: 1 (weak), 2 (moderate), 3 (strong).  Irrelevant for
            definitively-benign or definitively-scam results.
    """

    name: str = "heuristic"
    weight: int = 1

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Evaluate this heuristic against the given domain context.

        Args:
            ctx: Fully assembled ``DomainContext`` for the domain under review.

        Returns:
            A ``HeuristicResults`` describing the verdict for this heuristic.

        Raises:
            NotImplementedError: Concrete subclasses must override this method.
        """
        raise NotImplementedError


# ---------- Definitively-Benign heuristics ----------

class InactiveHeuristic(HeuristicBase):
    """Route domains that are unreachable or have no DNS records to BENIGN.

    An inactive domain cannot actively phish users, so it is classified as
    definitively benign to short-circuit further processing.
    """

    name: str = "inactive_domain"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return definitively-benign if HTTP fetch failed or DNS has no records.

        Args:
            ctx: Domain context.

        Returns:
            Definitively-benign result for inactive domains, or neutral otherwise.
        """
        pri: FetchResult = ctx.fetches.primary
        if pri and not (200 <= pri.status < 300):
            return _benign(self.name, f"http_status={pri.status}")
        if ctx.dns and not (ctx.dns.a_records or ctx.dns.aaaa_records) and not (ctx.dns.mx or ctx.dns.ns):
            return _benign(self.name, "dns_no_records")
        return _neutral(self.name)


class ParkingHeuristic(HeuristicBase):
    """Detect parked or for-sale domain pages and route them to BENIGN.

    Parked domains serve placeholder pages and pose no immediate phishing
    threat.  Detection uses configurable HTML signature strings and known
    parking-platform server headers.
    """

    name: str = "parking_detect"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return definitively-benign if parking signatures or headers are detected.

        Args:
            ctx: Domain context.

        Returns:
            Definitively-benign result for parked domains, or neutral otherwise.
        """
        pri: FetchResult = ctx.fetches.primary
        text: str = (pri.html or "").lower()
        headers: dict[str, str] = pri.headers
        sig_hit: bool = any(sig in text for sig in CONFIG.processor.parking_signatures)
        server: str = headers.get("server", "").lower()
        powered: str = headers.get("x-powered-by", "").lower()
        parked_server: bool = any(x in server for x in ["parking", "bodis", "sedo"]) or "parking" in powered
        if sig_hit or parked_server:
            return _benign(self.name, "parking_signature")
        return _neutral(self.name)


class LongLivedVerifiedHeuristic(HeuristicBase):
    """Route domains with OV/EV certificates or enforced HSTS to BENIGN.

    OV/EV certificates require verified organisational identity; HSTS signals
    a mature security posture.  Either signal is sufficient to classify the
    domain as definitively non-threatening.
    """

    name: str = "long_lived_or_verified"

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return definitively-benign for OV/EV-certified or HSTS-enforcing domains.

        Args:
            ctx: Domain context.

        Returns:
            Definitively-benign result when OV/EV cert or HSTS is present,
            or neutral otherwise.
        """
        pri: FetchResult = ctx.fetches.primary
        cert: Optional[CertInfo] = ctx.cert
        if cert and cert.org and not cert.error:
            return _benign(self.name, f"ov_ev_cert_org={cert.org}")
        if pri and "strict-transport-security" in pri.headers:
            return _benign(self.name, "hsts_present")
        return _neutral(self.name)


# ---------- Definitively-Scam heuristics ----------

class FormsExfilHeuristic(HeuristicBase):
    """Detect credential capture paired with a confirmed data-exfiltration channel.

    When a page contains a password or credit-card field **and** actively
    exfiltrates to an attacker-controlled endpoint (Telegram bot, Discord
    webhook, or a cross-domain form POST), the combination is treated as an
    unambiguous phishing pipeline.

    Partial matches — credential fields without confirmed exfil, or obfuscation
    and wallet-hook patterns alone — are treated as suspicious (weight 3) rather
    than definitively scam.
    """

    name: str = "forms_and_exfil"
    weight: int = 3

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Classify domains with active credential-capture-and-exfil pipelines.

        Returns ``is_scam_definitive=True`` when credential fields co-occur with
        a confirmed exfiltration channel.  Returns ``suspicious=True`` (weight 3)
        for partial matches.  Returns neutral when no signals are detected.

        Args:
            ctx: Domain context.

        Returns:
            A definitively-scam, suspicious, or neutral ``HeuristicResults``.
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

        has_credential_field: bool = has_password or has_cc
        has_confirmed_exfil: bool = exfil or cross_domain_post

        evidence: str = (
            f"password={has_password},otp={has_otp},cc={has_cc},"
            f"cross_post={cross_domain_post},exfil={exfil},"
            f"js_obf={js_obf or high_entropy},wallet={wallet_hooks},clipboard={clipboard_hijack}"
        )

        # Definitive: active credential-capture form + confirmed exfil channel
        if has_credential_field and has_confirmed_exfil:
            return _scam(self.name, evidence)

        # Suspicious: credential fields or obfuscation/wallet signals present without confirmed exfil
        if any((has_password, has_otp, has_cc, js_obf, high_entropy, wallet_hooks, clipboard_hijack)):
            return _suspicious(self.name, evidence)

        return _neutral(self.name)

    def _find_credential_payment_indicators(self, html: str) -> Tuple[bool, bool, bool]:
        """Scan HTML for password fields, OTP references, and credit-card inputs.

        Args:
            html: Raw HTML content.

        Returns:
            A three-tuple ``(has_password, has_otp, has_cc)``.
        """
        has_pwd: bool = bool(re.search(r'type=["\']?password["\']?', html, flags=re.IGNORECASE))
        has_otp: bool = bool(re.search(r"(2fa|otp|one[-\s]?time)", html, flags=re.IGNORECASE))
        has_cc: bool = bool(re.search(r"(card number|ccnum|cvv|cvc)", html, flags=re.IGNORECASE))
        return has_pwd, has_otp, has_cc

    def _has_cross_domain_post(self, html: str, host: str) -> bool:
        """Check whether any HTML form submits to a different hostname.

        Args:
            html: Raw HTML content.
            host: The current domain's hostname for comparison.

        Returns:
            ``True`` if a ``<form action>`` points to a host other than ``host``.
        """
        actions: list[str] = re.findall(r"<form[^>]*action=[\"']?([^\"'>\s]+)", html, flags=re.IGNORECASE)
        for act in actions:
            act_host = HTTPClient.normalize_host(act) if "://" in act else host
            if act_host and host and act_host != host and not act.startswith("#"):
                return True
        return False

    def _has_exfil_endpoints(self, html: str) -> bool:
        """Detect known data-exfiltration channels in HTML content.

        Checks for mailto links, PHP mailers, Telegram bots, and Discord
        webhooks — common vectors for sending stolen credentials.

        Args:
            html: Raw HTML content.

        Returns:
            ``True`` if any exfiltration pattern is found.
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
        """Detect JavaScript obfuscation via known API calls and high-entropy strings.

        Args:
            html: Raw HTML content.

        Returns:
            A two-tuple ``(has_obfuscation_calls, has_high_entropy_chunks)``.
        """
        js_obf: bool = bool(self.JS_OBFUSCATION_REGEX.search(html))
        high_entropy: bool = any(
            len(s) > 64 and HeuristicUtils.looks_base64(s)
            for s in re.findall(r"[A-Za-z0-9+/=]{40,}", html)
        )
        return js_obf, high_entropy

    WALLET_HOOKS_REGEX = re.compile(r"(window\.ethereum|eth_requestAccounts|web3|eth_sign|walletconnect)")

    def _has_wallet_hooks(self, html: str) -> bool:
        """Detect Web3 wallet-connection APIs indicative of crypto-drainer scams.

        Args:
            html: Raw HTML content.

        Returns:
            ``True`` if any Web3 wallet hook is present.
        """
        return bool(self.WALLET_HOOKS_REGEX.search(html))

    REPLACEMENT_REGEX = re.compile(r"(replace|execCommand|writeText)")

    def _has_clipboard_hijack(self, html: str) -> bool:
        """Detect clipboard-hijacking patterns used in crypto-address substitution.

        Args:
            html: Raw HTML content.

        Returns:
            ``True`` if clipboard-manipulation signals are present.
        """
        return "clipboard" in html.lower() and bool(self.REPLACEMENT_REGEX.search(html))


class PhishingKitHeuristic(HeuristicBase):
    """Detect phishing-kit signatures and known kit URL path patterns.

    An explicit kit-author comment in the HTML (``phishing kit by <name>``,
    ``tg://``) is treated as definitively scam — this text has no legitimate
    use on a real website.  URL path hits alone (``/owa``, ``/webmail``) are
    treated as suspicious (weight 2) since those paths also appear on
    legitimate mail servers.
    """

    name: str = "phishing_kit"
    weight: int = 2

    KIT_COMMENT_REGEX = re.compile(r"(phishing kit|by .* phisher|tg://|t\.me/)", re.IGNORECASE)

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Classify domains with phishing-kit fingerprints.

        Returns ``is_scam_definitive=True`` for in-HTML kit-author comments.
        Returns ``suspicious=True`` (weight 2) for URL path hits only.
        Returns neutral when neither is detected.

        Args:
            ctx: Domain context.

        Returns:
            A definitively-scam, suspicious, or neutral ``HeuristicResults``.
        """
        pri: FetchResult = ctx.fetches.primary
        html: str = pri.html.lower()
        path_hit: bool = any(p in pri.final_url.lower() for p in CONFIG.processor.kit_paths)
        kit_comment: bool = bool(self.KIT_COMMENT_REGEX.search(html))

        if kit_comment:
            return _scam(self.name, f"kit_comment=True,path_hit={path_hit}")
        if path_hit:
            return _suspicious(self.name, "path_hit=True")
        return _neutral(self.name)


# ---------- Suspicious — Weight 3 ----------

class BrandLookalikeHeuristic(HeuristicBase):
    """Detect typosquatted or visually similar domains targeting known brands.

    Uses confusable-aware Levenshtein distance to compare the domain against
    each configured brand name and its known valid domains.  A distance ≤ 10
    indicates a plausible lookalike.
    """

    name: str = "brand_lookalike"
    weight: int = 3

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if the domain is a close confusable match to a brand.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 3) if the minimum confusable distance to
            any brand name or domain is ≤ 10, or neutral otherwise.
        """
        host: str = HeuristicUtils.to_ascii(ctx.host or "")
        registrable: str = ctx.registrable or host

        best_hit: Optional[Dict[str, Any]] = None
        min_dist: int = 999
        for brand in CONFIG.brands:
            name: str = brand.name.lower()
            domains: list[str] = [d.lower() for d in brand.canonical_domains]
            candidates: list[str] = [host.lower(), registrable.lower()]
            for cand in candidates:
                if name:
                    d: int = HeuristicUtils.confusable_distance(cand, name)
                    if d < min_dist:
                        min_dist = d
                        best_hit = {"type": "name", "target": name}
                for bd in domains:
                    bd_host: str = bd.split(".")[0]
                    d = HeuristicUtils.confusable_distance(cand.split(".")[0], bd_host)
                    if d < min_dist:
                        min_dist = d
                        best_hit = {"type": "domain", "target": bd_host}

        if best_hit and min_dist <= CONFIG.processor.thresholds.lookalike_max_distance:
            return _suspicious(self.name, f"lookalike_to_{best_hit['type']}:{best_hit['target']},dist={min_dist}")
        return _neutral(self.name)


# ---------- Suspicious — Weight 2 ----------

class PunycodeHeuristic(HeuristicBase):
    """Detect Punycode-encoded internationalised domain names.

    IDN homograph attacks use Unicode characters that visually resemble ASCII
    letters.  A Punycode label (``xn--``) is a strong phishing indicator and
    almost never appears in legitimate consumer-facing domains.
    """

    name: str = "punycode"
    weight: int = 2

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if any domain label is Punycode-encoded.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 2) if Punycode is detected, or neutral
            otherwise.
        """
        host: str = HeuristicUtils.to_ascii(ctx.host or "")
        if host.startswith("xn--") or ".xn--" in host:
            return _suspicious(self.name, "punycode_label_detected")
        return _neutral(self.name)


class ForbiddenTokensHeuristic(HeuristicBase):
    """Detect brand-sensitive or high-risk tokens in the hostname and page content.

    Tokens are sourced from ``config.yaml`` under ``processor.suspicious_content_tokens``.
    A token hit in the hostname is more significant than a content hit, but either
    fires the heuristic.
    """

    name: str = "forbidden_tokens"
    weight: int = 2

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if forbidden keyword tokens are found in host or HTML.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 2) if any token matches, or neutral
            otherwise.
        """
        pri: FetchResult = ctx.fetches.primary
        text: str = (pri.html or "").lower()
        host: str = (ctx.host or "").lower()
        tokens: list[str] = CONFIG.processor.suspicious_content_tokens
        host_hit: bool = any(tok in host for tok in tokens)
        content_hit: bool = any(tok in text for tok in tokens)
        if host_hit or content_hit:
            return _suspicious(self.name, f"host_hit={host_hit},content_hit={content_hit}")
        return _neutral(self.name)


class RedirectCloakingHeuristic(HeuristicBase):
    """Detect multi-hop redirect chains and User-Agent-based content cloaking.

    Multi-hop redirects suggest an evasion chain.  Significant content divergence
    between the desktop and mobile fetches is a stronger indicator of cloaking,
    where bots see a benign page while users see the phishing page.
    """

    name: str = "redirect_and_cloaking"
    weight: int = 2

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if multi-hop redirects or UA-based cloaking is detected.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 2) if redirect depth ≥ 2 or content
            divergence between User-Agents exceeds 50%, or neutral otherwise.
        """
        pri: FetchResult = ctx.fetches.primary
        alt: FetchResult = ctx.fetches.alternative
        t = CONFIG.processor.thresholds
        multi_redirect: bool = len(pri.history) >= t.redirect_min_hops
        diff_ratio: float = HeuristicUtils.content_diff_ratio(pri.html, alt.html)
        cloaking: bool = diff_ratio > t.cloaking_diff_ratio and (len(pri.html) > t.cloaking_min_content_len or len(alt.html) > t.cloaking_min_content_len)
        if multi_redirect or cloaking:
            return _suspicious(self.name, f"redirects={pri.history},ua_diff_ratio={diff_ratio:.2f}")
        return _neutral(self.name)


class CertAgeHeuristic(HeuristicBase):
    """Flag domains with TLS certificates issued within the last 30 days.

    Brand-impersonation domains are typically registered and certificated shortly
    before a phishing campaign.  A fresh certificate on a brand-adjacent domain
    is a moderate suspicious signal.
    """

    name: str = "cert_age"
    weight: int = 2

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if the TLS certificate was issued within 30 days.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 2) if cert age < 30 days, or neutral
            if no cert data is available or cert is older.
        """
        cert: Optional[CertInfo] = ctx.cert
        if not cert or cert.error or not cert.not_before:
            return _neutral(self.name)
        try:
            not_before: datetime = datetime.strptime(cert.not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            age_days: int = (datetime.now(timezone.utc) - not_before).days
            if age_days < CONFIG.processor.thresholds.cert_age_days:
                return _suspicious(self.name, f"cert_age_days={age_days}")
        except (ValueError, OSError):
            pass
        return _neutral(self.name)


class BrandContentDensityHeuristic(HeuristicBase):
    """Detect abnormally high brand-keyword density in page content.

    Legitimate brand websites contain their own brand name at a natural
    frequency.  Phishing pages impersonating a brand often saturate the content
    with brand references to appear credible, resulting in an unusually high
    keyword-to-total-word ratio.
    """

    name: str = "brand_content_density"
    weight: int = 2

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if brand keywords account for more than the configured fraction of page words.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 2) if brand keyword density exceeds the
            threshold on a non-brand domain, or neutral otherwise.
        """
        host: str = (ctx.host or "").lower()

        # Skip if the host already belongs to a known brand domain
        for brand in CONFIG.brands:
            if HeuristicUtils.domain_belongs_to_brand(host, brand):
                return _neutral(self.name)

        html: str = (ctx.fetches.primary.html or "").lower()
        words: list[str] = re.findall(r"\w+", html)
        if not words:
            return _neutral(self.name)

        total: int = len(words)
        brand_keywords: list[str] = []
        for brand in CONFIG.brands:
            brand_keywords.append(brand.name.lower().split()[0])  # first word of brand name
            for vd in brand.canonical_domains:
                ext = tldextract.extract(vd)
                if ext.domain:
                    brand_keywords.append(ext.domain.lower())

        brand_count: int = sum(words.count(kw) for kw in set(brand_keywords))
        density: float = brand_count / total

        if density > CONFIG.processor.thresholds.brand_density_threshold:
            return _suspicious(self.name, f"brand_density={density:.3f},brand_count={brand_count},total_words={total}")
        return _neutral(self.name)


class HttpsLoginHeuristic(HeuristicBase):
    """Flag login pages served over plain HTTP without a redirect to HTTPS.

    Every legitimate login page redirects to HTTPS.  A password field
    accessible over HTTP with no HTTPS redirect is a reliable indicator that
    the page is not a genuine service.
    """

    name: str = "https_login"
    weight: int = 2

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if a password field is present on an HTTP-only page.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 2) if a password field is detected and
            the final URL is served over HTTP, or neutral otherwise.
        """
        pri: FetchResult = ctx.fetches.primary
        has_password: bool = bool(re.search(r'type=["\']?password["\']?', pri.html or "", re.IGNORECASE))
        served_over_http: bool = pri.final_url.startswith("http://")
        if has_password and served_over_http:
            return _suspicious(self.name, f"password_field=True,final_url={pri.final_url}")
        return _neutral(self.name)


# ---------- Suspicious — Weight 1 ----------

class DnsEmailPostureHeuristic(HeuristicBase):
    """Evaluate fast-flux DNS patterns and weak email-authentication configuration.

    Many phishing domains rotate IP addresses rapidly (fast-flux) and omit or
    weaken SPF/DMARC to facilitate spoofed email delivery.  These are weak
    supporting signals — they are common in scam infrastructure but not
    exclusive to it.
    """

    name: str = "dns_email_posture"
    weight: int = 1

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if fast-flux or weak email-auth posture is detected.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 1) if any fast-flux or weak SPF/DMARC
            signals are present, or neutral if DNS data is unavailable or clean.
        """
        info: Optional[DNSInfo] = ctx.dns
        if not info or info.error:
            return _neutral(self.name)

        t = CONFIG.processor.thresholds
        many_a: bool = len(info.a_records) >= t.fast_flux_min_a
        low_ttl: bool = info.ttl_min is not None and info.ttl_min < t.fast_flux_max_ttl
        has_mx: bool = len(info.mx) > 0
        spf_weak: bool = any("+all" in s.lower() or "~all" in s.lower() for s in info.spf)
        dmarc_weak: bool = len(info.dmarc) == 0 or any("p=none" in s.lower() for s in info.dmarc)
        fast_flux: bool = many_a or low_ttl
        weak_email_auth: bool = has_mx and (spf_weak or dmarc_weak)

        if fast_flux or weak_email_auth:
            return _suspicious(
                self.name,
                f"many_a={many_a},low_ttl={low_ttl},has_mx={has_mx},spf_weak={spf_weak},dmarc_weak={dmarc_weak}",
            )
        return _neutral(self.name)


class TlsCertHeuristic(HeuristicBase):
    """Flag TLS certificates whose CN contains a brand name on a non-brand host.

    Attackers sometimes obtain certificates with a brand name in the CN or SAN
    to appear more credible.  When the host does not belong to the brand's
    known domain list, this CN mismatch is a weak suspicious signal.
    """

    name: str = "tls_cert"
    weight: int = 1

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if the cert CN contains a brand name on a non-brand host.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 1) if a brand name appears in the cert CN
            for a non-brand host, or neutral otherwise.
        """
        cert: Optional[CertInfo] = ctx.cert
        if not cert or cert.error:
            return _neutral(self.name)

        host: str = ctx.host or ""
        cn: str = (cert.cn or "").lower()
        brand_names: list[str] = [b.name.lower() for b in CONFIG.brands]

        cn_mismatch: bool = (
            bool(cn)
            and any(b in cn for b in brand_names)
            and not any(HeuristicUtils.domain_belongs_to_brand(host, b) for b in CONFIG.brands)
        )
        if cn_mismatch:
            return _suspicious(self.name, f"cn_brand_mismatch=True,cn={cert.cn}")
        return _neutral(self.name)


class SubdomainDepthHeuristic(HeuristicBase):
    """Flag domains with three or more subdomain labels.

    Phishing kits frequently embed the target brand name in a deep subdomain
    (e.g. ``login.dbs.secure-auth.com``) to make the URL look legitimate at a
    glance.  Three or more dot-separated labels is a weak but useful signal.
    """

    name: str = "subdomain_depth"
    weight: int = 1

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if the domain has three or more dot-separated labels.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 1) if the hostname has ≥ 3 labels,
            or neutral otherwise.
        """
        host: str = ctx.host or ""
        labels: list[str] = [lbl for lbl in host.split(".") if lbl]
        if len(labels) >= CONFIG.processor.thresholds.subdomain_min_depth:
            return _suspicious(self.name, f"label_count={len(labels)}")
        return _neutral(self.name)


# ---------- Group A — No new I/O (derived from existing fetched data) ----------

class SuspiciousTldHeuristic(HeuristicBase):
    """Flag domains registered under high-abuse top-level domains.

    Free and cheap TLDs (``xyz``, ``tk``, ``ml``, ``cf``, ``ga``, etc.) are
    overwhelmingly used for phishing and malware campaigns.  The list of
    suspicious TLDs is operator-configurable via ``processor.suspicious_tlds``
    in ``config.yaml``.
    """

    name: str = "suspicious_tld"
    weight: int = 2

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if the registrable TLD is in the high-abuse list.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 2) if the TLD is flagged, or neutral
            otherwise.
        """
        ext: tldextract.ExtractResult = tldextract.extract(ctx.host or "")
        tld: str = ext.suffix.lower() if ext.suffix else ""
        if tld in CONFIG.processor.suspicious_tlds:
            return _suspicious(self.name, f"tld={tld}")
        return _neutral(self.name)


class TitleBrandMismatchHeuristic(HeuristicBase):
    """Detect pages whose ``<title>`` contains a brand name the domain does not own.

    Phishing pages frequently copy a brand's page title verbatim to appear
    legitimate.  When the page title mentions a known brand name but the domain
    is not on that brand's canonical domain list, the mismatch is suspicious.
    """

    name: str = "title_brand_mismatch"
    weight: int = 2

    _TITLE_RE: re.Pattern = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if a brand name appears in the page title of a non-brand domain.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 2) on brand/title mismatch, or neutral
            otherwise.
        """
        html: str = ctx.fetches.primary.html or ""
        host: str = ctx.host or ""
        m = self._TITLE_RE.search(html)
        if not m:
            return _neutral(self.name)
        title_lower: str = m.group(1).lower()
        for brand in CONFIG.brands:
            brand_keyword: str = brand.name.lower().split()[0]
            if brand_keyword in title_lower and not HeuristicUtils.domain_belongs_to_brand(host, brand):
                return _suspicious(self.name, f"brand={brand.name!r},title={m.group(1)[:60]!r}")
        return _neutral(self.name)


class MissingSecurityHeadersHeuristic(HeuristicBase):
    """Flag active pages that are missing all three standard security headers.

    Legitimate financial and authentication sites enforce
    ``Content-Security-Policy``, ``X-Frame-Options``, and
    ``X-Content-Type-Options``.  Phishing kits routinely omit all three.
    This heuristic fires only when **all three** are absent (a single missing
    header on an otherwise legitimate site should not penalise it).
    """

    name: str = "missing_security_headers"
    weight: int = 1

    _SECURITY_HEADERS: frozenset = frozenset([
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
    ])

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if all three standard security headers are absent.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 1) when all three security headers are
            missing from the primary response, or neutral otherwise.
        """
        pri: FetchResult = ctx.fetches.primary
        if not pri or pri.status != 200:
            return _neutral(self.name)
        headers: dict = pri.headers
        missing: List[str] = [h for h in self._SECURITY_HEADERS if h not in headers]
        if len(missing) == len(self._SECURITY_HEADERS):
            return _suspicious(self.name, f"missing={sorted(missing)}")
        return _neutral(self.name)


class FreemailMxHeuristic(HeuristicBase):
    """Detect domains whose MX records point to free consumer email providers.

    Legitimate financial brands operate their own mail infrastructure.  An MX
    record pointing to Gmail, Outlook, Yahoo, or similar free email services
    indicates the domain is not professionally managed and is unlikely to be a
    genuine banking property.
    """

    name: str = "freemail_mx"
    weight: int = 1

    _FREEMAIL_PROVIDERS: frozenset = frozenset([
        "google.com", "gmail.com",
        "outlook.com", "hotmail.com", "live.com",
        "yahoo.com", "yahoo.co",
        "protonmail.com", "icloud.com",
    ])

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if any MX record resolves to a free email provider.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 1) if a freemail MX is detected, or
            neutral if DNS data is unavailable or no freemail MX is found.
        """
        info: Optional[DNSInfo] = ctx.dns
        if not info or info.error or not info.mx:
            return _neutral(self.name)
        for mx in info.mx:
            mx_lower: str = mx.lower().rstrip(".")
            if any(provider in mx_lower for provider in self._FREEMAIL_PROVIDERS):
                return _suspicious(self.name, f"freemail_mx={mx}")
        return _neutral(self.name)


# ---------- Group B — New lightweight network calls ----------

class DomainAgeHeuristic(HeuristicBase):
    """Flag newly registered domains (< 30 days old) via RDAP.

    Freshly registered domains are the single strongest predictor of phishing
    campaigns: most phishing sites are live for fewer than 30 days and are
    registered shortly before the campaign launches.  RDAP data is sourced by
    ``get_rdap_info`` in ``src/enricher.py``.
    """

    name: str = "domain_age"
    weight: int = 3

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious (weight 3) if the domain was registered within the configured threshold.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 3) for new domains, or neutral if RDAP
            data is unavailable or the domain is older than the threshold.
        """
        reg = ctx.registration
        if not reg or reg.error or not reg.created:
            return _neutral(self.name)
        created = _parse_iso_date(reg.created)
        if created is None:
            return _neutral(self.name)
        age_days: int = (datetime.now(timezone.utc) - created).days
        if age_days < CONFIG.processor.thresholds.new_domain_days:
            return _suspicious(self.name, f"age_days={age_days}")
        return _neutral(self.name)


class FaviconBrandMismatchHeuristic(HeuristicBase):
    """Detect phishing sites that serve an exact copy of a brand's official favicon.

    Phishing kits frequently copy the target brand's ``favicon.ico`` byte-for-byte.
    When the fetched favicon's SHA-1 matches a hash in
    ``processor.brand_favicon_hashes`` (operator-seeded in ``config.yaml``) and
    the domain is **not** on any brand's canonical domain list, the match is
    treated as a definitive scam signal.
    """

    name: str = "favicon_brand_mismatch"
    weight: int = 3

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return definitively-scam if the favicon SHA-1 matches a known brand favicon
        on a non-brand-owned domain.

        Args:
            ctx: Domain context.

        Returns:
            Definitively-scam result if a brand favicon fingerprint is matched
            on a non-canonical domain, or neutral otherwise.
        """
        fav = ctx.favicon
        if not fav or fav.error or not fav.sha1:
            return _neutral(self.name)
        known_hashes: List[str] = CONFIG.processor.brand_favicon_hashes
        if fav.sha1 not in known_hashes:
            return _neutral(self.name)
        host: str = ctx.host or ""
        for brand in CONFIG.brands:
            if HeuristicUtils.domain_belongs_to_brand(host, brand):
                return _neutral(self.name)
        return _scam(self.name, f"favicon_sha1={fav.sha1}")


class ReverseDnsMismatchHeuristic(HeuristicBase):
    """Flag active domains with no reverse-DNS (PTR) records.

    Legitimate financial services infrastructure invariably has matching
    forward and reverse DNS.  Bulletproof hosters and throwaway campaign
    infrastructure often have no PTR records at all.
    """

    name: str = "reverse_dns_mismatch"
    weight: int = 1

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if no PTR records exist for any resolved A record.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 1) if there are A records but no PTR
            records, or neutral otherwise.
        """
        info: Optional[DNSInfo] = ctx.dns
        if not info or info.error or not info.a_records:
            return _neutral(self.name)
        if not info.ptr_records:
            return _suspicious(self.name, f"no_ptr_for_{len(info.a_records)}_a_records")
        return _neutral(self.name)


# ---------- Group C — Moderate complexity, notable additional value ----------

class BulletproofHostHeuristic(HeuristicBase):
    """Detect domains that CNAME to known bulletproof or abuse-friendly hosting.

    Bulletproof hosting providers (Stark Industries, Serverius, M247, etc.)
    are permissive of abuse complaints and are disproportionately used by
    phishing infrastructure.  CNAME data is sourced by ``get_cname_info``.
    The substring list is operator-configurable via
    ``processor.bulletproof_hosting_substrings`` in ``config.yaml``.
    """

    name: str = "bulletproof_host"
    weight: int = 2

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if any CNAME target matches a bulletproof hosting substring.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 2) if a bulletproof host is detected,
            or neutral otherwise.
        """
        cname_info = ctx.cname
        if not cname_info or cname_info.error or not cname_info.chain:
            return _neutral(self.name)
        bp_substrings: List[str] = CONFIG.processor.bulletproof_hosting_substrings
        for target in cname_info.chain:
            target_lower: str = target.lower()
            for bp in bp_substrings:
                if bp.lower() in target_lower:
                    return _suspicious(self.name, f"cname_target={target!r}")
        return _neutral(self.name)


class CtHistoryHeuristic(HeuristicBase):
    """Detect newly-launched campaign domains via Certificate Transparency history.

    Domains that have issued very few certificates (≤ 2) are likely recent
    campaign creations.  When combined with a young domain age (< 30 days),
    this is a reliable indicator of a freshly-deployed phishing site.
    CT data is sourced by ``get_ct_info`` from ``crt.sh``.
    """

    name: str = "ct_history"
    weight: int = 2

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if very few certs have ever been issued for the domain.

        Fires on ≤ ``ct_few_certs`` certs + domain age < ``new_domain_days``, or
        unconditionally on exactly 1 cert (no age data required).

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 2) for CT-sparse campaign domains, or
            neutral otherwise.
        """
        t = CONFIG.processor.thresholds
        ct = ctx.ct
        if not ct or ct.error or ct.cert_count == 0:
            return _neutral(self.name)
        if ct.cert_count > t.ct_few_certs:
            return _neutral(self.name)

        # Single certificate ever: reliable campaign signal regardless of RDAP age
        if ct.cert_count == 1:
            return _suspicious(self.name, f"cert_count={ct.cert_count}")

        # Remaining (2 .. ct_few_certs): only fire when domain is also newly registered
        reg = ctx.registration
        if reg and not reg.error and reg.created:
            created = _parse_iso_date(reg.created)
            if created is not None:
                age_days: int = (datetime.now(timezone.utc) - created).days
                if age_days < t.new_domain_days:
                    return _suspicious(self.name, f"cert_count={ct.cert_count},age_days={age_days}")

        return _neutral(self.name)


class RobotsTxtHeuristic(HeuristicBase):
    """Flag active, reachable domains that serve no ``robots.txt``.

    Legitimate websites invariably publish a ``robots.txt`` file; phishing kits
    typically do not bother deploying one.  This heuristic fires only when the
    domain is demonstrably active (HTTP 200 + DNS A record) so as not to penalise
    unreachable or parked domains.
    """

    name: str = "no_robots_txt"
    weight: int = 1

    def evaluate(self, ctx: DomainContext) -> HeuristicResults:
        """Return suspicious if the domain is active but has no ``robots.txt``.

        Args:
            ctx: Domain context.

        Returns:
            Suspicious result (weight 1) for active domains without
            ``robots.txt``, or neutral otherwise.
        """
        pri: FetchResult = ctx.fetches.primary
        if not pri or pri.status != 200:
            return _neutral(self.name)
        info: Optional[DNSInfo] = ctx.dns
        if not info or not info.a_records:
            return _neutral(self.name)
        if ctx.robots_txt is None:
            return _suspicious(self.name, "no_robots_txt_on_active_domain")
        return _neutral(self.name)
