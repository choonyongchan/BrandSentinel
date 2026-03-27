"""Processor: applies heuristics to classify a domain and returns a Verdict.

## Classification logic

1. Domains matching ``processor.trusted_domain_substrings`` are silently dropped
   (returns ``None``).
2. Domains matching ``processor.auto_scam_substrings`` are immediately classified
   as ``Verdict.SCAM``.
3. For all other domains a ``DomainContext`` is built and heuristics are
   evaluated in declaration order, stopping as soon as a definitive result
   is returned (lazy evaluation).
4. The first heuristic returning ``is_scam_definitive=True`` → ``Verdict.SCAM``
   immediately; remaining heuristics are not evaluated.
5. The first heuristic returning ``is_benign_definitive=True`` → ``Verdict.BENIGN``
   immediately (only reached if no scam-definitive heuristic fired first).
6. Otherwise a normalised score is computed as
   ``sum(fired weights) / sum(all heuristic weights)`` and compared against
   ``processor.thresholds.scam`` (a float in ``[0, 1]``).  If the score meets
   or exceeds the threshold → ``Verdict.SCAM``, else → ``Verdict.INCONCLUSIVE``.
"""

from typing import Optional

from .config import CONFIG
from .enricher import DomainContext, build_context
from .http_client import HTTPClient
from .verdict import Verdict
from .heuristics import (
    BrandContentDensityHeuristic,
    BrandLookalikeHeuristic,
    BulletproofHostHeuristic,
    CertAgeHeuristic,
    CtHistoryHeuristic,
    DnsEmailPostureHeuristic,
    DomainAgeHeuristic,
    FaviconBrandMismatchHeuristic,
    ForbiddenTokensHeuristic,
    FormsExfilHeuristic,
    FreemailMxHeuristic,
    HeuristicBase,
    HeuristicResults,
    HttpsLoginHeuristic,
    InactiveHeuristic,
    LongLivedVerifiedHeuristic,
    MissingSecurityHeadersHeuristic,
    ParkingHeuristic,
    PhishingKitHeuristic,
    PunycodeHeuristic,
    RedirectCloakingHeuristic,
    ReverseDnsMismatchHeuristic,
    RobotsTxtHeuristic,
    SubdomainDepthHeuristic,
    SuspiciousTldHeuristic,
    TitleBrandMismatchHeuristic,
    TlsCertHeuristic,
)


class Processor:
    """Domain classification engine: applies heuristics and returns a Verdict.

    ``Processor`` is kept as a class (rather than dissolved to module-level
    functions) so that tests can monkeypatch ``Processor.heuristics`` without
    replacing the entire module.

    Attributes:
        scam_threshold: Normalised threshold in ``[0, 1]``.  A domain is
            classified as SCAM when the ratio of fired heuristic weight to
            total possible heuristic weight meets or exceeds this value.
            Sourced from ``processor.thresholds.scam`` in ``config.yaml``.
        heuristics: Ordered list of ``HeuristicBase`` instances evaluated per
            domain.  Evaluated in order; evaluation stops immediately when a
            definitive result is returned.  Scam-definitive heuristics are
            ordered before benign-definitive ones so SCAM takes priority.
    """

    scam_threshold: float = CONFIG.processor.thresholds.scam

    heuristics: list[HeuristicBase] = [
        # Definitively-scam (highest priority — short-circuit to SCAM immediately)
        FormsExfilHeuristic(),
        PhishingKitHeuristic(),
        FaviconBrandMismatchHeuristic(),
        # Definitively-benign (short-circuit to BENIGN)
        InactiveHeuristic(),
        ParkingHeuristic(),
        LongLivedVerifiedHeuristic(),
        # Suspicious — weight 3 (strong)
        BrandLookalikeHeuristic(),
        DomainAgeHeuristic(),
        # Suspicious — weight 2 (moderate)
        PunycodeHeuristic(),
        ForbiddenTokensHeuristic(),
        RedirectCloakingHeuristic(),
        CertAgeHeuristic(),
        BrandContentDensityHeuristic(),
        HttpsLoginHeuristic(),
        SuspiciousTldHeuristic(),
        TitleBrandMismatchHeuristic(),
        BulletproofHostHeuristic(),
        CtHistoryHeuristic(),
        # Suspicious — weight 1 (weak)
        DnsEmailPostureHeuristic(),
        TlsCertHeuristic(),
        SubdomainDepthHeuristic(),
        MissingSecurityHeadersHeuristic(),
        FreemailMxHeuristic(),
        ReverseDnsMismatchHeuristic(),
        RobotsTxtHeuristic(),
    ]

    @staticmethod
    def is_trusted(host: str) -> bool:
        """Return ``True`` if ``host`` matches a trusted-infrastructure substring.

        Trusted domains are silently dropped — ``classify`` returns ``None``
        and the domain is not written to any output file.

        Args:
            host: Normalised bare hostname.

        Returns:
            ``True`` if the host should be skipped entirely.
        """
        wl: list[str] = CONFIG.processor.trusted_domain_substrings or []
        host_l: str = host.lower()
        return any(k for k in wl if k and k.lower() in host_l)

    @staticmethod
    def is_auto_scam(host: str) -> bool:
        """Return ``True`` if ``host`` matches an auto-scam substring.

        Matching domains bypass heuristics and are immediately classified as
        ``Verdict.SCAM``.

        Args:
            host: Normalised bare hostname.

        Returns:
            ``True`` if the host should be auto-classified as SCAM.
        """
        bl: list[str] = CONFIG.processor.auto_scam_substrings or []
        host_l: str = host.lower()
        return any(k for k in bl if k and k.lower() in host_l)

    @staticmethod
    async def classify(domain: str) -> Optional[Verdict]:
        """Classify a single domain and return a ``Verdict`` (or ``None`` if trusted).

        Heuristics are evaluated in declaration order.  Evaluation short-circuits
        as soon as any heuristic returns a definitive result: scam-definitive
        heuristics are ordered first so SCAM always takes priority over BENIGN.

        Args:
            domain: Domain string to classify.

        Returns:
            A ``Verdict`` enum value, or ``None`` for trusted domains
            (which are silently dropped by ``output_task``).
        """
        dom: str = domain.strip()
        host: str = HTTPClient.normalize_host(dom)

        if Processor.is_trusted(host):
            return None

        if Processor.is_auto_scam(host):
            return Verdict.SCAM

        ctx: DomainContext = await build_context(dom)

        total_weight: int = 0
        for h in Processor.heuristics:
            r: HeuristicResults = h.evaluate(ctx)
            if r.is_scam_definitive:
                return Verdict.SCAM
            if r.is_benign_definitive:
                return Verdict.BENIGN
            if r.suspicious:
                total_weight += h.weight
        max_weight: int = sum(h.weight for h in Processor.heuristics)
        score: float = total_weight / max_weight if max_weight > 0 else 0.0
        return Verdict.SCAM if score >= Processor.scam_threshold else Verdict.INCONCLUSIVE
