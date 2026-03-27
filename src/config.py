"""Strict YAML configuration loader for BrandSentinel.

All configuration is loaded from ``config.yaml`` at import time and exposed
via the module-level ``CONFIG`` singleton.  Every field is mandatory — the
loader raises ``ValueError`` immediately if any key is absent or has the wrong
type, making misconfiguration explicit at startup rather than at runtime.

Typical usage::

    from .config import CONFIG
    threshold = CONFIG.processor.thresholds.scam
"""

from dataclasses import dataclass
from typing import Any, ClassVar, Dict, List, Optional, cast

import os
import yaml


# ---- Strict dataclasses (no defaults; everything must come from YAML) ----

@dataclass
class IngestEnable:
    """Feature flags that control which ingestion sources are active.

    Attributes:
        openphish: Enable the OpenPhish feed source.
        phishtank: Enable the PhishTank feed source.
        urlhaus: Enable the URLhaus feed source.
        certstream: Enable the CertStream CT-log source.
        manual: Enable manual domain import from ``data/manual_domains.txt``.
        certpolska: Enable the CERT Polska (NASK) warning list source.
        phishingdatabase: Enable the Phishing.Database GitHub feed source.
        phishingarmy: Enable the Phishing Army extended blocklist source.
        botvrij: Enable the Botvrij.eu domain IOC feed source.
        digitalside: Enable the DigitalSide Threat-Intel domain feed source.
        urlhaus_country: Enable the URLhaus per-country feed source.
    """

    openphish: bool
    phishtank: bool
    urlhaus: bool
    certstream: bool
    manual: bool
    certpolska: bool
    phishingdatabase: bool
    phishingarmy: bool
    botvrij: bool
    digitalside: bool
    urlhaus_country: bool


@dataclass
class IngestIntervals:
    """Poll intervals (in seconds) for each threat-intelligence ingestion source.

    Attributes:
        openphish: Seconds between OpenPhish feed fetches.
        phishtank: Seconds between PhishTank feed fetches.
        urlhaus: Seconds between URLhaus feed fetches.
        certpolska: Seconds between CERT Polska feed fetches.
        phishingdatabase: Seconds between Phishing.Database fetches.
        phishingarmy: Seconds between Phishing Army feed fetches.
        botvrij: Seconds between Botvrij.eu feed fetches.
        digitalside: Seconds between DigitalSide feed fetches.
        urlhaus_country: Seconds between URLhaus per-country feed cycles.
        manual: Seconds between manual import file polls.
    """

    openphish: int
    phishtank: int
    urlhaus: int
    certpolska: int
    phishingdatabase: int
    phishingarmy: int
    botvrij: int
    digitalside: int
    urlhaus_country: int
    manual: int


@dataclass
class IngestConfig:
    """Top-level ingester configuration.

    Attributes:
        enable: Per-source feature flags.
        urlhaus_country_codes: ISO 3166-1 alpha-2 country codes polled by the
            ``URLhausCountry`` source (e.g. ``["SG", "MY", "TH"]``).
        intervals: Poll intervals in seconds for each ingestion source.
    """

    enable: IngestEnable
    urlhaus_country_codes: List[str]
    intervals: IngestIntervals


@dataclass
class ProcessorThresholds:
    """Numeric thresholds used by the processor's classification logic.

    Attributes:
        scam: Normalised threshold in ``[0, 1]``.  A domain is classified as
            SCAM when ``(sum of fired heuristic weights) / (sum of all
            heuristic weights)`` meets or exceeds this value.  Default in
            ``config.yaml`` is ``0.4``.
        lookalike_max_distance: Maximum confusable-aware edit distance at which
            a domain is considered a brand lookalike (``BrandLookalikeHeuristic``).
        redirect_min_hops: Minimum redirect-chain depth to trigger the cloaking
            heuristic (``RedirectCloakingHeuristic``).
        cloaking_diff_ratio: Minimum Jaccard-dissimilarity between desktop and
            mobile responses to indicate UA cloaking.
        cloaking_min_content_len: Minimum HTML length (either response) required
            before the cloaking ratio is evaluated.
        cert_age_days: TLS certificates newer than this many days are flagged
            as suspicious (``CertAgeHeuristic``).
        brand_density_threshold: Fraction of page words that must be brand
            keywords to trigger ``BrandContentDensityHeuristic``.
        fast_flux_min_a: Minimum number of A records to flag as fast-flux DNS.
        fast_flux_max_ttl: TTL (seconds) below which DNS is considered fast-flux.
        subdomain_min_depth: Minimum dot-separated label count to flag deep
            subdomain abuse (``SubdomainDepthHeuristic``).
        new_domain_days: Domains registered within this many days are flagged
            as newly registered (``DomainAgeHeuristic``, ``CtHistoryHeuristic``).
        ct_few_certs: Domains with at most this many CT certificates are flagged
            as campaign infrastructure (``CtHistoryHeuristic``).
    """

    scam: float
    lookalike_max_distance: int
    redirect_min_hops: int
    cloaking_diff_ratio: float
    cloaking_min_content_len: int
    cert_age_days: int
    brand_density_threshold: float
    fast_flux_min_a: int
    fast_flux_max_ttl: int
    subdomain_min_depth: int
    new_domain_days: int
    ct_few_certs: int


@dataclass
class ProcessorConfig:
    """All processor-stage configuration values.

    Attributes:
        thresholds: Numeric classification thresholds.
        trusted_domain_substrings: Domains whose hostname contains any of these
            strings are silently dropped before heuristic evaluation; they are
            known-good infrastructure.
        auto_scam_substrings: Domains whose hostname contains any of these
            strings are immediately classified as SCAM, bypassing heuristics.
        suspicious_content_tokens: Page-content tokens whose presence raises
            the suspicious score (used by ``ForbiddenTokensHeuristic``).
        parking_signatures: HTML patterns that indicate a parked domain
            (used by ``ParkingHeuristic``).
        kit_paths: URL path fragments indicative of phishing kits
            (used by ``PhishingKitHeuristic``).
        suspicious_tlds: High-abuse top-level domains; presence raises the
            suspicious score (used by ``SuspiciousTldHeuristic``).
        brand_favicon_hashes: SHA-1 hex hashes of known-brand favicons; a match
            on a non-canonical domain triggers a definitive-scam result
            (used by ``FaviconBrandMismatchHeuristic``).
        bulletproof_hosting_substrings: CNAME target substrings that indicate
            bulletproof or abuse-friendly hosting infrastructure
            (used by ``BulletproofHostHeuristic``).
    """

    thresholds: ProcessorThresholds
    trusted_domain_substrings: List[str]
    auto_scam_substrings: List[str]
    suspicious_content_tokens: List[str]
    parking_signatures: List[str]
    kit_paths: List[str]
    suspicious_tlds: List[str]
    brand_favicon_hashes: List[str]
    bulletproof_hosting_substrings: List[str]


@dataclass
class Brand:
    """Configuration for a single monitored brand.

    Attributes:
        name: Human-readable brand name (e.g. ``"DBS Bank"``).
        canonical_domains: The brand's own authoritative hostnames.  Used by
            heuristics to distinguish legitimate infrastructure from impersonators.
        domain_match_keywords: A domain must contain at least one of these
            substrings to pass the Filter stage for this brand.
        domain_exclude_keywords: A domain is routed to IRRELEVANT if it matches
            any of these substrings, even after passing ``domain_match_keywords``.
    """

    name: str
    canonical_domains: List[str]
    domain_match_keywords: List[str]
    domain_exclude_keywords: List[str]


@dataclass
class Config:
    """Root configuration object, loaded once from ``config.yaml``.

    Attributes:
        DEFAULT_PATH: Default path to the configuration file, relative to the
            working directory.
        ingester: Ingestion source feature flags.
        processor: Processor thresholds and keyword lists.
        brands: List of monitored brand definitions.
    """

    DEFAULT_PATH: ClassVar[str] = "config.yaml"

    ingester: IngestConfig
    processor: ProcessorConfig
    brands: List[Brand]

    # ---- Strict loader helpers ----

    @staticmethod
    def _require_dict(d: Dict[str, Any], key: str) -> Dict[str, Any]:
        """Return ``d[key]`` after asserting it is a non-empty mapping.

        Args:
            d: Parent mapping to look up.
            key: Key whose value must be a ``dict``.

        Returns:
            The nested mapping at ``d[key]``.

        Raises:
            ValueError: If ``key`` is absent from ``d`` or its value is not a
                ``dict``.
        """
        if key not in d or not isinstance(d[key], dict):
            raise ValueError(f"Missing or invalid '{key}' section in config.yaml")
        return d[key]

    @staticmethod
    def _require_list(d: Dict[str, Any], key: str) -> List[Any]:
        """Return ``d[key]`` after asserting it is a list.

        Args:
            d: Parent mapping to look up.
            key: Key whose value must be a ``list``.

        Returns:
            The list at ``d[key]``.

        Raises:
            ValueError: If ``key`` is absent from ``d`` or its value is not a
                ``list``.
        """
        if key not in d or not isinstance(d[key], list):
            raise ValueError(f"Missing or invalid list for '{key}' in config.yaml")
        return d[key]

    @staticmethod
    def _require(d: Dict[str, Any], key: str) -> Any:
        """Return ``d[key]``, raising if the key is absent.

        Args:
            d: Mapping to look up.
            key: Required key.

        Returns:
            The value at ``d[key]``.

        Raises:
            ValueError: If ``key`` is not present in ``d``.
        """
        if key not in d:
            raise ValueError(f"Missing '{key}' in config.yaml")
        return d[key]

    @staticmethod
    def load(path: Optional[str] = None) -> "Config":
        """Parse ``config.yaml`` and return a fully populated ``Config``.

        Reads the YAML file at ``path`` (or ``Config.DEFAULT_PATH`` if
        omitted), validates that every required key is present and of the
        correct type, and constructs the nested dataclass hierarchy.

        Args:
            path: Optional override for the config file path.

        Returns:
            A ``Config`` instance populated from the YAML file.

        Raises:
            FileNotFoundError: If the config file does not exist.
            ValueError: If any required key is missing or has an incorrect type.
        """
        cfg_path = path or Config.DEFAULT_PATH
        if not os.path.exists(cfg_path):
            raise FileNotFoundError(f"Config file not found: {cfg_path}")

        with open(cfg_path, "r", encoding="utf-8") as f:
            raw_any: Any = yaml.safe_load(f) or {}
        if not isinstance(raw_any, dict):
            raise ValueError("Top-level YAML structure must be a mapping")
        raw: Dict[str, Any] = cast(Dict[str, Any], raw_any)

        # ---- Ingest config ----
        ingester_raw = Config._require_dict(raw, "ingester")
        enable_raw = Config._require_dict(ingester_raw, "enable")

        enable = IngestEnable(
            openphish=bool(Config._require(enable_raw, "openphish")),
            phishtank=bool(Config._require(enable_raw, "phishtank")),
            urlhaus=bool(Config._require(enable_raw, "urlhaus")),
            certstream=bool(Config._require(enable_raw, "certstream")),
            manual=bool(Config._require(enable_raw, "manual")),
            certpolska=bool(Config._require(enable_raw, "certpolska")),
            phishingdatabase=bool(Config._require(enable_raw, "phishingdatabase")),
            phishingarmy=bool(Config._require(enable_raw, "phishingarmy")),
            botvrij=bool(Config._require(enable_raw, "botvrij")),
            digitalside=bool(Config._require(enable_raw, "digitalside")),
            urlhaus_country=bool(Config._require(enable_raw, "urlhaus_country")),
        )
        country_codes = list(Config._require_list(ingester_raw, "urlhaus_country_codes"))
        intervals_raw = Config._require_dict(ingester_raw, "intervals")
        intervals = IngestIntervals(
            openphish=int(Config._require(intervals_raw, "openphish")),
            phishtank=int(Config._require(intervals_raw, "phishtank")),
            urlhaus=int(Config._require(intervals_raw, "urlhaus")),
            certpolska=int(Config._require(intervals_raw, "certpolska")),
            phishingdatabase=int(Config._require(intervals_raw, "phishingdatabase")),
            phishingarmy=int(Config._require(intervals_raw, "phishingarmy")),
            botvrij=int(Config._require(intervals_raw, "botvrij")),
            digitalside=int(Config._require(intervals_raw, "digitalside")),
            urlhaus_country=int(Config._require(intervals_raw, "urlhaus_country")),
            manual=int(Config._require(intervals_raw, "manual")),
        )
        ingester = IngestConfig(enable=enable, urlhaus_country_codes=country_codes, intervals=intervals)

        # ---- Processor config ----
        processor_raw = Config._require_dict(raw, "processor")
        thresholds_raw = Config._require_dict(processor_raw, "thresholds")

        processor = ProcessorConfig(
            thresholds=ProcessorThresholds(
                scam=float(Config._require(thresholds_raw, "scam")),
                lookalike_max_distance=int(Config._require(thresholds_raw, "lookalike_max_distance")),
                redirect_min_hops=int(Config._require(thresholds_raw, "redirect_min_hops")),
                cloaking_diff_ratio=float(Config._require(thresholds_raw, "cloaking_diff_ratio")),
                cloaking_min_content_len=int(Config._require(thresholds_raw, "cloaking_min_content_len")),
                cert_age_days=int(Config._require(thresholds_raw, "cert_age_days")),
                brand_density_threshold=float(Config._require(thresholds_raw, "brand_density_threshold")),
                fast_flux_min_a=int(Config._require(thresholds_raw, "fast_flux_min_a")),
                fast_flux_max_ttl=int(Config._require(thresholds_raw, "fast_flux_max_ttl")),
                subdomain_min_depth=int(Config._require(thresholds_raw, "subdomain_min_depth")),
                new_domain_days=int(Config._require(thresholds_raw, "new_domain_days")),
                ct_few_certs=int(Config._require(thresholds_raw, "ct_few_certs")),
            ),
            suspicious_content_tokens=list(Config._require_list(processor_raw, "suspicious_content_tokens")),
            parking_signatures=list(Config._require_list(processor_raw, "parking_signatures")),
            kit_paths=list(Config._require_list(processor_raw, "kit_paths")),
            trusted_domain_substrings=list(Config._require_list(processor_raw, "trusted_domain_substrings")),
            auto_scam_substrings=list(Config._require_list(processor_raw, "auto_scam_substrings")),
            suspicious_tlds=list(Config._require_list(processor_raw, "suspicious_tlds")),
            brand_favicon_hashes=list(Config._require_list(processor_raw, "brand_favicon_hashes")),
            bulletproof_hosting_substrings=list(Config._require_list(processor_raw, "bulletproof_hosting_substrings")),
        )

        # ---- Brands ----
        brands_raw = Config._require_list(raw, "brands")
        brands: List[Brand] = []
        for b_any in brands_raw:
            if not isinstance(b_any, dict):
                raise ValueError("Each brand entry must be a mapping")
            b: Dict[str, Any] = cast(Dict[str, Any], b_any)
            name_val: Optional[Any] = b.get("name")
            name: str = str(name_val)
            brands.append(
                Brand(
                    name=name,
                    canonical_domains=list(Config._require_list(b, "canonical_domains")),
                    domain_match_keywords=list(Config._require_list(b, "domain_match_keywords")),
                    domain_exclude_keywords=list(Config._require_list(b, "domain_exclude_keywords")),
                )
            )

        return Config(ingester=ingester, processor=processor, brands=brands)


CONFIG = Config.load()
