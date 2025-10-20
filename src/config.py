from dataclasses import dataclass
from typing import Any, ClassVar, Dict, List, Optional, cast

import os
import yaml


# ---- Strict dataclasses (no defaults; everything must come from YAML) ----

@dataclass
class IngestEnable:
    openphish: bool
    phishtank: bool
    urlhaus: bool
    certstream: bool
    manual: bool


@dataclass
class IngestConfig:
    enable: IngestEnable

@dataclass
class ProcessorThresholds:
    scam: int
    non_scam: int


@dataclass
class ProcessorConfig:
    timeout_s: float
    total_timeout_s: float
    max_content_bytes: int
    thresholds: ProcessorThresholds
    # brand-scoped lists
    whitelist_keywords: List[str]
    blacklist_keywords: List[str]
    # heuristics config
    forbidden_keywords: List[str]
    parking_signatures: List[str]
    kit_paths: List[str]


@dataclass
class Brand:
    name: str
    valid_domains: List[str]
    domain_accept_keywords: List[str]
    domain_reject_keywords: List[str]


@dataclass
class Counter:
    enable: bool
    interval_s: int

@dataclass
class Config:
    DEFAULT_PATH: ClassVar[str] = "config.yaml"

    ingester: IngestConfig
    processor: ProcessorConfig
    brands: List[Brand]
    counter: Counter

    # ---- Strict loader helpers ----
    @staticmethod
    def _require_dict(d: Dict[str, Any], key: str) -> Dict[str, Any]:
        if key not in d or not isinstance(d[key], dict):
            raise ValueError(f"Missing or invalid '{key}' section in config.yaml")
        return d[key]

    @staticmethod
    def _require_list(d: Dict[str, Any], key: str) -> List[Any]:
        if key not in d or not isinstance(d[key], list):
            raise ValueError(f"Missing or invalid list for '{key}' in config.yaml")
        return d[key]

    @staticmethod
    def _require(d: Dict[str, Any], key: str) -> Any:
        if key not in d:
            raise ValueError(f"Missing '{key}' in config.yaml")
        return d[key]

    @staticmethod
    def load(path: Optional[str] = None) -> "Config":
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
        )
        ingester = IngestConfig(enable=enable)

        # ---- Processor config ----
        processor_raw = Config._require_dict(raw, "processor")
        thresholds_raw = Config._require_dict(processor_raw, "thresholds")

        processor = ProcessorConfig(
            timeout_s=float(Config._require(processor_raw, "timeout_s")),
            total_timeout_s=float(Config._require(processor_raw, "total_timeout_s")),
            max_content_bytes=int(Config._require(processor_raw, "max_content_bytes")),
            thresholds=ProcessorThresholds(
                scam=int(Config._require(thresholds_raw, "scam")),
                non_scam=int(Config._require(thresholds_raw, "non_scam")),
            ),
            forbidden_keywords=list(Config._require_list(processor_raw, "forbidden_keywords")),
            parking_signatures=list(Config._require_list(processor_raw, "parking_signatures")),
            kit_paths=list(Config._require_list(processor_raw, "kit_paths")),
            whitelist_keywords=list(Config._require_list(processor_raw, "whitelist_keywords")),
            blacklist_keywords=list(Config._require_list(processor_raw, "blacklist_keywords")),
        )

        # ---- Brands ----
        brands_raw = Config._require_list(raw, "brands")
        brands: List[Brand] = []
        for b_any in brands_raw:
            if not isinstance(b_any, dict):
                raise ValueError("Each brand entry must be a mapping")
            b: Dict[str, Any] = cast(Dict[str, Any], b_any)
            name_val: Optional[Any] = b.get("name")
            name: Optional[str] = None if name_val is None else str(name_val)
            brands.append(
                Brand(
                    name=name,
                    valid_domains=list(Config._require_list(b, "valid_domains")),
                    domain_accept_keywords=list(Config._require_list(b, "domain_accept_keywords")),
                    domain_reject_keywords=list(Config._require_list(b, "domain_reject_keywords")),
                )
            )

        # ---- Counter ----
        counter_raw = Config._require_dict(raw, "counter")
        counter = Counter(
            enable=bool(Config._require(counter_raw, "enable")),
            interval_s=int(Config._require(counter_raw, "interval_s")),
        )

        return Config(ingester=ingester, processor=processor, brands=brands, counter=counter)

CONFIG = Config.load()