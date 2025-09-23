import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

@dataclass
class IngestEnable:
    crtsh: bool = True
    urlhaus: bool = True
    openphish: bool = True
    urlscan: bool = True
    phishstats: bool = True
    threatfox: bool = True
    otx: bool = False


@dataclass
class IngestIntervals:
    crtsh: int = 60
    urlhaus: int = 300
    openphish: int = 300
    urlscan: int = 120
    phishstats: int = 180
    threatfox: int = 300
    otx: int = 600


@dataclass
class IngestApiKeys:
    otx: str = ""
    urlscan: str = ""


@dataclass
class IngestConfig:
    enable: IngestEnable = field(default_factory=IngestEnable)
    intervals: IngestIntervals = field(default_factory=IngestIntervals)
    api_keys: IngestApiKeys = field(default_factory=IngestApiKeys)


@dataclass
class ProcessorThresholds:
    scam: int = 80
    non_scam: int = -40


@dataclass
class ProcessorConfig:
    timeout_s: float = 8.0
    total_timeout_s: float = 20.0
    max_content_bytes: int = 1_048_576
    thresholds: ProcessorThresholds = field(default_factory=ProcessorThresholds)
    # brand-scoped lists
    whitelist_keywords: List[str] = field(default_factory=list)  # dropped/ignored
    blacklist_keywords: List[str] = field(default_factory=list)  # auto-scam
    # heuristics config
    forbidden_keywords: List[str] = field(default_factory=list)
    parking_signatures: List[str] = field(default_factory=list)
    kit_paths: List[str] = field(default_factory=list)


@dataclass
class Brand:
    name: Optional[str] = None
    domains: List[str] = field(default_factory=list)


@dataclass
class Config:
    DEFAULT_PATH: str = "config.yaml"

    ingester: IngestConfig = field(default_factory=IngestConfig)
    processor: ProcessorConfig = field(default_factory=ProcessorConfig)
    brands: List[Brand] = field(default_factory=list)

    @staticmethod
    def obj_to(dc_cls, data):
        if not isinstance(data, dict):
            return dc_cls()  # type: ignore
        # nested dataclasses
        fields = {k: v for k, v in data.items()}
        inst = dc_cls()  # type: ignore
        for name, value in fields.items():
            if hasattr(getattr(inst, name, None), "__dataclass_fields__"):
                nested_cls = type(getattr(inst, name))
                setattr(inst, name, Config.obj_to(nested_cls, value))
            else:
                setattr(inst, name, value)
        return inst

    @staticmethod
    def load(path: Optional[str] = None) -> "Config":
        cfg_path = path or Config.DEFAULT_PATH
        if not os.path.exists(cfg_path):
            print(f"Config file not found: {cfg_path}")
            return Config()
        with open(cfg_path, "r", encoding="utf-8") as f:
            raw: Dict[str, Any] = yaml.safe_load(f) or {}

        ingester = Config.obj_to(IngestConfig, raw.get("ingester", {}))
        processor = Config.obj_to(ProcessorConfig, raw.get("processor", {}))
        brands = []
        for b in raw.get("brands", []):
            brands.append(Brand(name=b.get("name"), domains=b.get("domains", [])))
        return Config(ingester=ingester, processor=processor, brands=brands)