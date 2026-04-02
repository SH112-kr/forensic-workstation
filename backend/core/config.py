"""Configuration management for Forensic Orchestra MCP."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Config(BaseSettings):
    # API Keys (Phase 4)
    otx_api_key: str = ""
    abuseipdb_api_key: str = ""

    # Tool paths (Phase 5)
    hayabusa_path: str = "hayabusa"
    chainsaw_path: str = "chainsaw"

    # Ghidra (Phase 2)
    ghidra_install_dir: str = ""

    # YARA (Phase 3)
    yara_rules_path: str = ""

    # Limits — centralized caps for all search/pagination
    default_limit: int = 50
    max_limit: int = 1000
    search_max_limit: int = 200
    timeline_max_limit: int = 500
    srum_max_limit: int = 200
    correlate_max_limit: int = 200

    model_config = {"env_file": ".env", "env_prefix": "FORENSIC_"}


config = Config()
