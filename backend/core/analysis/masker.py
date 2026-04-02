"""Data masking layer — masks sensitive values before they reach the LLM.

Sensitive data types:
- IPv4/IPv6 addresses → IP_001, IP_002, ...
- Domain names → DOMAIN_001, DOMAIN_002, ...
- Email addresses → EMAIL_001, EMAIL_002, ...
- Hash values (MD5/SHA1/SHA256) → HASH_001, HASH_002, ...
- Hostnames/Computer names → HOST_001, HOST_002, ...
- Usernames/Accounts → USER_001, USER_002, ...
- File paths (configurable) → PATH_001, PATH_002, ...

Mapping is stored in a local JSON file for later demasking.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any


class DataMasker:
    """Masks sensitive forensic data with reversible tokens."""

    def __init__(self, mapping_path: str = "") -> None:
        if not mapping_path:
            mapping_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "masking_map.json",
            )
        self._mapping_path = mapping_path
        self._enabled = False

        # Forward map: original_value -> token
        self._forward: dict[str, str] = {}
        # Reverse map: token -> original_value
        self._reverse: dict[str, str] = {}
        # Counters per type
        self._counters: dict[str, int] = {
            "IP": 0, "DOMAIN": 0, "EMAIL": 0, "HASH": 0,
            "HOST": 0, "USER": 0, "PATH": 0,
        }

        # Patterns for auto-detection
        self._patterns = [
            ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
            ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
            ("HASH", re.compile(r"\b[a-fA-F0-9]{32}\b")),
            ("HASH", re.compile(r"\b[a-fA-F0-9]{40}\b")),
            ("HASH", re.compile(r"\b[a-fA-F0-9]{64}\b")),
        ]

        # User-defined sensitive values (hostnames, usernames, etc.)
        self._sensitive_values: dict[str, str] = {}  # value -> type

        self._load_mapping()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    def add_sensitive_value(self, value: str, value_type: str = "HOST") -> str:
        """Manually register a sensitive value for masking.

        Args:
            value: The sensitive string (e.g., hostname, username)
            value_type: Type prefix (HOST, USER, PATH, etc.)

        Returns:
            The assigned token.
        """
        value_type = value_type.upper()
        if value_type not in self._counters:
            self._counters[value_type] = 0
        self._sensitive_values[value] = value_type
        return self._get_or_create_token(value, value_type)

    def mask(self, data: Any) -> Any:
        """Mask sensitive data in a tool result (dict, list, or string).

        If masking is disabled, returns data unchanged.
        """
        if not self._enabled:
            return data
        result = self._mask_recursive(data)
        self._save_mapping()
        return result

    def _mask_recursive(self, data: Any) -> Any:
        if isinstance(data, str):
            return self._mask_string(data)
        elif isinstance(data, dict):
            return {k: self._mask_recursive(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._mask_recursive(item) for item in data]
        elif isinstance(data, (int, float, bool)) or data is None:
            return data
        else:
            return self._mask_string(str(data))

    def _mask_string(self, text: str) -> str:
        if not text:
            return text

        # 1. Mask user-defined sensitive values (longest first to avoid partial matches)
        for value in sorted(self._sensitive_values.keys(), key=len, reverse=True):
            if value in text:
                vtype = self._sensitive_values[value]
                token = self._get_or_create_token(value, vtype)
                text = text.replace(value, token)

        # 2. Auto-detect and mask patterns
        for ptype, pattern in self._patterns:
            def replacer(match, pt=ptype):
                original = match.group(0)
                # Skip if already a token
                if re.match(r"^[A-Z]+_\d{3,}$", original):
                    return original
                # Skip zero hashes and trivial values
                if pt == "HASH" and original == "0" * len(original):
                    return original
                return self._get_or_create_token(original, pt)
            text = pattern.sub(replacer, text)

        return text

    def _get_or_create_token(self, value: str, value_type: str) -> str:
        if value in self._forward:
            return self._forward[value]
        self._counters[value_type] = self._counters.get(value_type, 0) + 1
        token = f"{value_type}_{self._counters[value_type]:03d}"
        self._forward[value] = token
        self._reverse[token] = value
        return token

    def get_mapping(self) -> dict[str, str]:
        """Get the current token -> original mapping."""
        return dict(self._reverse)

    def get_stats(self) -> dict:
        return {
            "enabled": self._enabled,
            "total_masked_values": len(self._forward),
            "by_type": dict(self._counters),
            "mapping_file": self._mapping_path,
        }

    # ── Persistence ──

    def _save_mapping(self) -> None:
        data = {
            "created": datetime.now(timezone.utc).isoformat(),
            "counters": self._counters,
            "mapping": self._reverse,
            "sensitive_values": self._sensitive_values,
        }
        try:
            with open(self._mapping_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _load_mapping(self) -> None:
        if not os.path.exists(self._mapping_path):
            return
        try:
            with open(self._mapping_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._counters = data.get("counters", self._counters)
            self._reverse = data.get("mapping", {})
            self._forward = {v: k for k, v in self._reverse.items()}
            self._sensitive_values = data.get("sensitive_values", {})
        except (json.JSONDecodeError, KeyError):
            pass

    def reset(self) -> None:
        """Clear all mappings and start fresh."""
        self._forward.clear()
        self._reverse.clear()
        self._sensitive_values.clear()
        self._counters = {k: 0 for k in self._counters}
        if os.path.exists(self._mapping_path):
            os.remove(self._mapping_path)
