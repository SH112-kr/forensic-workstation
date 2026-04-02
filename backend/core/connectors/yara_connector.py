"""YARA scanning connector."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from connectors.base import BaseConnector


class YaraConnector(BaseConnector):
    """YARA rule-based file/memory scanning."""

    def __init__(self) -> None:
        self._rules = None
        self._rules_path: str = ""
        self._rule_count: int = 0

    def connect(self, path: str, **kwargs: Any) -> dict:
        """Load YARA rules from a file or directory.

        Args:
            path: Path to .yar/.yara file or directory of rules
        """
        import yara

        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"YARA rules not found: {path}")

        if p.is_dir():
            filepaths = {}
            for i, f in enumerate(sorted(p.rglob("*.yar*"))):
                filepaths[f"rule_{i}"] = str(f)
            if not filepaths:
                raise ValueError(f"No .yar/.yara files found in {path}")
            self._rules = yara.compile(filepaths=filepaths)
            self._rule_count = len(filepaths)
        else:
            self._rules = yara.compile(filepath=str(p))
            self._rule_count = 1

        self._rules_path = path
        return {
            "status": "success",
            "rules_path": path,
            "rule_files_loaded": self._rule_count,
        }

    def disconnect(self) -> None:
        self._rules = None
        self._rule_count = 0

    def is_connected(self) -> bool:
        return self._rules is not None

    def get_metadata(self) -> dict:
        return {"rules_path": self._rules_path, "rule_files": self._rule_count}

    def search(self, keyword: str = "", filters: dict | None = None,
               limit: int = 50, offset: int = 0) -> dict:
        return {"error": "Use yara_scan_file or yara_scan_directory instead."}

    def get_capabilities(self) -> list[str]:
        return ["scan_file", "scan_directory", "scan_data"]

    def scan_file(self, target_path: str) -> list[dict]:
        """Scan a single file against loaded rules."""
        if not self._rules:
            return [{"error": "No rules loaded."}]
        if not os.path.isfile(target_path):
            return [{"error": f"File not found: {target_path}"}]

        matches = self._rules.match(filepath=target_path)
        return self._format_matches(matches, target_path)

    def scan_data(self, data: bytes) -> list[dict]:
        """Scan raw bytes against loaded rules."""
        if not self._rules:
            return [{"error": "No rules loaded."}]
        matches = self._rules.match(data=data)
        return self._format_matches(matches, "(memory)")

    def scan_directory(self, dir_path: str, pattern: str = "*", limit: int = 100) -> list[dict]:
        """Scan all files in a directory."""
        if not self._rules:
            return [{"error": "No rules loaded."}]

        results = []
        p = Path(dir_path)
        if not p.is_dir():
            return [{"error": f"Directory not found: {dir_path}"}]

        for f in sorted(p.rglob(pattern))[:limit]:
            if f.is_file():
                try:
                    matches = self._rules.match(filepath=str(f))
                    if matches:
                        results.extend(self._format_matches(matches, str(f)))
                except Exception as e:
                    results.append({"file": str(f), "error": str(e)})
        return results

    def _format_matches(self, matches, file_path: str) -> list[dict]:
        results = []
        for match in matches:
            strings_found = []
            for s in match.strings:
                for instance in s.instances:
                    strings_found.append({
                        "offset": instance.offset,
                        "identifier": s.identifier,
                        "data": instance.matched_data[:100].hex() if instance.matched_data else "",
                    })
            results.append({
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "meta": dict(match.meta) if match.meta else {},
                "file": file_path,
                "strings_matched": len(strings_found),
                "strings": strings_found[:20],
            })
        return results
