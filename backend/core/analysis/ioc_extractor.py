"""IOC extraction — SQL-based pattern matching against .mfdb."""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from connectors.axiom_mfdb import AxiomMfdbConnector

PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|tk|ml|ga|cf|gq|pw|"
        r"onion|bit|kr|jp|de|uk|fr|br|in|au|ca|nl|se|ch|es|it|pl|cz|"
        r"me|tv|co|us|eu)\b",
        re.IGNORECASE,
    ),
    "url": re.compile(r"https?://[^\s<>\"'`,\)\]]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
}

KNOWN_GOOD_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
    "google.com", "googleapis.com", "gstatic.com", "gmail.com",
    "apple.com", "icloud.com", "akamai.net", "akamaihd.net",
    "cloudflare.com", "amazonaws.com", "azure.com",
    "github.com", "githubusercontent.com",
    "facebook.com", "fbcdn.net", "youtube.com",
    "adobe.com", "symantec.com", "digicert.com",
    "letsencrypt.org", "verisign.com",
}

# SQL LIKE patterns to pre-filter candidate strings
SQL_FILTERS = {
    "ipv4": ["%.%.%.%"],
    "domain": ["%.com%", "%.net%", "%.org%", "%.io%", "%.ru%", "%.cn%", "%.kr%",
               "%.xyz%", "%.onion%", "%.top%", "%.info%", "%.biz%"],
    "url": ["http://%", "https://%"],
    "email": ["%@%.%"],
}


def _is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def _is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def _is_known_good(domain: str) -> bool:
    domain = domain.lower()
    for d in KNOWN_GOOD_DOMAINS:
        if domain == d or domain.endswith("." + d):
            return True
    return False


def extract_iocs(
    connector: AxiomMfdbConnector,
    ioc_types: str = "",
    exclude_private: bool = True,
    exclude_known_good: bool = True,
) -> dict:
    """Extract IOCs using SQL pre-filtering + regex validation."""
    requested = set()
    if ioc_types:
        requested = {t.strip().lower() for t in ioc_types.split(",") if t.strip()}
        # Aliases
        if "ip" in requested:
            requested.add("ipv4")
        if "hash" in requested or "hashes" in requested:
            requested.update({"md5", "sha1", "sha256"})

    ioc_map: dict[tuple[str, str], dict] = {}

    # 1. Hash IOCs from hit_hash table (direct, no regex needed)
    if not requested or requested & {"hash", "hashes", "md5", "sha1", "sha256"}:
        hashes = connector.get_all_hashes(limit=2000)
        for h in hashes:
            val = h["hash"].lower()
            if not val or val == "0" * len(val):
                continue
            if len(val) == 32:
                ht = "md5"
            elif len(val) == 40:
                ht = "sha1"
            elif len(val) == 64:
                ht = "sha256"
            else:
                continue
            key = (ht, val)
            if key not in ioc_map:
                ioc_map[key] = {
                    "ioc_type": ht, "value": val, "count": 0,
                    "source_artifact_types": set(),
                }
            ioc_map[key]["count"] += 1
            ioc_map[key]["source_artifact_types"].add(h.get("artifact_type", ""))

    # 2. String-based IOCs (IP, domain, URL, email)
    for ioc_type, regex in PATTERNS.items():
        if requested and ioc_type not in requested:
            continue

        sql_patterns = SQL_FILTERS.get(ioc_type, [])
        for sql_pat in sql_patterns:
            rows = connector.search_string_values(sql_pat, limit=5000)
            for row in rows:
                value = row["value"]
                if not value:
                    continue
                matches = regex.findall(value)
                for match in matches:
                    match = match.strip().rstrip(".,;:)")

                    if ioc_type == "ipv4":
                        if not _is_valid_ip(match):
                            continue
                        if exclude_private and _is_private_ip(match):
                            continue
                    elif ioc_type == "domain":
                        if exclude_known_good and _is_known_good(match):
                            continue

                    key = (ioc_type, match.lower())
                    if key not in ioc_map:
                        ioc_map[key] = {
                            "ioc_type": ioc_type, "value": match, "count": 0,
                            "source_artifact_types": set(),
                        }
                    ioc_map[key]["count"] += 1

    # Format results
    results = []
    for entry in sorted(ioc_map.values(), key=lambda x: x["count"], reverse=True):
        results.append({
            "ioc_type": entry["ioc_type"],
            "value": entry["value"],
            "count": entry["count"],
            "source_artifact_types": sorted(entry["source_artifact_types"]) if isinstance(entry["source_artifact_types"], set) else entry["source_artifact_types"],
        })

    summary = {}
    for r in results:
        t = r["ioc_type"]
        summary[t] = summary.get(t, 0) + 1

    return {
        "total_iocs": len(results),
        "by_type": summary,
        "iocs": results[:500],
        "truncated": len(results) > 500,
    }
