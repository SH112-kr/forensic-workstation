"""E01-derived artifact cache builder.

This module is the first stage of making E01 behave like MFDB/KAPE-derived
inputs. It does not parse EVTX/Registry/Prefetch internals yet; it inventories
high-value artifact files inside the image and emits source-attributed records
that can later be handed to specialized parsers.

The default path is intentionally lazy. Older code used global ``**`` patterns
that work on tiny fixtures but can stall on multi-GB E01 images. The lazy target
manifest below borrows KAPE/EZ-tool and AXIOM/MFDB artifact names as the
semantic contract, then resolves them from E01 via exact paths, bounded
directory scans, and user-profile expansion.
"""

from __future__ import annotations

import fnmatch
from typing import Any


LAZY_E01_TARGETS: list[dict[str, Any]] = [
    {
        "target_id": "evtx_core_logs",
        "artifact_type": "EVTX Candidate",
        "mfdb_artifact_name": "Windows Event Logs",
        "kape_tool": "EvtxECmd",
        "lane": "ingress_access",
        "priority": 10,
        "exact_paths": [
            "/c:/Windows/System32/winevt/Logs/Security.evtx",
            "/c:/Windows/System32/winevt/Logs/System.evtx",
            "/c:/Windows/System32/winevt/Logs/Application.evtx",
            "/c:/Windows/System32/winevt/Logs/Windows PowerShell.evtx",
            "/c:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
            "/c:/Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx",
            "/c:/Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
            "/c:/Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
            "/c:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
        ],
    },
    {
        "target_id": "registry_system_hives",
        "artifact_type": "Registry Hive Candidate",
        "mfdb_artifact_name": "Registry",
        "kape_tool": "RECmd",
        "lane": "persistence_cleanup",
        "priority": 20,
        "exact_paths": [
            "/c:/Windows/System32/config/SYSTEM",
            "/c:/Windows/System32/config/SOFTWARE",
            "/c:/Windows/System32/config/SAM",
            "/c:/Windows/System32/config/SECURITY",
            "/c:/Windows/AppCompat/Programs/Amcache.hve",
            "/c:/Windows/System32/sru/SRUDB.dat",
        ],
    },
    {
        "target_id": "registry_user_hives",
        "artifact_type": "User Registry Hive Candidate",
        "mfdb_artifact_name": "Registry",
        "kape_tool": "RECmd",
        "lane": "persistence_cleanup",
        "priority": 21,
        "profile_relative_paths": [
            "NTUSER.DAT",
            "AppData/Local/Microsoft/Windows/UsrClass.dat",
        ],
    },
    {
        "target_id": "prefetch",
        "artifact_type": "Prefetch Candidate",
        "mfdb_artifact_name": "Prefetch Files - Windows 8/10/11",
        "kape_tool": "PECmd",
        "lane": "execution_impact",
        "priority": 30,
        "bounded_globs": [
            {"path": "/c:/Windows/Prefetch", "pattern": "*.pf", "limit": 500},
        ],
    },
    {
        "target_id": "scheduled_tasks",
        "artifact_type": "Scheduled Task Candidate",
        "mfdb_artifact_name": "Scheduled Tasks",
        "kape_tool": "RECmd",
        "lane": "persistence_cleanup",
        "priority": 40,
        "bounded_globs": [
            {"path": "/c:/Windows/System32/Tasks", "pattern": "*", "limit": 500},
        ],
    },
    {
        "target_id": "ntfs_core",
        "artifact_type": "NTFS Metadata Candidate",
        "mfdb_artifact_name": "MFT Entries",
        "kape_tool": "MFTECmd",
        "lane": "execution_impact",
        "priority": 50,
        "exact_paths": [
            "/c:/$MFT",
            "/c:/$LogFile",
            "/c:/$Extend/$UsnJrnl:$J",
        ],
    },
    {
        "target_id": "root_user_content",
        "artifact_type": "Data File Candidate",
        "mfdb_artifact_name": "File System Items",
        "kape_tool": "MFTECmd",
        "lane": "context",
        "priority": 55,
        "bounded_globs": [
            {"path": "/", "pattern": "*.zip", "limit": 100},
            {"path": "/", "pattern": "*.7z", "limit": 100},
            {"path": "/", "pattern": "*.rar", "limit": 100},
            {"path": "/", "pattern": "*.doc", "limit": 100},
            {"path": "/", "pattern": "*.docx", "limit": 100},
            {"path": "/", "pattern": "*.odt", "limit": 100},
            {"path": "/", "pattern": "*.pdf", "limit": 100},
        ],
    },
    {
        "target_id": "data_volume_root_items",
        "artifact_type": "Data Volume Root Item",
        "mfdb_artifact_name": "File System Items",
        "kape_tool": "MFTECmd",
        "lane": "context",
        "priority": 56,
        "bounded_globs": [
            {"path": "/", "pattern": "*", "limit": 500, "include_dirs": True},
        ],
    },
    {
        "target_id": "lnk_recent",
        "artifact_type": "LNK Candidate",
        "mfdb_artifact_name": "LNK Files",
        "kape_tool": "LECmd",
        "lane": "execution_impact",
        "priority": 60,
        "profile_bounded_globs": [
            {"relative_dir": "AppData/Roaming/Microsoft/Windows/Recent", "pattern": "*.lnk", "limit": 200},
        ],
    },
    {
        "target_id": "browser_history",
        "artifact_type": "Browser History Candidate",
        "mfdb_artifact_name": "Chrome Web Visits",
        "kape_tool": "SQLECmd",
        "lane": "ingress_access",
        "priority": 70,
        "profile_relative_paths": [
            "AppData/Local/Google/Chrome/User Data/Default/History",
            "AppData/Local/Microsoft/Edge/User Data/Default/History",
            "AppData/Roaming/Mozilla/Firefox/Profiles",
        ],
    },
    {
        "target_id": "remote_access_teamviewer",
        "artifact_type": "Remote Access Log Candidate",
        "mfdb_artifact_name": "Remote Access Applications",
        "kape_tool": "File System + RECmd",
        "lane": "ingress_access",
        "priority": 72,
        "exact_paths": [
            "/c:/Program Files/TeamViewer/Connections_incoming.txt",
            "/c:/Program Files (x86)/TeamViewer/Connections_incoming.txt",
            "/c:/Program Files/TeamViewer/TeamViewer14_Logfile.log",
            "/c:/Program Files (x86)/TeamViewer/TeamViewer14_Logfile.log",
            "/c:/Program Files/TeamViewer/TeamViewer14_Logfile_OLD.log",
            "/c:/Program Files (x86)/TeamViewer/TeamViewer14_Logfile_OLD.log",
        ],
        "profile_bounded_globs": [
            {"relative_dir": "AppData/Roaming/TeamViewer", "pattern": "*.log", "limit": 50},
            {"relative_dir": "AppData/Roaming/TeamViewer", "pattern": "Connections*.txt", "limit": 50},
        ],
    },
    {
        "target_id": "windows_notifications",
        "artifact_type": "Windows Notification DB Candidate",
        "mfdb_artifact_name": "Windows Notifications",
        "kape_tool": "SQLECmd",
        "lane": "context",
        "priority": 74,
        "profile_relative_paths": [
            "AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db",
            "AppData/Local/Microsoft/Windows/Notifications/appdb.dat",
        ],
    },
    {
        "target_id": "user_downloads_root",
        "artifact_type": "User Download Candidate",
        "mfdb_artifact_name": "File System Items",
        "kape_tool": "MFTECmd",
        "lane": "ingress_access",
        "priority": 76,
        "profile_bounded_globs": [
            {"relative_dir": "Downloads", "pattern": "*", "limit": 200},
        ],
    },
]


HIGH_VALUE_PATTERNS: list[dict[str, str]] = [
    {"artifact_type": "EVTX Candidate", "pattern": "**/Windows/System32/winevt/Logs/*.evtx", "lane": "ingress_access"},
    {"artifact_type": "Prefetch Candidate", "pattern": "**/Windows/Prefetch/*.pf", "lane": "execution_impact"},
    {"artifact_type": "Registry Hive Candidate", "pattern": "**/Windows/System32/config/SYSTEM", "lane": "persistence_cleanup"},
    {"artifact_type": "Registry Hive Candidate", "pattern": "**/Windows/System32/config/SOFTWARE", "lane": "persistence_cleanup"},
    {"artifact_type": "User Registry Hive Candidate", "pattern": "**/Users/*/NTUSER.DAT", "lane": "persistence_cleanup"},
    {"artifact_type": "Scheduled Task Candidate", "pattern": "**/Windows/System32/Tasks/*", "lane": "persistence_cleanup"},
    {"artifact_type": "Browser History Candidate", "pattern": "**/Users/*/AppData/Local/*/*/User Data/*/History", "lane": "ingress_access"},
    {"artifact_type": "LNK Candidate", "pattern": "**/Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk", "lane": "execution_impact"},
    {"artifact_type": "Document Candidate", "pattern": "**/*.docx", "lane": "context"},
    {"artifact_type": "Document Candidate", "pattern": "**/*.doc", "lane": "context"},
    {"artifact_type": "Document Candidate", "pattern": "**/*.odt", "lane": "context"},
    {"artifact_type": "Document Candidate", "pattern": "**/*.pdf", "lane": "context"},
    {"artifact_type": "Archive Candidate", "pattern": "**/*.zip", "lane": "context"},
    {"artifact_type": "Archive Candidate", "pattern": "**/*.7z", "lane": "context"},
    {"artifact_type": "Archive Candidate", "pattern": "**/*.rar", "lane": "context"},
    {"artifact_type": "Ransom Note Candidate", "pattern": "**/*README*.txt", "lane": "execution_impact"},
    {"artifact_type": "Encrypted Extension Candidate", "pattern": "**/*.INC", "lane": "execution_impact"},
    {"artifact_type": "Encrypted Extension Candidate", "pattern": "**/*.locked", "lane": "execution_impact"},
]


def build_e01_artifact_cache(
    e01_connector: Any,
    *,
    source_id: str = "e01",
    temporal_layer: str = "e01_live",
    limit_per_pattern: int = 200,
    extra_patterns: list[dict[str, str]] | None = None,
    include_high_value_patterns: bool = False,
    include_lazy_targets: bool = True,
    user_profile_root: str = "/c:/Users",
) -> dict[str, Any]:
    """Inventory high-value artifact files from an E01 connector."""
    metadata = _safe_metadata(e01_connector)
    records: list[dict[str, Any]] = []
    parser_failures: list[dict[str, Any]] = []

    lazy_specs = LAZY_E01_TARGETS if include_lazy_targets else []
    specs = [*lazy_specs, *(HIGH_VALUE_PATTERNS if include_high_value_patterns else []), *(extra_patterns or [])]
    for spec in specs:
        pattern = spec.get("pattern") or spec.get("target_id") or ""
        try:
            if _is_lazy_spec(spec):
                hits = _resolve_lazy_target(
                    e01_connector,
                    spec,
                    limit_per_pattern=limit_per_pattern,
                    user_profile_root=user_profile_root,
                )
            elif spec.get("exact_path"):
                hits = _find_exact_path(e01_connector, spec["exact_path"])
            else:
                hits = e01_connector.find_files(pattern, limit=limit_per_pattern) or []
        except Exception as exc:  # noqa: BLE001
            parser_failures.append({
                "artifact_type": spec["artifact_type"],
                "pattern": pattern,
                "status": "failed",
                "error": str(exc),
            })
            continue
        for idx, hit in enumerate(hits):
            if hit.get("error"):
                parser_failures.append({
                    "artifact_type": spec["artifact_type"],
                    "pattern": pattern,
                    "status": "failed",
                    "error": hit.get("error", ""),
                })
                continue
            path = str(hit.get("path") or "")
            records.append({
                "schema_version": "fw.e01_artifact_cache.v1",
                "artifact_id": f"{source_id}:{temporal_layer}:{len(records) + 1}",
                "source_id": source_id,
                "temporal_layer": temporal_layer,
                "artifact_type": spec["artifact_type"],
                "timestamp": "",
                "message": path,
                "value": {
                    "internal_path": path,
                    "size": hit.get("size", -1),
                    "lane": spec["lane"],
                    "pattern": pattern,
                    "target_id": spec.get("target_id", ""),
                    "mfdb_artifact_name": spec.get("mfdb_artifact_name", ""),
                    "kape_tool": spec.get("kape_tool", ""),
                    "resolution": hit.get("resolution", ""),
                },
                "source_chain": [{
                    "adapter": "e01_image",
                    "parser": "e01_lazy_artifact_inventory" if _is_lazy_spec(spec) else "e01_artifact_inventory",
                    "source_path": metadata.get("image_path", ""),
                    "hit_id": idx,
                }],
                "parser_status": {"status": "indexed", "error": ""},
                "conflict_flags": [],
            })

    lane_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    for record in records:
        lane = record["value"]["lane"]
        art = record["artifact_type"]
        lane_counts[lane] = lane_counts.get(lane, 0) + 1
        type_counts[art] = type_counts.get(art, 0) + 1

    return {
        "ok": True,
        "source_id": source_id,
        "temporal_layer": temporal_layer,
        "record_count": len(records),
        "records": records,
        "artifact_type_counts": type_counts,
        "lane_counts": lane_counts,
        "parser_failures": parser_failures,
        "notes": [
            "This is an E01 artifact inventory cache, not full EVTX/Registry/Prefetch semantic parsing.",
            "Default mode uses KAPE/MFDB-inspired lazy targets instead of global ** inventory.",
            "Records preserve internal_path so specialized parsers can extract and normalize later.",
            "Use this cache to decide which E01 parsers to run lazily instead of scanning the whole image repeatedly.",
        ],
    }


def _safe_metadata(connector: Any) -> dict[str, Any]:
    try:
        return connector.get_metadata() or {}
    except Exception:
        return {}


def _find_exact_path(connector: Any, internal_path: str) -> list[dict[str, Any]]:
    try:
        info = connector.get_file_info(internal_path)
    except Exception:
        return []
    if info.get("error"):
        return []
    return [{
        "path": info.get("path") or internal_path,
        "is_dir": False,
        "size": info.get("size", -1),
        "resolution": "exact_path",
    }]


def _is_lazy_spec(spec: dict[str, Any]) -> bool:
    return bool(
        spec.get("exact_paths")
        or spec.get("bounded_globs")
        or spec.get("profile_relative_paths")
        or spec.get("profile_bounded_globs")
    )


def _resolve_lazy_target(
    connector: Any,
    spec: dict[str, Any],
    *,
    limit_per_pattern: int,
    user_profile_root: str,
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    seen: set[str] = set()
    roots = _root_prefix_candidates(connector)

    def add_many(items: list[dict[str, Any]]) -> None:
        for item in items:
            if item.get("error"):
                hits.append(item)
                continue
            path = str(item.get("path") or "")
            if not path or path in seen:
                continue
            seen.add(path)
            hits.append(item)

    for path in spec.get("exact_paths", []) or []:
        for candidate in _path_variants(path, roots):
            add_many(_find_exact_path(connector, candidate))

    for glob_spec in spec.get("bounded_globs", []) or []:
        for candidate_dir in _path_variants(glob_spec.get("path", "/"), roots):
            add_many(_find_bounded_glob(
                connector,
                candidate_dir,
                glob_spec.get("pattern", "*"),
                limit=int(glob_spec.get("limit") or limit_per_pattern),
                include_dirs=bool(glob_spec.get("include_dirs", False)),
            ))

    profile_dirs: list[str] = []
    for root in _profile_root_variants(user_profile_root, roots):
        profile_dirs.extend(_list_user_profiles(connector, root))
    profile_dirs = sorted(set(profile_dirs))
    for rel in spec.get("profile_relative_paths", []) or []:
        for profile in profile_dirs:
            add_many(_find_exact_path(connector, _join_internal(profile, rel)))

    for glob_spec in spec.get("profile_bounded_globs", []) or []:
        for profile in profile_dirs:
            add_many(_find_bounded_glob(
                connector,
                _join_internal(profile, glob_spec.get("relative_dir", "")),
                glob_spec.get("pattern", "*"),
                limit=int(glob_spec.get("limit") or limit_per_pattern),
                include_dirs=bool(glob_spec.get("include_dirs", False)),
            ))

    return hits


def _find_bounded_glob(
    connector: Any,
    internal_dir: str,
    pattern: str,
    *,
    limit: int,
    include_dirs: bool = False,
) -> list[dict[str, Any]]:
    try:
        entries = connector.list_directory(internal_dir) or []
        hits = []
        for entry in entries:
            if entry.get("error") or (entry.get("is_dir") and not include_dirs):
                continue
            name = str(entry.get("name") or "")
            if fnmatch.fnmatchcase(name.lower(), pattern.lower()):
                item = dict(entry)
                item.setdefault("resolution", "bounded_directory")
                hits.append(item)
                if len(hits) >= limit:
                    break
    except Exception as exc:  # noqa: BLE001
        return [{"error": str(exc)}]
    return hits


def _list_user_profiles(connector: Any, user_profile_root: str) -> list[str]:
    try:
        entries = connector.list_directory(user_profile_root) or []
    except Exception:
        return []
    profiles: list[str] = []
    for entry in entries:
        if entry.get("error") or not entry.get("is_dir"):
            continue
        name = str(entry.get("name") or "").lower()
        if name in {"all users", "default", "default user", "public"}:
            continue
        path = str(entry.get("path") or "")
        if path:
            profiles.append(path)
    return profiles


def _root_prefix_candidates(connector: Any) -> list[str]:
    try:
        entries = connector.list_directory("/") or []
    except Exception:
        return ["/c:"]
    names = {str(e.get("name") or "").lower() for e in entries if not e.get("error")}
    roots = []
    if "c:" in names:
        roots.append("/c:")
    if "windows" in names or "$mft" in names:
        roots.append("")
    # Keep /c: as a final fallback for test doubles that do not expose root.
    if "/c:" not in roots:
        roots.append("/c:")
    return roots


def _path_variants(path: str, roots: list[str]) -> list[str]:
    normalized = path.replace("\\", "/")
    variants = []
    if normalized.startswith("/c:/"):
        suffix = normalized[len("/c:"):]
        for root in roots:
            variants.append(f"{root}{suffix}" if root else suffix)
    elif normalized == "/c:":
        variants.extend(root or "/" for root in roots)
    else:
        variants.append(normalized)
    out = []
    seen = set()
    for item in variants:
        clean = item or "/"
        if clean not in seen:
            out.append(clean)
            seen.add(clean)
    return out


def _profile_root_variants(user_profile_root: str, roots: list[str]) -> list[str]:
    variants = _path_variants(user_profile_root, roots)
    for base in ["/Users", "/Documents and Settings"]:
        for root in roots:
            candidate = f"{root}{base}" if root else base
            if candidate not in variants:
                variants.append(candidate)
    return variants


def _join_internal(base: str, rel: str) -> str:
    clean_rel = rel.replace("\\", "/").lstrip("/")
    return f"{base.rstrip('/')}/{clean_rel}"
