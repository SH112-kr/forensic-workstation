"""E01 image connector — mount and extract files from forensic disk images via dissect."""

from __future__ import annotations

import hashlib
import fnmatch
import os
import re
import struct
import types
from datetime import datetime, timezone
from typing import Any

from core.connectors.base import BaseConnector


class E01ImageConnector(BaseConnector):
    """Open E01/VM/raw disk images using dissect for file extraction.

    Uses EwfContainer + Target for E01 files to avoid SmartLog interference.
    Falls back to Target.open() for other image formats.
    """

    def __init__(self) -> None:
        self._target = None
        self._fhs: list = []  # Keep file handles alive
        self._path: str = ""
        self._fat_fallback = None
        self._vss_cache: dict[str, Any] = {}

    def connect(self, path: str, **kwargs: Any) -> dict:
        """Open a disk image (E01, VMDK, raw, etc.)."""
        from dissect.target import Target

        if not os.path.exists(path):
            raise FileNotFoundError(f"Image not found: {path}")

        self._path = path

        if path.lower().endswith((".e01", ".ex01")):
            self._target = self._open_ewf(path)
        else:
            self._target = Target.open(path)
        self._fat_fallback = self._open_fat_fallback()

        return self.get_metadata()

    def _open_ewf(self, path: str) -> "Target":
        """Open EWF/E01 image by manually filtering segments (avoids SmartLog issue)."""
        from dissect.target import Target
        from dissect.target.containers.ewf import EwfContainer

        base_dir = os.path.dirname(path)
        base_name = os.path.splitext(os.path.basename(path))[0]
        base_name_lc = base_name.lower()

        # Collect only valid E0x/Ex01 segments (skip smartlog, etc.)
        segments = []
        for f in sorted(os.listdir(base_dir)):
            if not f.lower().startswith(base_name_lc):
                continue
            ext = os.path.splitext(f)[1].lower()
            # Match .E01-.E99, .EAA+ patterns
            if re.match(r'\.e[0-9a-z]{2}$', ext):
                segments.append(os.path.join(base_dir, f))

        if not segments:
            raise FileNotFoundError(f"No EWF segments found for: {path}")

        self._fhs = [open(s, "rb") for s in segments]
        container = EwfContainer(self._fhs)

        t = Target()
        t.disks.add(container)
        t._os_plugin = None
        t.apply()
        return t

    def disconnect(self) -> None:
        self._target = None
        self._fat_fallback = None
        self._vss_cache = {}
        for fh in self._fhs:
            try:
                fh.close()
            except Exception:
                pass
        self._fhs = []
        self._path = ""

    def is_connected(self) -> bool:
        return self._target is not None

    def get_metadata(self) -> dict:
        t = self._target
        meta: dict[str, Any] = {
            "image_path": self._path,
            "hostname": "",
            "os_type": "",
            "volumes": [],
            "fallback_filesystems": [],
            "root_listing": [],
            "image_format_notes": [],
        }
        ext = os.path.splitext(self._path)[1].lower()
        if ext in {".vmdk", ".vhd", ".vhdx", ".avhd", ".avhdx", ".vdi", ".qcow", ".qcow2", ".hdd", ".hds"}:
            meta["image_format_notes"].append(
                "VM disk images expose guest disk state only; analyze separate memory dumps for RAM state."
            )
        if ext in {".avhd", ".avhdx"}:
            meta["image_format_notes"].append(
                "Hyper-V differencing/checkpoint disks may require the parent chain to represent the intended point in time."
            )
        try:
            meta["hostname"] = str(t.hostname)
        except Exception:
            pass
        try:
            meta["os_type"] = str(t.os)
        except Exception:
            pass
        try:
            for v in t.volumes:
                meta["volumes"].append(str(v))
        except Exception:
            pass
        try:
            for entry in sorted(t.fs.path("/").iterdir()):
                meta["root_listing"].append(str(entry))
                if len(meta["root_listing"]) >= 20:
                    break
        except Exception:
            pass
        if not meta["root_listing"] and self._fat_fallback:
            meta["root_listing"] = [
                item["path"] for item in self._fat_fallback.list_directory("/")[:20]
            ]
        if self._fat_fallback:
            meta["fallback_filesystems"].append(self._fat_fallback.metadata())
        return meta

    def search(self, keyword: str = "", filters: dict | None = None,
               limit: int = 50, offset: int = 0) -> dict:
        """Search filenames by glob pattern."""
        pattern = keyword or (filters or {}).get("pattern", "**/*")
        results = self.find_files(pattern, limit=limit)
        return {"total": len(results), "files": results}

    def list_directory(self, path: str = "/") -> list[dict]:
        """List files and directories at the given internal path."""
        if self._fat_fallback:
            fat_results = self._fat_fallback.list_directory(path)
            if fat_results:
                return fat_results
        p = self._target.fs.path(self._normalize_path(path))
        results = []
        try:
            for entry in sorted(p.iterdir()):
                info: dict[str, Any] = {
                    "name": entry.name,
                    "path": str(entry),
                    "is_dir": entry.is_dir(),
                }
                if not entry.is_dir():
                    try:
                        st = entry.stat()
                        info["size"] = st.st_size
                        info["created"] = _format_fs_ts(
                            getattr(st, "st_birthtime", None) or getattr(st, "st_ctime", None)
                        )
                        info["modified"] = _format_fs_ts(st.st_mtime)
                        info["accessed"] = _format_fs_ts(st.st_atime)
                    except Exception:
                        info["size"] = -1
                results.append(info)
        except Exception as e:
            return [{"error": str(e)}]
        return results

    def find_files(self, pattern: str, path: str = "/", limit: int = 100) -> list[dict]:
        """Glob for files matching a pattern."""
        if self._fat_fallback:
            fat_results = self._fat_fallback.find_files(pattern, path=path, limit=limit)
            if fat_results:
                return fat_results
        base = self._target.fs.path(self._normalize_path(path))
        results = []
        try:
            for entry in base.rglob(pattern):
                info: dict[str, Any] = {
                    "path": str(entry),
                    "is_dir": entry.is_dir(),
                }
                if not entry.is_dir():
                    try:
                        info["size"] = entry.stat().st_size
                    except Exception:
                        info["size"] = -1
                results.append(info)
                if len(results) >= limit:
                    break
        except Exception as e:
            return [{"error": str(e)}]
        return results

    def extract_file(self, internal_path: str, output_path: str) -> dict:
        """Extract a file from the image to local filesystem for STATIC ANALYSIS ONLY.

        WARNING: Extracted files may be malware. They are written with no execute
        permission and must NEVER be executed. Only use with static analysis tools
        like Ghidra.

        Returns dict with output_path, size, and sha256.
        """
        norm = self._normalize_path(internal_path)
        if self._fat_fallback:
            info = self._fat_fallback.get_file_info(norm)
            if not info.get("error"):
                return info
        fp = self._target.fs.path(norm)

        if not fp.exists():
            raise FileNotFoundError(f"File not found in image: {internal_path} (tried {norm})")

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Write warning marker in extraction directory
        warn_path = os.path.join(os.path.dirname(output_path), "_WARNING_MALWARE_DO_NOT_EXECUTE.txt")
        if not os.path.exists(warn_path):
            with open(warn_path, "w", encoding="utf-8") as wf:
                wf.write(
                    "WARNING: This directory contains files extracted from a forensic disk image.\n"
                    "These files may be MALWARE. DO NOT EXECUTE any file in this directory.\n"
                    "Use only static analysis tools (e.g., Ghidra, strings, hex editors).\n"
                )

        sha256 = hashlib.sha256()
        size = 0
        with fp.open("rb") as src, open(output_path, "wb") as dst:
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                dst.write(chunk)
                sha256.update(chunk)
                size += len(chunk)

        # Strip execute permission (Unix/WSL)
        try:
            current = os.stat(output_path).st_mode
            os.chmod(output_path, current & 0o666)  # remove execute bits
        except Exception:
            pass

        return {
            "internal_path": internal_path,
            "output_path": output_path,
            "size": size,
            "sha256": sha256.hexdigest(),
            "execute_allowed": False,
            "warning": "STATIC ANALYSIS ONLY - do not execute this file",
        }

    def read_file_content(self, internal_path: str, max_size: int = 1048576) -> bytes:
        """Read file content from mounted image without extracting to disk."""
        norm = self._normalize_path(internal_path)
        fp = self._target.fs.path(norm)

        if not fp.exists():
            raise FileNotFoundError(f"File not found in image: {internal_path} (tried {norm})")

        data = b""
        with fp.open("rb") as src:
            while len(data) < max_size:
                chunk = src.read(min(65536, max_size - len(data)))
                if not chunk:
                    break
                data += chunk
        return data

    def get_file_info(self, internal_path: str) -> dict:
        """Get file information with full NTFS timestamps.

        Returns creation, modification, access, and MFT change timestamps
        to enable proper forensic timeline analysis. These are critical for
        verifying when a file was actually placed on disk vs. when its
        content was compiled or last used.
        """
        from datetime import datetime, timezone

        norm = self._normalize_path(internal_path)
        fp = self._target.fs.path(norm)
        if not fp.exists():
            return {"error": f"File not found: {internal_path}"}
        try:
            st = fp.stat()
            result: dict[str, Any] = {
                "path": str(fp),
                "size": st.st_size,
            }

            def _fmt_ts(ts) -> str:
                """Format timestamp to ISO string."""
                if ts is None:
                    return ""
                try:
                    if isinstance(ts, (int, float)):
                        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                    else:
                        dt = ts
                    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                except Exception:
                    return str(ts)

            # Standard timestamps
            result["created"] = _fmt_ts(getattr(st, "st_birthtime", None) or getattr(st, "st_ctime", None))
            result["modified"] = _fmt_ts(st.st_mtime)
            result["accessed"] = _fmt_ts(st.st_atime)

            # Try to get NTFS $STANDARD_INFORMATION and $FILE_NAME timestamps
            # via dissect's filesystem layer for deeper forensic accuracy
            try:
                entry = fp.get()
                # dissect NTFS entries expose .stdinfo and .filename attrs
                si = getattr(entry, "stdinfo", None)
                fn = getattr(entry, "filename", None)
                if si:
                    result["$SI_created"] = _fmt_ts(getattr(si, "creation_time", None))
                    result["$SI_modified"] = _fmt_ts(getattr(si, "modification_time", None))
                    result["$SI_mft_modified"] = _fmt_ts(getattr(si, "mft_modification_time", None))
                    result["$SI_accessed"] = _fmt_ts(getattr(si, "access_time", None))
                if fn:
                    result["$FN_created"] = _fmt_ts(getattr(fn, "creation_time", None))
                    result["$FN_modified"] = _fmt_ts(getattr(fn, "modification_time", None))
            except Exception:
                pass  # Not all filesystems support MFT-level access

            return result
        except Exception as e:
            return {"path": str(fp), "error": str(e)}

    def get_capabilities(self) -> list[str]:
        return [
            "search",
            "list_directory",
            "find_files",
            "extract_file",
            "list_vss_snapshots",
            "vss_list_directory",
            "vss_find_files",
            "vss_find_files_with_coverage",
            "vss_extract_file",
            "vss_get_file_info",
        ]

    def list_vss_snapshots(self, volume: str = "/c:") -> dict[str, Any]:
        """List VSS stores on a mounted NTFS volume."""
        try:
            vss, _volume = self._get_vss_for_volume(volume)
        except Exception as e:
            return {
                "ok": False,
                "volume": volume,
                "error": str(e),
                "snapshots": [],
            }
        snapshots = [self._snapshot_metadata(store, volume) for store in vss.catalog.stores]
        return {
            "ok": True,
            "volume": volume,
            "snapshot_count": len(snapshots),
            "snapshots": snapshots,
            "guardrails": _vss_connector_guardrails(),
        }

    def vss_list_directory(self, snapshot_id: str, path: str = "/", volume: str = "/c:") -> list[dict]:
        snapshot, fs = self._get_vss_snapshot_fs(snapshot_id, volume)
        p = fs.path(self._normalize_volume_relative_path(path))
        results = []
        try:
            for entry in sorted(p.iterdir()):
                info: dict[str, Any] = {
                    "name": entry.name,
                    "path": _vss_display_path(volume, str(entry)),
                    "is_dir": entry.is_dir(),
                    "temporal_layer": snapshot["temporal_layer"],
                    "snapshot_id": snapshot["snapshot_id"],
                    "snapshot_creation_time": snapshot["snapshot_creation_time"],
                }
                if not entry.is_dir():
                    try:
                        info["size"] = entry.stat().st_size
                    except Exception:
                        info["size"] = -1
                results.append(info)
        except Exception as e:
            return [{"error": str(e)}]
        return results

    def vss_find_files(
        self,
        snapshot_id: str,
        pattern: str,
        path: str = "/",
        volume: str = "/c:",
        limit: int = 100,
    ) -> list[dict]:
        return self.vss_find_files_with_coverage(
            snapshot_id,
            pattern,
            path=path,
            volume=volume,
            limit=limit,
        )["files"]

    def vss_find_files_with_coverage(
        self,
        snapshot_id: str,
        pattern: str,
        path: str = "/",
        volume: str = "/c:",
        limit: int = 100,
    ) -> dict[str, Any]:
        snapshot, fs = self._get_vss_snapshot_fs(snapshot_id, volume)
        base = fs.path(self._normalize_volume_relative_path(path))
        results = []
        search = self._safe_vss_rglob_with_coverage(base, pattern, limit=limit)
        try:
            for entry in search["matches"]:
                info: dict[str, Any] = {
                    "path": _vss_display_path(volume, str(entry)),
                    "is_dir": entry.is_dir(),
                    "temporal_layer": snapshot["temporal_layer"],
                    "snapshot_id": snapshot["snapshot_id"],
                    "snapshot_creation_time": snapshot["snapshot_creation_time"],
                }
                if not entry.is_dir():
                    try:
                        info["size"] = entry.stat().st_size
                    except Exception:
                        info["size"] = -1
                results.append(info)
                if len(results) >= limit:
                    break
        except Exception as e:
            search["coverage"]["paths_skipped"] += 1
            search["coverage"]["skip_reasons"]["other"] += 1
            search["coverage"]["coverage_gap"] = (
                f"{search['coverage']['paths_skipped']} paths unexamined in snapshot "
                f"{snapshot['snapshot_id']}."
            )
            return {
                "files": [{"error": str(e), **snapshot}],
                "coverage": search["coverage"],
                **snapshot,
            }
        coverage = search["coverage"]
        if coverage.get("paths_skipped", 0):
            coverage["coverage_gap"] = (
                f"{coverage['paths_skipped']} paths unexamined in snapshot "
                f"{snapshot['snapshot_id']}."
            )
        return {
            "files": results,
            "coverage": coverage,
            **snapshot,
        }

    def vss_get_file_info(self, snapshot_id: str, internal_path: str, volume: str = "/c:") -> dict:
        snapshot, fs = self._get_vss_snapshot_fs(snapshot_id, volume)
        norm = self._normalize_volume_relative_path(internal_path)
        fp = fs.path(norm)
        if not fp.exists():
            return {
                "error": f"File not found in VSS snapshot {snapshot['snapshot_id']}: {internal_path}",
                **snapshot,
                "path": _vss_display_path(volume, norm),
            }
        try:
            return {
                **self._file_info_from_path(fp),
                **snapshot,
                "path": _vss_display_path(volume, str(fp)),
            }
        except Exception as e:
            return {
                "path": _vss_display_path(volume, str(fp)),
                "error": str(e),
                **snapshot,
            }

    def vss_extract_file(
        self,
        snapshot_id: str,
        internal_path: str,
        output_path: str,
        volume: str = "/c:",
    ) -> dict:
        """Extract a file from a VSS snapshot for static analysis only."""
        snapshot, fs = self._get_vss_snapshot_fs(snapshot_id, volume)
        norm = self._normalize_volume_relative_path(internal_path)
        fp = fs.path(norm)
        if not fp.exists():
            raise FileNotFoundError(
                f"File not found in VSS snapshot {snapshot['snapshot_id']}: {internal_path}"
            )
        result = self._copy_fs_path_to_output(fp, internal_path, output_path)
        result.update(snapshot)
        result["source"] = "vss_snapshot"
        result["volume"] = volume
        return result

    def vss_read_file_content(
        self,
        snapshot_id: str,
        internal_path: str,
        volume: str = "/c:",
        max_size: int = 1048576,
    ) -> bytes:
        _snapshot, fs = self._get_vss_snapshot_fs(snapshot_id, volume)
        fp = fs.path(self._normalize_volume_relative_path(internal_path))
        if not fp.exists():
            raise FileNotFoundError(f"File not found in VSS snapshot: {internal_path}")
        data = b""
        with fp.open("rb") as src:
            while len(data) < max_size:
                chunk = src.read(min(65536, max_size - len(data)))
                if not chunk:
                    break
                data += chunk
        return data

    def _get_vss_for_volume(self, volume_ref: str = "/c:"):
        if not self._target:
            raise RuntimeError("No disk image mounted")
        volume = self._resolve_volume(volume_ref)
        cache_key = str(getattr(volume, "guid", "")) or str(getattr(volume, "offset", ""))
        cached = self._vss_cache.get(cache_key)
        if cached:
            return cached["vss"], volume
        try:
            from dissect.volume.vss import VSS
        except Exception as e:
            raise RuntimeError(f"dissect.volume.vss is unavailable: {e}") from e
        try:
            volume.seek(0)
            vss = VSS(volume)
        except Exception as e:
            raise RuntimeError(f"No readable VSS catalog on volume {volume_ref}: {e}") from e
        self._patch_vss_stores(vss)
        self._vss_cache[cache_key] = {"vss": vss}
        return vss, volume

    def _get_vss_snapshot_fs(self, snapshot_id: str, volume: str = "/c:"):
        from dissect.target.filesystems.ntfs import NtfsFilesystem

        vss, _volume = self._get_vss_for_volume(volume)
        token = str(snapshot_id or "").strip().lower()
        for store in vss.catalog.stores:
            aliases = {
                str(store.index).lower(),
                f"vss{store.index}".lower(),
                str(store.copy_identifier).lower(),
            }
            if token in aliases:
                meta = self._snapshot_metadata(store, volume)
                return meta, NtfsFilesystem(store.open())
        valid = [str(store.copy_identifier) for store in vss.catalog.stores]
        raise ValueError(f"VSS snapshot not found: {snapshot_id}. Valid snapshot_ids: {valid}")

    def _resolve_volume(self, volume_ref: str):
        ref = str(volume_ref or "/c:").strip().lower().replace("\\", "/")
        wanted_drive = ""
        if len(ref) >= 2 and ref[1] == ":":
            wanted_drive = ref[0]
        elif ref.startswith("/") and len(ref) >= 3 and ref[2] == ":":
            wanted_drive = ref[1]

        candidates = []
        for volume in self._target.volumes:
            fs = getattr(volume, "fs", None)
            if fs is None or str(fs).lower().find("ntfs") < 0:
                continue
            candidates.append(volume)
            drive = str(getattr(volume, "drive_letter", "") or "").lower().rstrip(":")
            if wanted_drive and drive == wanted_drive:
                return volume
            guid = str(getattr(volume, "guid", "") or "").lower()
            if guid and guid in ref:
                return volume
        if wanted_drive == "c" and candidates:
            os_volume = self._select_windows_volume(candidates)
            if os_volume is not None:
                return os_volume
            return max(candidates, key=self._volume_size)
        if len(candidates) == 1:
            return candidates[0]
        os_volume = self._select_windows_volume(candidates)
        if os_volume is not None:
            return os_volume
        raise ValueError(f"Unable to resolve NTFS volume for {volume_ref!r}")

    def _select_windows_volume(self, volumes: list[Any]) -> Any | None:
        for volume in volumes:
            if self._volume_has_path(volume, "/Windows/System32/config/SYSTEM"):
                return volume
        for volume in volumes:
            if self._volume_has_path(volume, "/Windows"):
                return volume
        return None

    def _volume_has_path(self, volume: Any, path: str) -> bool:
        fs = getattr(volume, "fs", None)
        if fs is None:
            return False
        try:
            return bool(fs.path(path).exists())
        except Exception:
            return False

    def _volume_size(self, volume: Any) -> int:
        for attr in ("size", "length"):
            value = getattr(volume, attr, None)
            if isinstance(value, int):
                return value
        try:
            return int(len(volume))
        except Exception:
            return 0

    def _patch_vss_stores(self, vss: Any) -> None:
        """Patch VSS sparse-block fallback to read from the active volume.

        The installed dissect.volume.vss StoreStream returns zeroes for some
        sparse/unchanged blocks. For filesystem mounting we need the complete
        virtual volume, so unchanged blocks fall back to the active volume bytes.
        Overlay and forwarded blocks still come from the VSS store chain.
        """
        try:
            from dissect.volume.vss import BLOCK_SIZE
        except Exception:
            BLOCK_SIZE = 0x4000

        def read_block(store_self, block: int, active_store: Any | None = None) -> bytes:
            descriptor = store_self.block_list.map.map.get(block)
            buf = None
            if descriptor:
                if descriptor.is_forwarder:
                    if store_self.next_store:
                        buf = store_self.next_store.read_block(
                            descriptor.relative_offset // BLOCK_SIZE,
                            store_self,
                        )
                    else:
                        store_self.fh.seek(descriptor.relative_offset)
                        buf = store_self.fh.read(BLOCK_SIZE)
                elif not descriptor.is_overlay:
                    store_self.fh.seek(descriptor.store_offset)
                    buf = store_self.fh.read(BLOCK_SIZE)
            if not descriptor or descriptor.is_overlay:
                if store_self.next_store:
                    buf = store_self.next_store.read_block(block, store_self)
                else:
                    store_self.fh.seek(block * BLOCK_SIZE)
                    buf = store_self.fh.read(BLOCK_SIZE)
            if not buf:
                raise ValueError(f"Error reading VSS block {block}")
            return buf

        for store in getattr(getattr(vss, "catalog", None), "stores", []) or []:
            store.read_block = types.MethodType(read_block, store)

    def _snapshot_metadata(self, store: Any, volume: str) -> dict[str, Any]:
        copy_id = str(store.copy_identifier)
        return {
            "temporal_layer": f"vss:{store.index}:{copy_id}",
            "snapshot_id": copy_id,
            "snapshot_index": int(store.index),
            "snapshot_creation_time": _filetime_to_iso(getattr(store, "creation_time", None)),
            "volume": volume,
            "integrity_note": "VSS contents are historical layers, not verified-clean baseline state.",
        }

    def _file_info_from_path(self, fp: Any) -> dict[str, Any]:
        st = fp.stat()
        result: dict[str, Any] = {
            "path": str(fp),
            "size": st.st_size,
        }

        result["created"] = _format_fs_ts(
            getattr(st, "st_birthtime", None) or getattr(st, "st_ctime", None)
        )
        result["modified"] = _format_fs_ts(st.st_mtime)
        result["accessed"] = _format_fs_ts(st.st_atime)

        try:
            entry = fp.get()
            si = getattr(entry, "stdinfo", None)
            fn = getattr(entry, "filename", None)
            if si:
                result["$SI_created"] = _format_fs_ts(getattr(si, "creation_time", None))
                result["$SI_modified"] = _format_fs_ts(getattr(si, "modification_time", None))
                result["$SI_mft_modified"] = _format_fs_ts(getattr(si, "mft_modification_time", None))
                result["$SI_accessed"] = _format_fs_ts(getattr(si, "access_time", None))
            if fn:
                result["$FN_created"] = _format_fs_ts(getattr(fn, "creation_time", None))
                result["$FN_modified"] = _format_fs_ts(getattr(fn, "modification_time", None))
        except Exception:
            pass
        return result

    def _copy_fs_path_to_output(self, fp: Any, internal_path: str, output_path: str) -> dict:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        warn_path = os.path.join(os.path.dirname(output_path), "_WARNING_MALWARE_DO_NOT_EXECUTE.txt")
        if not os.path.exists(warn_path):
            with open(warn_path, "w", encoding="utf-8") as wf:
                wf.write(
                    "WARNING: This directory contains files extracted from a forensic disk image.\n"
                    "These files may be MALWARE. DO NOT EXECUTE any file in this directory.\n"
                    "Use only static analysis tools (e.g., Ghidra, strings, hex editors).\n"
                )

        sha256 = hashlib.sha256()
        size = 0
        with fp.open("rb") as src, open(output_path, "wb") as dst:
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                dst.write(chunk)
                sha256.update(chunk)
                size += len(chunk)
        try:
            current = os.stat(output_path).st_mode
            os.chmod(output_path, current & 0o666)
        except Exception:
            pass
        return {
            "internal_path": internal_path,
            "output_path": output_path,
            "size": size,
            "sha256": sha256.hexdigest(),
            "execute_allowed": False,
            "warning": "STATIC ANALYSIS ONLY - do not execute this file",
        }

    def _safe_vss_rglob(self, base: Any, pattern: str, limit: int = 100):
        """Walk a VSS filesystem tree without letting one bad path abort search."""
        yield from self._safe_vss_rglob_with_coverage(base, pattern, limit=limit)["matches"]

    def _safe_vss_rglob_with_coverage(self, base: Any, pattern: str, limit: int = 100) -> dict[str, Any]:
        """Walk a VSS filesystem tree and report unreadable paths as coverage gaps."""
        pattern_lc = str(pattern or "*").lower()
        stack: list[Any] = [base]
        visited_dirs = 0
        max_dirs = 20000
        matches: list[Any] = []
        skipped_paths: set[str] = set()
        coverage: dict[str, Any] = {
            "paths_attempted": 0,
            "paths_succeeded": 0,
            "paths_skipped": 0,
            "skip_reasons": {
                "access_denied": 0,
                "io_error": 0,
                "path_too_long": 0,
                "symlink": 0,
                "other": 0,
            },
            "skipped_path_samples": [],
            "truncated": False,
            "max_paths": max_dirs,
        }

        def record_skip(path_obj: Any, exc: Exception) -> None:
            path_text = str(path_obj)
            if path_text in skipped_paths:
                return
            skipped_paths.add(path_text)
            reason = _vss_skip_reason(exc)
            coverage["paths_skipped"] += 1
            coverage["skip_reasons"][reason] += 1
            if len(coverage["skipped_path_samples"]) < 20:
                coverage["skipped_path_samples"].append({
                    "path": path_text,
                    "reason": reason,
                    "error": str(exc),
                })

        while stack and len(matches) < limit and visited_dirs < max_dirs:
            current = stack.pop()
            visited_dirs += 1
            coverage["paths_attempted"] += 1
            try:
                entries = sorted(
                    list(current.iterdir()),
                    key=lambda entry: str(getattr(entry, "name", "") or "").lower(),
                )
                coverage["paths_succeeded"] += 1
            except Exception as exc:
                record_skip(current, exc)
                continue

            for entry in entries:
                try:
                    name = str(getattr(entry, "name", "") or "")
                    entry_path = str(entry).replace("\\", "/")
                    is_match = (
                        fnmatch.fnmatchcase(name.lower(), pattern_lc)
                        or fnmatch.fnmatchcase(entry_path.lower(), pattern_lc)
                    )
                    is_dir = entry.is_dir()
                except Exception as exc:
                    record_skip(entry, exc)
                    continue
                if is_match:
                    matches.append(entry)
                    if len(matches) >= limit:
                        break
                if is_dir:
                    stack.append(entry)
        if stack:
            coverage["truncated"] = True
        return {"matches": matches, "coverage": coverage}

    def _normalize_volume_relative_path(self, path: str) -> str:
        path = self._normalize_path(path)
        m = re.match(r"^/[a-z]:/?", path, flags=re.IGNORECASE)
        if m:
            path = "/" + path[m.end():].lstrip("/")
        return path or "/"

    def _open_fat_fallback(self):
        try:
            if any(True for _ in self._target.filesystems):
                return None
        except Exception:
            pass
        try:
            disk = next(iter(self._target.disks))
            volume = next(iter(self._target.volumes))
            return _FatRootFallback(
                disk,
                int(getattr(volume, "offset", 0) or 0),
                int(getattr(volume, "size", 0) or 0),
            )
        except Exception:
            return None

    def _normalize_path(self, path: str) -> str:
        """Convert Windows/AXIOM-style path to dissect internal format."""
        path = path.replace("\\", "/")
        # Strip AXIOM partition description prefix
        # e.g. "Evidence.E01 - Partition 3 (Microsoft NTFS, 237.57 GB)/Windows/..."
        m = re.match(r'^[^)]+Partition\s+\d+\s*\([^)]+\)\s*/?\s*', path, flags=re.IGNORECASE)
        if m:
            path = path[m.end():]
        # Handle drive letter: C:/Windows -> /c:/Windows
        if len(path) >= 2 and path[1] == ":":
            path = "/" + path[0].lower() + path[1:]
        elif path.startswith("/"):
            pass  # Already absolute
        else:
            # No drive letter after AXIOM prefix strip — default to /c:/
            path = "/c:/" + path.lstrip("/")
        return path


def _format_fs_ts(ts: Any) -> str:
    if ts is None:
        return ""
    try:
        if isinstance(ts, (int, float)):
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        else:
            dt = ts
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except Exception:
        return str(ts)


def _filetime_to_iso(value: Any) -> str:
    try:
        if value is None:
            return ""
        seconds = (int(value) - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return str(value or "")


def _vss_display_path(volume: str, path: str) -> str:
    vol = str(volume or "/c:").replace("\\", "/").strip()
    if not vol.startswith("/"):
        vol = "/" + vol
    vol = vol.rstrip("/")
    rel = str(path or "/").replace("\\", "/")
    if len(rel) >= 3 and rel.startswith("/") and rel[2] == ":":
        return rel
    return f"{vol}/{rel.lstrip('/')}"


def _vss_skip_reason(exc: Exception) -> str:
    text = str(exc).lower()
    name = exc.__class__.__name__.lower()
    if isinstance(exc, PermissionError) or "access" in text or "permission" in text:
        return "access_denied"
    if isinstance(exc, OSError) or "io" in name or "read" in text:
        return "io_error"
    if "too long" in text or "nametoolong" in name:
        return "path_too_long"
    if "symlink" in text or "reparse" in text:
        return "symlink"
    return "other"


def _vss_connector_guardrails() -> dict[str, Any]:
    return {
        "temporal_layer_required": True,
        "merge_with_current_fs_allowed": False,
        "absence_is_negative_evidence": False,
        "vss_is_verified_clean_baseline": False,
        "interpretation": (
            "VSS snapshots are historical filesystem layers. Treat them as "
            "separate evidence sources and compare explicitly."
        ),
    }


class _FatRootFallback:
    """Minimal read-only FAT16/FAT32 root directory fallback.

    This is intentionally narrow: it indexes the root directory of FAT data
    volumes that dissect.target does not mount, enough for coverage and
    overcall-bias checks without adding case-specific filenames.
    """

    def __init__(self, disk: Any, partition_offset: int, partition_size: int) -> None:
        self._disk = disk
        self._partition_offset = partition_offset
        self._partition_size = partition_size
        self._fat_type = ""
        self._entries: list[dict[str, Any]] = []
        self._load()

    def metadata(self) -> dict[str, Any]:
        return {
            "type": self._fat_type or "fat",
            "parser": "fat_root_fallback",
            "offset": self._partition_offset,
            "size": self._partition_size,
            "root_entry_count": len(self._entries),
        }

    def list_directory(self, path: str = "/") -> list[dict[str, Any]]:
        if _clean_fat_path(path) not in {"", "/"}:
            return []
        return [dict(entry) for entry in self._entries]

    def find_files(self, pattern: str, path: str = "/", limit: int = 100) -> list[dict[str, Any]]:
        import fnmatch

        if _clean_fat_path(path) not in {"", "/"}:
            return []
        matches = []
        for entry in self._entries:
            if entry.get("is_dir"):
                continue
            if fnmatch.fnmatchcase(str(entry.get("name", "")).lower(), pattern.lower()):
                matches.append(dict(entry))
                if len(matches) >= limit:
                    break
        return matches

    def get_file_info(self, path: str) -> dict[str, Any]:
        clean = _clean_fat_path(path).lower()
        for entry in self._entries:
            if _clean_fat_path(str(entry.get("path", ""))).lower() == clean:
                return dict(entry)
        return {"error": f"File not found: {path}"}

    def _load(self) -> None:
        boot = self._read_at(self._partition_offset, 512)
        if len(boot) < 512 or boot[510:512] != b"\x55\xaa":
            return
        bytes_per_sector = _u16(boot, 11)
        sectors_per_cluster = boot[13]
        reserved_sectors = _u16(boot, 14)
        fat_count = boot[16]
        root_entry_count = _u16(boot, 17)
        total_sectors = _u16(boot, 19) or _u32(boot, 32)
        sectors_per_fat = _u16(boot, 22) or _u32(boot, 36)
        if not bytes_per_sector or not sectors_per_cluster or not sectors_per_fat or not total_sectors:
            return

        root_dir_sectors = ((root_entry_count * 32) + (bytes_per_sector - 1)) // bytes_per_sector
        first_data_sector = reserved_sectors + (fat_count * sectors_per_fat) + root_dir_sectors
        if root_entry_count:
            self._fat_type = "fat16"
            root_offset = self._partition_offset + (reserved_sectors + fat_count * sectors_per_fat) * bytes_per_sector
            root_size = root_dir_sectors * bytes_per_sector
            root_data = self._read_at(root_offset, root_size)
        else:
            self._fat_type = "fat32"
            root_cluster = _u32(boot, 44) or 2
            fat_offset = self._partition_offset + reserved_sectors * bytes_per_sector
            fat = self._read_at(fat_offset, sectors_per_fat * bytes_per_sector)
            root_data = b"".join(
                self._read_cluster(cluster, first_data_sector, bytes_per_sector, sectors_per_cluster)
                for cluster in self._cluster_chain(fat, root_cluster)
            )
        self._entries = _parse_fat_directory(root_data)

    def _cluster_chain(self, fat: bytes, start: int) -> list[int]:
        chain = []
        cluster = start
        seen = set()
        while cluster >= 2 and cluster not in seen and len(chain) < 4096:
            seen.add(cluster)
            chain.append(cluster)
            offset = cluster * 4
            if offset + 4 > len(fat):
                break
            nxt = struct.unpack_from("<I", fat, offset)[0] & 0x0FFFFFFF
            if nxt >= 0x0FFFFFF8:
                break
            cluster = nxt
        return chain

    def _read_cluster(self, cluster: int, first_data_sector: int, bytes_per_sector: int, sectors_per_cluster: int) -> bytes:
        sector = first_data_sector + (cluster - 2) * sectors_per_cluster
        offset = self._partition_offset + sector * bytes_per_sector
        return self._read_at(offset, sectors_per_cluster * bytes_per_sector)

    def _read_at(self, offset: int, size: int) -> bytes:
        self._disk.seek(offset)
        return self._disk.read(size)


def _parse_fat_directory(data: bytes) -> list[dict[str, Any]]:
    entries = []
    lfn_parts: list[tuple[int, str]] = []
    for pos in range(0, len(data) - 31, 32):
        raw = data[pos:pos + 32]
        first = raw[0]
        if first == 0x00:
            break
        if first == 0xE5:
            lfn_parts = []
            continue
        attr = raw[11]
        if attr == 0x0F:
            order = raw[0] & 0x1F
            lfn_parts.append((order, _decode_lfn_part(raw)))
            continue
        if attr & 0x08:
            lfn_parts = []
            continue
        name = _short_fat_name(raw)
        if lfn_parts:
            ordered = "".join(part for _, part in sorted(lfn_parts))
            name = ordered.rstrip("\uffff\x00") or name
        lfn_parts = []
        if not name:
            continue
        is_dir = bool(attr & 0x10)
        entries.append({
            "name": name,
            "path": f"/{name}",
            "is_dir": is_dir,
            "size": 0 if is_dir else _u32(raw, 28),
            "resolution": "fat_root_fallback",
        })
    return entries


def _short_fat_name(raw: bytes) -> str:
    stem = raw[0:8].decode("ascii", errors="ignore").strip()
    ext = raw[8:11].decode("ascii", errors="ignore").strip()
    if not stem:
        return ""
    return f"{stem}.{ext}" if ext else stem


def _decode_lfn_part(raw: bytes) -> str:
    chars = raw[1:11] + raw[14:26] + raw[28:32]
    return chars.decode("utf-16le", errors="ignore").replace("\x00", "")


def _clean_fat_path(path: str) -> str:
    text = path.replace("\\", "/")
    if text.lower().startswith("/c:/"):
        text = text[3:]
    return text.rstrip("/")


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]
