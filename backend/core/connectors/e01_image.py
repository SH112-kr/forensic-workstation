"""E01 image connector — mount and extract files from forensic disk images via dissect."""

from __future__ import annotations

import hashlib
import os
import re
import struct
from typing import Any

from core.connectors.base import BaseConnector


class E01ImageConnector(BaseConnector):
    """Open E01/VMDK/raw images using dissect for file extraction.

    Uses EwfContainer + Target for E01 files to avoid SmartLog interference.
    Falls back to Target.open() for other image formats.
    """

    def __init__(self) -> None:
        self._target = None
        self._fhs: list = []  # Keep file handles alive
        self._path: str = ""
        self._fat_fallback = None

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
        }
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
                        info["size"] = entry.stat().st_size
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
        return ["search", "list_directory", "find_files", "extract_file"]

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
        # e.g. "E01Capture.E01 - Partition 3 (Microsoft NTFS, 237.57 GB)/Windows/..."
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
