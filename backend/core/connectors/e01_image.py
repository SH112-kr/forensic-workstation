"""E01 image connector — mount and extract files from forensic disk images via dissect."""

from __future__ import annotations

import hashlib
import os
import re
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

        return self.get_metadata()

    def _open_ewf(self, path: str) -> "Target":
        """Open EWF/E01 image by manually filtering segments (avoids SmartLog issue)."""
        from dissect.target import Target
        from dissect.target.containers.ewf import EwfContainer

        base_dir = os.path.dirname(path)
        base_name = os.path.splitext(os.path.basename(path))[0]

        # Collect only valid E0x/Ex01 segments (skip smartlog, etc.)
        segments = []
        for f in sorted(os.listdir(base_dir)):
            if not f.startswith(base_name):
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
        return meta

    def search(self, keyword: str = "", filters: dict | None = None,
               limit: int = 50, offset: int = 0) -> dict:
        """Search filenames by glob pattern."""
        pattern = keyword or (filters or {}).get("pattern", "**/*")
        results = self.find_files(pattern, limit=limit)
        return {"total": len(results), "files": results}

    def list_directory(self, path: str = "/") -> list[dict]:
        """List files and directories at the given internal path."""
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
            "warning": "STATIC ANALYSIS ONLY — do not execute this file",
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

    def _normalize_path(self, path: str) -> str:
        """Convert Windows/AXIOM-style path to dissect internal format."""
        path = path.replace("\\", "/")
        # Strip AXIOM partition description prefix
        # e.g. "E01Capture.E01 - Partition 3 (Microsoft NTFS, 237.57 GB)/Windows/..."
        m = re.match(r'^[^)]+\)\s*/?\s*', path)
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
