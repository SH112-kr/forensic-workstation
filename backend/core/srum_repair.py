"""Auto-repair dirty SRUM databases for SrumECmd parsing.

ESE databases (SRUDB.dat) from live collection are often in a dirty state
because the system was running when the file was copied. This module:
1. Copies SRUDB.dat + transaction logs to a temp directory
2. Runs esentutl /r (soft recovery), then /p (hard repair) if needed
3. Runs SrumECmd on the repaired copy
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any


def find_srudb_in_collection(collected_dir: str) -> list[str]:
    """Find all SRUDB.dat files in KAPE collected directory."""
    return sorted(glob.glob(
        os.path.join(collected_dir, "**", "SRUDB.dat"), recursive=True
    ))


def find_srumecmd() -> str | None:
    """Find SrumECmd.exe from KAPE modules or PATH."""
    from core.config import find_kape

    kape = find_kape()
    if kape:
        kape_dir = os.path.dirname(kape)
        candidates = [
            os.path.join(kape_dir, "Modules", "bin", "SrumECmd.exe"),
            os.path.join(kape_dir, "Modules", "bin", "SrumECmd", "SrumECmd.exe"),
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c

    return shutil.which("SrumECmd") or shutil.which("SrumECmd.exe")


def repair_srudb(srudb_path: str) -> dict[str, Any]:
    """Copy SRUDB.dat to temp dir, run esentutl recovery + repair.

    Returns {"status": "ok"|"repaired"|"failed", "repaired_path": str, ...}
    """
    if not os.path.isfile(srudb_path):
        return {"status": "failed", "detail": f"SRUDB.dat not found: {srudb_path}"}

    sru_dir = os.path.dirname(srudb_path)
    tmp = tempfile.mkdtemp(prefix="srum_repair_")

    try:
        # Copy SRUDB.dat + all SRU* transaction logs/checkpoints
        shutil.copy2(srudb_path, os.path.join(tmp, "SRUDB.dat"))
        for pattern in ("SRU*.log", "SRU*.chk", "SRUtmp.log"):
            for f in glob.glob(os.path.join(sru_dir, pattern)):
                shutil.copy2(f, os.path.join(tmp, os.path.basename(f)))

        repaired_path = os.path.join(tmp, "SRUDB.dat")
        method = None

        # Step 1: Soft recovery (replay transaction logs)
        result = subprocess.run(
            ["powershell", "-Command",
             f"cd '{tmp}'; esentutl.exe /r sru /i"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            method = "soft"
        else:
            # Step 2: Hard repair
            result = subprocess.run(
                ["powershell", "-Command",
                 f"cd '{tmp}'; esentutl.exe /p SRUDB.dat /o"],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0 or "repaired" in result.stdout.lower():
                method = "hard"
            else:
                return {
                    "status": "failed",
                    "detail": f"esentutl repair failed: {result.stderr[:200]}",
                    "tmp_dir": tmp,
                }

        return {
            "status": "repaired",
            "method": method,
            "repaired_path": repaired_path,
            "tmp_dir": tmp,
        }

    except subprocess.TimeoutExpired:
        return {"status": "failed", "detail": "esentutl timed out", "tmp_dir": tmp}
    except Exception as e:
        return {"status": "failed", "detail": str(e), "tmp_dir": tmp}


def repair_and_parse_srum(
    srudb_path: str,
    output_dir: str,
    srumecmd_path: str | None = None,
) -> dict[str, Any]:
    """Full pipeline: repair dirty SRUDB.dat, then parse with SrumECmd.

    Returns {"status": ..., "csvs_created": int, "records": {...}, ...}
    """
    if not srumecmd_path:
        srumecmd_path = find_srumecmd()
    if not srumecmd_path:
        return {"status": "failed", "detail": "SrumECmd.exe not found"}

    # First try parsing directly (maybe it's clean)
    direct = _run_srumecmd(srumecmd_path, srudb_path, output_dir)
    if direct["status"] == "ok":
        return direct

    # Direct parse failed — repair and retry
    repair = repair_srudb(srudb_path)
    if repair["status"] != "repaired":
        return {"status": "failed", "detail": f"Repair failed: {repair.get('detail', '')}"}

    result = _run_srumecmd(srumecmd_path, repair["repaired_path"], output_dir)
    result["repair_method"] = repair["method"]

    # Cleanup temp dir
    tmp = repair.get("tmp_dir")
    if tmp and os.path.isdir(tmp):
        try:
            shutil.rmtree(tmp)
        except OSError:
            pass

    return result


def _run_srumecmd(exe: str, srudb: str, output_dir: str) -> dict[str, Any]:
    """Run SrumECmd and parse output."""
    os.makedirs(output_dir, exist_ok=True)

    try:
        result = subprocess.run(
            [exe, "-f", srudb, "--csv", output_dir],
            capture_output=True, text=True, timeout=300,
        )

        output = result.stdout + result.stderr
        if result.returncode != 0 and "dirty" in output.lower():
            return {"status": "dirty", "detail": "Database is dirty"}
        if result.returncode != 0:
            return {"status": "failed", "detail": output[:300]}

        # Parse record counts from output
        records = {}
        for line in output.splitlines():
            if " count:" in line.lower():
                parts = line.strip().rsplit(":", 1)
                if len(parts) == 2:
                    name = parts[0].strip()
                    try:
                        count = int(parts[1].strip().replace(",", ""))
                        records[name] = count
                    except ValueError:
                        pass

        # Count created CSVs
        csvs = glob.glob(os.path.join(output_dir, "*SrumECmd*"))
        return {
            "status": "ok",
            "csvs_created": len(csvs),
            "records": records,
            "total_records": sum(records.values()),
        }

    except subprocess.TimeoutExpired:
        return {"status": "failed", "detail": "SrumECmd timed out"}
    except Exception as e:
        return {"status": "failed", "detail": str(e)}
