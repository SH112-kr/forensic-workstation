from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mcp_bridge  # noqa: E402


def test_candidate_disk_paths_from_hits_extracts_exact_windows_paths():
    hits = [
        {
            "fields": {
                "File Name": r"C:\Intel\64-bit\netscan.exe",
                "Other": r"noise C:\Temp\ignore.dll",
            }
        },
        {
            "fields": {
                "Full Path": r"\\device\\harddiskvolume2\\intel\\64-bit\\netscan.exe",
                "Rendered": r'ImagePath="C:\ProgramData\bomgar-pec-0x695f5087\bomgar-pec.exe"',
            }
        },
    ]
    r = mcp_bridge._candidate_disk_paths_from_hits("netscan.exe", hits)
    assert r == [r"C:\Intel\64-bit\netscan.exe"]


def test_candidate_disk_paths_from_hits_keeps_multiple_entity_paths():
    hits = [
        {"fields": {"A": r"C:\ProgramData\bomgar-pec-0x1\bomgar-pec.exe"}},
        {"fields": {"B": r"C:\Users\S\Downloads\bomgar-pec-installer.exe"}},
    ]
    r = mcp_bridge._candidate_disk_paths_from_hits("bomgar-pec", hits)
    assert r == [
        r"C:\ProgramData\bomgar-pec-0x1\bomgar-pec.exe",
        r"C:\Users\S\Downloads\bomgar-pec-installer.exe",
    ]
