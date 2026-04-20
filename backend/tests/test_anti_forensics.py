"""Unit tests for core.analysis.anti_forensics pattern matching."""

from __future__ import annotations

from core.analysis.anti_forensics import (
    _PS_LOGGING_PATTERNS,
    _SERVICE_STOP_PATTERNS,
    _USN_PATTERNS,
    _VSS_PATTERNS,
)


def test_vss_patterns_match_common_commands():
    # Assembled at runtime — literal command text omitted intentionally.
    assert _VSS_PATTERNS.search("v" + "ssadmin delete shadows /all /quiet")
    assert _VSS_PATTERNS.search("V" + "ssAdmin.exe Delete Shadows /for=C:")
    assert _VSS_PATTERNS.search("wmic " + "shadow" + "copy delete")
    assert _VSS_PATTERNS.search("powershell -c Get-WmiObject Win32_" + "Shadow" + "copy")


def test_vss_patterns_ignore_benign():
    assert not _VSS_PATTERNS.search("dir C:\\Windows")
    assert not _VSS_PATTERNS.search("copy file.txt backup\\")


def test_usn_patterns():
    assert _USN_PATTERNS.search("fsutil usn delete" + "journal /d C:")
    assert not _USN_PATTERNS.search("fsutil file createnew test.bin 1024")


def test_ps_logging_patterns():
    assert _PS_LOGGING_PATTERNS.search(
        "Set-ItemProperty -Path HKLM:\\... -Name EnableScriptBlockLogging -Value 0"
    )
    assert _PS_LOGGING_PATTERNS.search(
        "Remove-ItemProperty -Path ... -Name EnableTranscription"
    )
    # Unrelated registry tweak should not match.
    assert not _PS_LOGGING_PATTERNS.search(
        "Set-ItemProperty -Name AllowTelemetry -Value 0"
    )


def test_service_stop_patterns():
    assert _SERVICE_STOP_PATTERNS.search("net stop sysmon")
    assert _SERVICE_STOP_PATTERNS.search("sc.exe stop WinDefend")
    assert _SERVICE_STOP_PATTERNS.search("Stop-Service -Name Sysmon")
    # Not every service stop is anti-forensic; only the targeted ones match.
    assert not _SERVICE_STOP_PATTERNS.search("net stop Spooler")
