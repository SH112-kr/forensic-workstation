"""Tests for the IFEO Debugger / SilentProcessExit persistence parser."""

from __future__ import annotations

from core.raw_index.artifact_indexer import (
    _IFEO_PATH,
    _SILENT_PROCESS_EXIT_PATH,
    _filetime_int_to_ms,
    parse_ifeo_entries,
)


class _Val:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class _Hdr:
    def __init__(self, last_modified):
        self.last_modified = last_modified


class _Sub:
    def __init__(self, name, values, last_modified=0):
        self.name = name
        self._values = values
        self.header = _Hdr(last_modified)

    def iter_values(self):
        return iter(self._values)


class _Key:
    def __init__(self, subs):
        self._subs = subs

    def iter_subkeys(self):
        return iter(self._subs)


class _Hive:
    def __init__(self, keys):
        self._keys = keys

    def get_key(self, path):
        if path not in self._keys:
            raise KeyError(f"Did not find {path}")
        return self._keys[path]


_FT = 134229275568254687  # a real FILETIME observed in a SOFTWARE hive


def test_ifeo_debugger_emitted_benign_skipped():
    hive = _Hive({
        _IFEO_PATH: _Key([
            _Sub("sethc.exe", [_Val("Debugger", "C:\\Windows\\Temp\\evil.exe")], _FT),
            _Sub("notepad.exe", [_Val("PerfOptions", 1)]),  # benign — no Debugger
            _Sub("photoviewer.dll", []),                    # benign — no values
        ]),
    })
    entries, gaps = parse_ifeo_entries(hive)
    assert gaps == []
    assert len(entries) == 1
    e = entries[0]
    assert e["kind"] == "ifeo_debugger"
    assert e["image"] == "sethc.exe"
    assert e["debugger"].endswith("evil.exe")
    assert e["key_last_modified"] is not None  # FILETIME decoded


def test_ifeo_verifier_dll_emitted():
    hive = _Hive({
        _IFEO_PATH: _Key([
            _Sub("winlogon.exe", [_Val("VerifierDlls", "evil.dll"),
                                  _Val("GlobalFlag", 0x100)], _FT),
        ]),
    })
    entries, _gaps = parse_ifeo_entries(hive)
    assert len(entries) == 1
    assert entries[0]["kind"] == "ifeo_verifier_dll"
    assert entries[0]["verifier_dlls"] == "evil.dll"


def test_silent_process_exit_emitted():
    hive = _Hive({
        _SILENT_PROCESS_EXIT_PATH: _Key([
            _Sub("svchost.exe", [_Val("MonitorProcess", "C:\\bad\\mon.exe"),
                                 _Val("ReportingMode", 1)], _FT),
            _Sub("nope.exe", [_Val("ReportingMode", 1)]),  # no MonitorProcess — skip
        ]),
    })
    entries, _gaps = parse_ifeo_entries(hive)
    assert len(entries) == 1
    assert entries[0]["kind"] == "silent_process_exit"
    assert entries[0]["monitor_process"].endswith("mon.exe")


def test_ifeo_absent_keys_no_entries_no_gap():
    entries, gaps = parse_ifeo_entries(_Hive({}))
    assert entries == []
    assert gaps == []  # absent key is normal, not a gap


def test_ifeo_corrupt_key_is_gap():
    class _CorruptHive:
        def get_key(self, path):
            raise RuntimeError("RegistryParsingException-like corruption")

    entries, gaps = parse_ifeo_entries(_CorruptHive())
    assert entries == []
    assert any(g.get("reason") == "ifeo_key_error" for g in gaps)


def test_ifeo_subkey_read_error_is_gap():
    class _BadSub:
        name = "x.exe"
        header = _Hdr(0)

        def iter_values(self):
            raise RuntimeError("unreadable values")

    hive = _Hive({_IFEO_PATH: _Key([_BadSub()])})
    entries, gaps = parse_ifeo_entries(hive)
    assert entries == []
    assert any(g.get("reason") == "ifeo_subkey_read_error" for g in gaps)


def test_filetime_int_to_ms():
    parsed = _filetime_int_to_ms(_FT)
    assert parsed is not None
    ms, display = parsed
    assert ms > 0
    assert display.startswith("20")  # ISO year
    assert _filetime_int_to_ms(0) is None
    assert _filetime_int_to_ms("not-a-number") is None
