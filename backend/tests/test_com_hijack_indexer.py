"""Tests for the per-user COM hijack parser (UsrClass.dat CLSID servers)."""

from __future__ import annotations

import core.raw_index.artifact_indexer as ai
from core.raw_index.artifact_indexer import parse_com_hijack


class _Val:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class _SrvKey:
    def __init__(self, values):
        self._values = values

    def iter_values(self):
        return iter(self._values)


class _GuidKey:
    def __init__(self, name, servers):
        self.name = name
        self._servers = servers  # {subkey_name: _SrvKey}

    def get_subkey(self, name):
        if name not in self._servers:
            raise KeyError(name)
        return self._servers[name]


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
            raise KeyError(path)
        return self._keys[path]


def _hive(guid_keys):
    return _Hive({"\\CLSID": _Key(guid_keys)})


def test_com_hijack_emits_user_writable_skips_program_files():
    hive = _hive([
        _GuidKey("{evil}", {"InprocServer32": _SrvKey([
            _Val("", "C:\\Users\\v\\AppData\\Local\\Temp\\eviltsk.dll"),
            _Val("ThreadingModel", "Apartment")])}),
        _GuidKey("{legit}", {"InprocServer32": _SrvKey([
            _Val("", "C:\\Program Files\\Vendor\\app.dll")])}),
    ])
    entries, gaps = parse_com_hijack(hive, user="v")
    assert gaps == []
    assert len(entries) == 1
    assert entries[0]["clsid"] == "{evil}"
    assert entries[0]["server_kind"] == "inproc"
    assert entries[0]["threading_model"] == "Apartment"
    assert "AppData" in entries[0]["server"]


def test_com_hijack_localserver32_emitted():
    hive = _hive([
        _GuidKey("{x}", {"LocalServer32": _SrvKey([
            _Val("", "C:\\Users\\v\\AppData\\Roaming\\mal.exe")])}),
    ])
    entries, _gaps = parse_com_hijack(hive, user="v")
    assert len(entries) == 1
    assert entries[0]["server_kind"] == "local"


def test_com_hijack_absent_clsid_root_no_gap():
    entries, gaps = parse_com_hijack(_Hive({}), user="v")
    assert entries == []
    assert gaps == []


def test_com_hijack_corrupt_key_is_gap():
    class _CorruptHive:
        def get_key(self, path):
            raise RuntimeError("RegistryParsingException-like")

    entries, gaps = parse_com_hijack(_CorruptHive(), user="v")
    assert entries == []
    assert any(g.get("reason") == "com_clsid_key_error" for g in gaps)


def test_com_hijack_subkey_value_read_error_is_gap():
    class _BadSrv:
        def iter_values(self):
            raise RuntimeError("unreadable")

    hive = _hive([_GuidKey("{g}", {"InprocServer32": _BadSrv()})])
    entries, gaps = parse_com_hijack(hive, user="v")
    assert entries == []
    assert any(g.get("reason") == "com_subkey_read_error" for g in gaps)


def test_com_hijack_scriptlet_and_env_var_paths_flagged():
    hive = _hive([
        _GuidKey("{scriptlet}", {"InprocServer32": _SrvKey([
            _Val("", "C:\\Windows\\System32\\scrobj.dll")])}),  # scriptlet COM
        _GuidKey("{envvar}", {"InprocServer32": _SrvKey([
            _Val("", "%APPDATA%\\mal.dll")])}),                 # env-var path
    ])
    entries, _gaps = parse_com_hijack(hive, user="v")
    reasons = {e["clsid"]: e["suspicious_reason"] for e in entries}
    assert reasons["{scriptlet}"] == "scriptlet_com"  # scrobj.dll in System32 still caught
    assert reasons["{envvar}"] == "env_var_path"


def test_com_hijack_get_subkey_corrupt_is_gap():
    class _CorruptGuid:
        name = "{g}"

        def get_subkey(self, name):
            raise RuntimeError("RegistryParsingException-like corruption")

    hive = _hive([_CorruptGuid()])
    entries, gaps = parse_com_hijack(hive, user="v")
    assert entries == []
    assert any(g.get("reason") == "com_subkey_read_error" for g in gaps)


def test_com_hijack_cap_reached_is_gap(monkeypatch):
    monkeypatch.setattr(ai, "_COM_CLSID_CAP", 2)
    guids = [
        _GuidKey("{%d}" % i, {"InprocServer32": _SrvKey([
            _Val("", "C:\\Users\\v\\AppData\\Local\\m%d.dll" % i)])})
        for i in range(5)
    ]
    entries, gaps = parse_com_hijack(_hive(guids), user="v")
    assert any(g.get("reason") == "com_clsid_cap_reached" for g in gaps)
    assert len(entries) <= 2
