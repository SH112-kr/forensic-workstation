from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from core.connectors.e01_image import E01ImageConnector


def _epoch(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


class _FakeEntry:
    def __init__(self, name: str, path: str, stat_result: SimpleNamespace) -> None:
        self.name = name
        self._path = path
        self._stat_result = stat_result

    def __lt__(self, other: object) -> bool:
        return self.name < getattr(other, "name", "")

    def __str__(self) -> str:
        return self._path

    def is_dir(self) -> bool:
        return False

    def stat(self) -> SimpleNamespace:
        return self._stat_result


class _FakeDir:
    def __init__(self, entries: list[_FakeEntry]) -> None:
        self._entries = entries

    def iterdir(self):
        return iter(self._entries)


class _FakeFs:
    def __init__(self, entries: list[_FakeEntry]) -> None:
        self._entries = entries

    def path(self, _path: str) -> _FakeDir:
        return _FakeDir(self._entries)


class _FakeTarget:
    def __init__(self, entries: list[_FakeEntry]) -> None:
        self.fs = _FakeFs(entries)


def test_list_directory_includes_file_timestamps_from_stat():
    entry = _FakeEntry(
        "dated.exe",
        "/c:/Tools/dated.exe",
        SimpleNamespace(
            st_size=2048,
            st_birthtime=_epoch("2026-10-03T00:00:00Z"),
            st_ctime=_epoch("2026-10-03T00:00:00Z"),
            st_mtime=_epoch("2026-10-04T00:00:00Z"),
            st_atime=_epoch("2026-10-05T00:00:00Z"),
        ),
    )
    connector = E01ImageConnector()
    connector._target = _FakeTarget([entry])

    result = connector.list_directory("/c:/Tools")

    assert result == [{
        "name": "dated.exe",
        "path": "/c:/Tools/dated.exe",
        "is_dir": False,
        "size": 2048,
        "created": "2026-10-03 00:00:00.000",
        "modified": "2026-10-04 00:00:00.000",
        "accessed": "2026-10-05 00:00:00.000",
    }]
