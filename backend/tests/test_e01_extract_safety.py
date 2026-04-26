from __future__ import annotations

import os


class _FakeEvidencePath:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def exists(self) -> bool:
        return True

    def open(self, mode: str):
        from io import BytesIO

        assert mode == "rb"
        return BytesIO(self._data)


class _FakeFs:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def path(self, _path: str) -> _FakeEvidencePath:
        return _FakeEvidencePath(self._data)


class _FakeTarget:
    def __init__(self, data: bytes) -> None:
        self.fs = _FakeFs(data)


def test_e01_extract_file_marks_static_only_and_non_executable(tmp_path):
    from core.connectors.e01_image import E01ImageConnector

    connector = E01ImageConnector()
    connector._target = _FakeTarget(b"MZ-not-executed")
    output = tmp_path / "sample.exe"

    result = connector.extract_file("/c:/Windows/System32/sample.exe", str(output))

    assert result["execute_allowed"] is False
    assert "do not execute" in result["warning"].lower()
    assert (tmp_path / "_WARNING_MALWARE_DO_NOT_EXECUTE.txt").exists()
    assert output.read_bytes() == b"MZ-not-executed"
    if os.name != "nt":
        assert not (output.stat().st_mode & 0o111)


def test_e01_normalize_path_preserves_parentheses_in_filename():
    from core.connectors.e01_image import E01ImageConnector

    connector = E01ImageConnector()

    assert (
        connector._normalize_path("/c:/Users/jcloudy/Desktop/Cloudy thoughts (4apr).docx")
        == "/c:/Users/jcloudy/Desktop/Cloudy thoughts (4apr).docx"
    )
    assert (
        connector._normalize_path(
            "LoneWolf.E01 - Partition 4 (Microsoft NTFS, 476.34 GB)\\Users\\jcloudy\\Desktop\\Cloudy thoughts (4apr).docx"
        )
        == "/c:/Users/jcloudy/Desktop/Cloudy thoughts (4apr).docx"
    )
