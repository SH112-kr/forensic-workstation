from __future__ import annotations


def test_file_browser_recognizes_disk_image_extensions():
    from api.files import FORENSIC_EXTENSIONS

    for ext in (".e01", ".ex01", ".vmdk", ".dd", ".img"):
        assert FORENSIC_EXTENSIONS[ext] == "Disk Image"
