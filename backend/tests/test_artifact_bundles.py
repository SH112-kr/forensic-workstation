from __future__ import annotations

from core.analysis.artifact_bundles import build_artifact_bundles


class _StubConnector:
    def __init__(self):
        self._artifact_counts = [
            {"artifact_type": "Prefetch Files - Windows 8/10/11", "count": 4},
            {"artifact_type": "UserAssist", "count": 2},
            {"artifact_type": "Scheduled Tasks", "count": 3},
            {"artifact_type": "Encrypted Files", "count": 1},
            {"artifact_type": "SRUM Network Connections", "count": 5},
            {"artifact_type": "Windows Stored Credentials", "count": 1},
        ]

    def get_artifact_type_counts(self):
        return self._artifact_counts

    def search(self, keyword="", filters=None, limit=50, offset=0):
        filters = filters or {}
        artifact_type = filters.get("artifact_type")
        if artifact_type == "Prefetch Files - Windows 8/10/11":
            return {
                "total": 4,
                "hits": [
                    {"hit_id": 1, "artifact_type": artifact_type, "fields": {"Application Name": "cmd.exe", "Full Path": r"C:\Windows\System32\cmd.exe"}},
                ],
            }
        if artifact_type == "Windows Stored Credentials":
            return {
                "total": 1,
                "hits": [
                    {"hit_id": 2, "artifact_type": artifact_type, "fields": {"Target Name": "server1", "User Name": "alice"}},
                ],
            }
        if artifact_type == "Encrypted Files":
            return {
                "total": 1,
                "hits": [
                    {"hit_id": 3, "artifact_type": artifact_type, "source_path": r"C:\Users\alice\Documents\report.docx.locked"},
                ],
            }
        if artifact_type == "Text Documents":
            return {
                "total": 0,
                "hits": [],
            }
        return {"total": 0, "hits": []}


def test_build_artifact_bundles_returns_methodology_oriented_bundles():
    result = build_artifact_bundles(_StubConnector())

    assert result["artifact_bundles"]
    bundle_ids = [b["bundle_id"] for b in result["artifact_bundles"]]
    assert "execution_evidence" in bundle_ids
    assert "credential_evidence" in bundle_ids
    execution = next(b for b in result["artifact_bundles"] if b["bundle_id"] == "execution_evidence")
    assert execution["methodology"]
    assert execution["artifacts"][0]["artifact_type"]
    assert execution["signal_score"] > 0
    assert "bundle ordering uses signal_score" in result["notes"][1]
    assert "rule-based findings should be treated as analyst assists" in result["notes"][2]


class _HighVolumeImpactNoiseConnector(_StubConnector):
    def __init__(self):
        self._artifact_counts = [
            {"artifact_type": "Prefetch Files - Windows 8/10/11", "count": 4},
            {"artifact_type": "UserAssist", "count": 2},
            {"artifact_type": "Scheduled Tasks", "count": 3},
            {"artifact_type": "Potential Browser Activity", "count": 50},
            {"artifact_type": "Edge Downloads", "count": 3},
            {"artifact_type": "Text Documents", "count": 400},
            {"artifact_type": "$LogFile Analysis", "count": 8000},
            {"artifact_type": "NTFS LogFile Operation Candidates", "count": 1500},
            {"artifact_type": "UsnJrnl", "count": 200000},
            {"artifact_type": "USN Rename Transitions", "count": 2500},
            {"artifact_type": "File Signature Mismatch (Document)", "count": 15000},
        ]

    def search(self, keyword="", filters=None, limit=50, offset=0):
        filters = filters or {}
        artifact_type = filters.get("artifact_type")
        if artifact_type == "Text Documents":
            return {"total": 180, "hits": [{"hit_id": 10, "artifact_type": artifact_type, "source_path": r"C:\Boot\README.txt"}]}
        if artifact_type == "Encrypted Files":
            return {"total": 0, "hits": []}
        if artifact_type == "$LogFile Analysis":
            return {"total": 8000, "hits": [{"hit_id": 11, "artifact_type": artifact_type, "source_path": r"C:\$LogFile"}]}
        if artifact_type == "NTFS LogFile Operation Candidates":
            return {"total": 1500, "hits": [{"hit_id": 16, "artifact_type": artifact_type, "source_path": r"C:\$LogFile:page:4096"}]}
        if artifact_type == "UsnJrnl":
            return {"total": 200000, "hits": [{"hit_id": 12, "artifact_type": artifact_type, "source_path": r"C:\$Extend\$UsnJrnl"}]}
        if artifact_type == "USN Rename Transitions":
            return {"total": 2500, "hits": [{"hit_id": 17, "artifact_type": artifact_type, "source_path": r"C:\$Extend\$UsnJrnl:$J:rename:100:120"}]}
        if artifact_type == "File Signature Mismatch (Document)":
            return {"total": 15000, "hits": [{"hit_id": 13, "artifact_type": artifact_type, "source_path": r"C:\ProgramData\helper.dll"}]}
        if artifact_type == "Potential Browser Activity":
            return {"total": 50, "hits": [{"hit_id": 14, "artifact_type": artifact_type, "fields": {"URL": "https://remote.example"}}]}
        if artifact_type == "Edge Downloads":
            return {"total": 3, "hits": [{"hit_id": 15, "artifact_type": artifact_type, "fields": {"File Name": "agent.exe"}}]}
        return super().search(keyword=keyword, filters=filters, limit=limit, offset=offset)


def test_impact_bundle_uses_signal_score_instead_of_raw_volume():
    result = build_artifact_bundles(_HighVolumeImpactNoiseConnector())

    impact = next(b for b in result["artifact_bundles"] if b["bundle_id"] == "impact_evidence")
    remote = next(b for b in result["artifact_bundles"] if b["bundle_id"] == "remote_access_evidence")

    assert impact["evidence_total"] > remote["evidence_total"]
    assert impact["signal_score"] < impact["evidence_total"]
    assert any(
        a["artifact_type"] == "NTFS LogFile Operation Candidates"
        for a in impact["artifacts"]
    )
    assert any(
        a["artifact_type"] == "USN Rename Transitions"
        for a in impact["artifacts"]
    )
    assert remote["signal_score"] > 0
