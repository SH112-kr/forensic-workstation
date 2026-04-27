from __future__ import annotations

from core import dependencies


def test_diagnose_exception_reports_missing_dependency(monkeypatch):
    def fake_report():
        return {
            "dependencies": [
                {
                    "key": "regipy",
                    "display_name": "regipy",
                    "available": False,
                    "required_for": "Offline Windows registry hive parsing",
                    "install_hint": "python -m pip install regipy",
                }
            ]
        }

    monkeypatch.setattr(dependencies, "dependency_report", fake_report)

    diagnostic = dependencies.diagnose_exception("ModuleNotFoundError: No module named 'regipy'")

    assert diagnostic is not None
    assert diagnostic["type"] == "missing_dependency"
    assert diagnostic["dependency"]["key"] == "regipy"
    assert diagnostic["recovery"] == "python -m pip install regipy"


def test_dependency_report_has_blocking_capability_context():
    report = dependencies.dependency_report()

    regipy = next(item for item in report["dependencies"] if item["key"] == "regipy")

    assert regipy["required_for"]
    assert "Service persistence registry review" in regipy["blocked_capabilities"]
    assert report["overall_status"] in {"ready", "degraded", "blocked"}
