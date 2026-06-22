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


def test_missing_pcap_dependencies_do_not_degrade_endpoint_ir_readiness(monkeypatch):
    missing = {"pyshark", "tshark"}

    monkeypatch.setattr(
        dependencies,
        "_check_import",
        lambda name: False if name in missing else True,
    )
    monkeypatch.setattr(
        dependencies.shutil,
        "which",
        lambda name: None if name in missing else f"C:/tools/{name}",
    )

    report = dependencies.dependency_report()
    by_key = {item["key"]: item for item in report["dependencies"]}

    assert report["overall_status"] == "ready"
    assert by_key["pyshark"]["available"] is False
    assert by_key["tshark"]["available"] is False
    assert by_key["pyshark"]["affects_overall_status"] is False
    assert by_key["tshark"]["affects_overall_status"] is False
