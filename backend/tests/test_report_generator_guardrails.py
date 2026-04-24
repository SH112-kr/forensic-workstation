from __future__ import annotations


class _StubAxiom:
    artifact_queries = object()

    def is_connected(self):
        return True

    def get_metadata(self):
        return {
            "case_name": "demo_case",
            "evidence_sources": ["demo.E01"],
            "total_hits": 123,
            "artifact_type_count": 5,
            "date_range_start": "2026-04-10T00:00:00Z",
            "date_range_end": "2026-04-15T00:00:00Z",
        }

    def get_artifact_type_counts(self):
        return [{"artifact_type": "Text Documents", "count": 4}]

    def get_timeline(self, limit=500):
        return {"entries": [{"timestamp": "2026-04-10T01:00:00Z", "artifact_type": "Demo", "description": "Event"}]}


def _patch_common(monkeypatch):
    import analysis.suspicious as suspicious
    import analysis.ioc_extractor as ioc_extractor
    import analysis.mitre_mapper as mitre_mapper
    import analysis.evidence_strength as evidence_strength
    import analysis.anti_forensics as anti_forensics
    import analysis.coverage as coverage
    import analysis.bias_remediation as bias_remediation

    monkeypatch.setattr(suspicious, "find_suspicious", lambda *_args, **_kwargs: {
        "findings": [
            {
                "rule_name": "evtx_eid_7045_service_installs",
                "query_description": "EID 7045 — service install events.",
                "matching_count": 3,
                "returned_count": 3,
                "truncated": False,
                "detail_cap": 20,
                "category": "persistence",
                "details": [],
                "mitre_techniques": ["T1543.003"],
            }
        ],
        "total_findings": 1,
        "zero_result_rules": [],
        "strength_rollup": {"confirmed": 1},
    })
    monkeypatch.setattr(evidence_strength, "score_findings", lambda payload: payload)
    monkeypatch.setattr(ioc_extractor, "extract_iocs", lambda *_args, **_kwargs: {"iocs": [], "total_iocs": 0})
    monkeypatch.setattr(mitre_mapper, "get_attack_narrative", lambda *_args, **_kwargs: {"narrative": [], "total_techniques": 0})
    monkeypatch.setattr(anti_forensics, "detect_anti_forensics", lambda *_args, **_kwargs: {"rules_fired": 0, "total_hits": 0, "rules": []})
    monkeypatch.setattr(coverage, "build_coverage_report", lambda *_args, **_kwargs: {"summary": {}, "coverage": []})
    monkeypatch.setattr(
        bias_remediation,
        "build_lane_evidence_summary_surface",
        lambda *_args, **_kwargs: {
            "lane_evidence_summary": {
                "ingress_access": {"artifact_families_seen": ["evtx_4624"], "event_count": 5},
                "execution_impact": {"artifact_families_seen": ["prefetch"], "event_count": 12},
                "persistence_cleanup": {"artifact_families_seen": ["services"], "event_count": 3},
            }
        },
    )


def test_generate_report_renders_key_findings_from_raw_findings(monkeypatch, tmp_path):
    import core.analysis.report_generator as report_generator
    _patch_common(monkeypatch)

    output = tmp_path / "report.html"
    result = report_generator.generate_report({"axiom": _StubAxiom()}, output_path=str(output))

    assert result["status"] == "success"
    html = output.read_text(encoding="utf-8")
    assert "<h2>Key Findings</h2>" in html
    # Verdict/prescription sections must be absent
    assert "Candidate Axes" not in html
    assert "Candidate hypotheses" not in html
    assert "Evidence Alerts" not in html
    assert "Investigation incomplete" not in html
    # Raw finding data is present in the embedded JSON
    assert "evtx_eid_7045_service_installs" in html
    assert "T1543.003" in html


def test_generate_report_lane_evidence_summary_section_rendered(monkeypatch, tmp_path):
    import core.analysis.report_generator as report_generator
    _patch_common(monkeypatch)

    output = tmp_path / "report_les.html"
    result = report_generator.generate_report({"axiom": _StubAxiom()}, output_path=str(output))

    assert result["status"] == "success"
    html = output.read_text(encoding="utf-8")
    assert "Lane Evidence Summary" in html
    # Fact labels present
    assert "Ingress / Access" in html
    assert "Execution / Impact" in html
    assert "Persistence / Cleanup" in html
    # No old verdict fields
    assert "allow_strong_conclusion" not in html
    assert "lane_state_board" not in html
