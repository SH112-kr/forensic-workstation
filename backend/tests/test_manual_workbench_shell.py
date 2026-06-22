from __future__ import annotations

import asyncio
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _run(coro):
    return asyncio.run(coro)


def test_manual_status_reports_selected_image_and_guardrails(monkeypatch):
    from api import manual

    monkeypatch.setattr(
        manual,
        "resolve_image_evidence",
        lambda _ref="": {"path": r"D:\cases\host.E01", "source": "allowed_evidence"},
    )

    result = _run(manual.manual_status())

    assert result["analyst_only"] is True
    assert result["llm_auto_ingest"] is False
    assert result["auto_ioc_graph"] is False
    assert result["selected_image"] == r"D:\cases\host.E01"
    assert result["selected_image_source"] == "allowed_evidence"
    assert result["connected"] is True
    assert any("not verdict" in note.lower() for note in result["guardrails"])


def test_manual_status_handles_missing_selected_image(monkeypatch):
    from api import manual

    monkeypatch.setattr(manual, "resolve_image_evidence", lambda _ref="": {})

    result = _run(manual.manual_status())

    assert result["selected_image"] == ""
    assert result["selected_image_source"] == ""
    assert result["connected"] is False
    assert any("selected image" in note.lower() for note in result["guardrails"])


def test_manual_workbench_layout_contract_is_stable():
    component = ROOT / "frontend" / "src" / "components" / "ManualWorkbench.tsx"
    layout = ROOT / "frontend" / "src" / "components" / "Layout.tsx"
    sidebar = ROOT / "frontend" / "src" / "components" / "Sidebar.tsx"
    translations = ROOT / "frontend" / "src" / "i18n" / "translations.ts"

    component_src = component.read_text(encoding="utf-8")
    layout_src = layout.read_text(encoding="utf-8")
    sidebar_src = sidebar.read_text(encoding="utf-8")
    translations_src = translations.read_text(encoding="utf-8")

    assert "gridTemplateColumns: '220px minmax(420px, 1fr) 280px'" in component_src
    assert "overflow: 'hidden'" in component_src
    assert "overflowWrap: 'anywhere'" in component_src
    assert "minHeight: 0" in component_src
    assert "Manual Workbench is analyst-facing only" in component_src

    assert "import ManualWorkbench from './ManualWorkbench'" in layout_src
    assert "manual: ManualWorkbench" in layout_src
    assert "id: 'manual'" in sidebar_src
    assert "nav.manualWorkbench" in sidebar_src
    assert "manualWorkbench" in translations_src
