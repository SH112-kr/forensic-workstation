from __future__ import annotations


def test_external_validation_runner_uses_allowlisted_non_executable_sources(monkeypatch, tmp_path):
    import regression.external_validation as mod

    safe_datasets = {
        name: {**spec, "path": tmp_path / spec["path"].name}
        for name, spec in mod.SAFE_DATASETS.items()
    }
    monkeypatch.setattr(mod, "SAFE_DATASETS", safe_datasets)
    for spec in safe_datasets.values():
        spec["path"] = tmp_path / spec["path"].name

    names = []

    def fake_download(name):
        names.append(name)
        path = mod.SAFE_DATASETS[name]["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
        return {
            "name": name,
            "path": str(path),
            "type": mod.SAFE_DATASETS[name]["type"],
            "downloaded": True,
            "safety": {"allowlisted": True, "executables_allowed": False, "malware_samples_allowed": False},
        }

    monkeypatch.setattr(mod, "download_allowlisted", fake_download)
    monkeypatch.setattr(mod, "validate_scenarios", lambda _path: {"ok": True, "dataset": "evtx"})
    monkeypatch.setattr(mod, "validate_otrf_scenario", lambda _path: {"ok": True, "dataset": "otrf"})
    monkeypatch.setattr(mod, "validate_apt29_dataset", lambda _path: {"ok": True, "dataset": "apt29"})
    monkeypatch.setattr(mod, "validate_cfreds_hacking_case", lambda download=False: {"ok": True, "dataset": "cfreds"})

    result = mod.run_external_validation(download=True)

    assert set(names) == set(mod.SAFE_DATASETS)
    assert result["ok"] is True
    assert result["safety_policy"]["download_executables"] is False
    assert result["safety_policy"]["execute_extracted_files"] is False
