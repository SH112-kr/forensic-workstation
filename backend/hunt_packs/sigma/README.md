# Sigma rules (B-1 subset loader)

Drop community or case-derived Sigma `.yml` rules here. They are loaded by
`hunt_evtx_rules(include_sigma=True)` via `core/analysis/sigma_loader.py`.

## Supported subset (everything else is skipped, with a reason)

- `logsource.product: windows` (other products are skipped)
- `detection.condition: selection` (single bare map only)
- `detection.selection`:
  - `EventID:` int or list
  - `<field>|contains:` string or list (becomes OR keyword needles)
  - bare `<field>:` string equality (also keyword needle)

## Not supported (rule is dropped, feature counted in `sigma_load`)

`|re`, `|base64*`, `|all`, numeric field comparisons, `1 of`/`all of`/`not`
conditions, multiple selection maps. The engine does EID + substring matching
only — anything requiring richer logic is declined rather than approximated,
so coverage is never overstated.

Each loaded rule is published with `provenance.origin: sigma-community` and is
treated as an **evidence hint**, never a verdict.
