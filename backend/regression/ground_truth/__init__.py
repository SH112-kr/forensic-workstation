"""Ground-truth JSON loader for fixture cases."""

from __future__ import annotations

import json
import os


_GT_DIR = os.path.dirname(os.path.abspath(__file__))


def load(fixture_name: str) -> dict:
    """Return ground truth dict for the named fixture.

    Raises ``FileNotFoundError`` if the fixture has no ground truth yet.
    """
    path = os.path.join(_GT_DIR, f"{fixture_name}.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def available() -> list[str]:
    out = []
    for name in os.listdir(_GT_DIR):
        if name.endswith(".json"):
            out.append(name[:-5])
    return sorted(out)
