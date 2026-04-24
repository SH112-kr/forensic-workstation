"""FW_FIXTURE environment-driven fixture preloading.

If ``FW_FIXTURE`` is set to a known fixture name, load that synthetic
connector and register it as the active case on the given ``app_state``.
Production runs (env unset) are unaffected.

The hook is idempotent so modules importing state more than once do not
attach the fixture twice.
"""

from __future__ import annotations

import os
import sys
from typing import Any


_PRELOAD_DONE_FLAG = "_fw_fixture_preloaded"


def preload_fixture_if_requested(app_state: Any) -> None:
    """Attach a fixture connector if FW_FIXTURE is set.

    Args:
        app_state: The live :class:`state.AppState` singleton. Must have
            ``set(name, connector)`` and a ``_connectors`` dict.
    """
    if getattr(app_state, _PRELOAD_DONE_FLAG, False):
        return
    name = os.environ.get("FW_FIXTURE", "").strip()
    if not name:
        return

    from regression.fixtures import load as load_fixture

    try:
        connector = load_fixture(name)
    except KeyError as e:
        print(
            f"[regression] FW_FIXTURE={name!r} is not a known fixture: {e}",
            file=sys.stderr,
        )
        raise SystemExit(2)

    app_state.set("axiom", connector)
    app_state.set("axiom:fixture", connector)
    # Mark so repeated imports do not re-inject.
    setattr(app_state, _PRELOAD_DONE_FLAG, True)
    print(f"[regression] Preloaded fixture: {name}")
