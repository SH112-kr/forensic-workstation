"""Parallel $MFT scanning — shard the segment range across worker processes.

The expensive part of the MFT inventory is dissect's per-record parsing
(``full_path()`` walks + attribute decode), which is pure-Python and
CPU-bound. ``Mft.segments(start, end)`` already accepts an inclusive segment
slice and preserves skip-vs-error semantics, so we shard [0, last_segment]
into contiguous ranges and parse them in parallel worker processes.

Only the *parse* is parallelized. The parent still inserts serially via
``RawIndexStore`` so the FTS / search-text / id integrity is untouched.
imap_unordered streams each shard's records back as it finishes, overlapping
worker parsing with the parent's insert loop.

No-miss: a shard that fails to even start streaming returns a single gap
record instead of raising, so one bad shard never aborts the whole scan.
Per-record failures are already yielded as gap dicts by iter_mft_records.
"""

from __future__ import annotations

import multiprocessing as mp
import os
from typing import Any, Iterator


# Per-process worker state. Each spawned worker opens the E01 image exactly
# once (via the Pool initializer) and reuses that handle across every chunk
# it is assigned — re-opening per chunk would cost ~15-25s each.
_WORKER: dict[str, Any] = {}


# Each worker opens its OWN copy of the E01 image (~1.7 GB resident on the
# validation laptop), and the parent's serial insert (~220s on a 1.27M-file
# volume) is the wall-clock floor: once parsing is sharded below that floor,
# more workers only add image-memory pressure for no speedup. So the default
# is capped low regardless of core count — 8 shards already hide the parse
# behind the insert on a many-core box without a 30-worker × 1.7 GB blowup.
_MAX_DEFAULT_WORKERS = 8


def default_worker_count() -> int:
    """Memory- and insert-bound-aware default shard count (min 1).

    Leaves 2 cores for the parent insert loop + OS, then caps at
    ``_MAX_DEFAULT_WORKERS`` because each shard holds a full image handle and
    the serial insert is the floor. Callers may pass an explicit ``workers``
    to override (e.g. a RAM-constrained host should lower it)."""
    return max(1, min((os.cpu_count() or 4) - 2, _MAX_DEFAULT_WORKERS))


def segment_ranges(last_segment: int, chunk_size: int) -> list[tuple[int, int]]:
    """Inclusive [start, end] shards covering segments 0..last_segment.

    The end bound matches ``Mft.segments(start, end)`` (inclusive). Returns an
    empty list when there is nothing to scan so callers can short-circuit.
    """
    if last_segment <= 0 or chunk_size <= 0:
        return []
    return [
        (start, min(start + chunk_size - 1, last_segment))
        for start in range(0, last_segment + 1, chunk_size)
    ]


def _init_worker(e01_path: str, volume_ref: str) -> None:
    # Store the args only. Opening the E01 here would make a connect failure an
    # initializer crash, which under the spawn start method can respawn workers
    # and hang the pool. Defer the open to the first _scan_chunk so a failure
    # becomes a coverage gap instead.
    _WORKER["e01_path"] = e01_path
    _WORKER["vref"] = volume_ref
    _WORKER["conn"] = None


def _scan_chunk(seg_range: tuple[int, int]) -> list[dict[str, Any]]:
    """Parse one inclusive segment slice; return records (entries + gap dicts).

    The E01 is opened lazily on the first chunk and cached for the worker's
    lifetime. A connect failure or whole-shard parse failure is downgraded to a
    single gap record so the parent keeps inserting the other shards (no-miss).
    """
    try:
        conn = _WORKER.get("conn")
        if conn is None:
            from core.connectors.e01_image import E01ImageConnector

            conn = E01ImageConnector()
            conn.connect(_WORKER["e01_path"])
            _WORKER["conn"] = conn
        vref = _WORKER["vref"]
        return list(conn.iter_mft_records(vref, segment_range=seg_range))
    except Exception as exc:  # noqa: BLE001 — one shard must not abort the scan
        return [{
            "error": f"shard_scan_failed: {exc}",
            "segment": seg_range[0],
            "reason": "mft_shard_error",
        }]


def parallel_mft_record_stream(
    e01_path: str,
    volume_ref: str,
    last_segment: int,
    workers: int,
    *,
    chunk_size: int = 20000,
) -> Iterator[dict[str, Any]]:
    """Yield $MFT records (same shape as ``iter_mft_records``) in parallel.

    Records arrive shard-by-shard (unordered) as workers finish, so the
    consumer can insert them while later shards are still being parsed.
    """
    ranges = segment_ranges(last_segment, chunk_size)
    if not ranges:
        return
    workers = max(1, int(workers))
    # spawn: required on Windows and safest cross-platform (no forked dissect
    # handles). Workers re-import this module and re-open the image cleanly.
    ctx = mp.get_context("spawn")
    pool = ctx.Pool(
        processes=workers,
        initializer=_init_worker,
        initargs=(e01_path, volume_ref),
    )
    try:
        for records in pool.imap_unordered(_scan_chunk, ranges):
            for rec in records:
                yield rec
    except BaseException:
        # Consumer raised / generator closed / insert failed: don't block on the
        # remaining shards — kill them now instead of close()+join() waiting.
        pool.terminate()
        raise
    else:
        pool.close()
    finally:
        pool.join()
