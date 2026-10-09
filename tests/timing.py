"""Cost per MB for the performance tests.

Limits are in seconds per MB (10^6 bytes of UTF-8 input), so tests of different sizes compare, and a
limit reads as a throughput: 0.25 s/MB is 4 MB of commands a second.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable


def size_mb(texts: str | Iterable[str]) -> float:
    if isinstance(texts, str):
        texts = [texts]
    return sum(len(t.encode("utf-8", "surrogatepass")) for t in texts) / 1_000_000


def seconds_per_mb(run: Callable[[], object], mb: float, repeat: int = 1) -> float:
    """Seconds per MB of the fastest of ``repeat`` runs."""
    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        run()
        best = min(best, time.perf_counter() - start)
    return best / mb
