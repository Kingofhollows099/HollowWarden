"""A small in-memory sliding-window rate limiter."""

from __future__ import annotations

import time
from collections import OrderedDict, deque


class RateLimiter:
    """Allow at most `maxEvents` per key within `windowSeconds`.

    The number of tracked keys is capped. Without a cap, someone sending
    requests from many different addresses could make this dictionary grow
    until the process ran out of memory.
    """

    def __init__(self, maxEvents: int, windowSeconds: float, maxKeys: int = 10_000) -> None:
        self.maxEvents = maxEvents
        self.windowSeconds = windowSeconds
        self.maxKeys = maxKeys
        self._events: OrderedDict[object, deque[float]] = OrderedDict()
        self._lastPrune = float("-inf")

    def allow(self, key: object, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        cutoff = now - self.windowSeconds
        # Sweep out idle keys once per window, so entries don't stay in memory
        # after their window has passed.
        if now - self._lastPrune >= self.windowSeconds:
            self._pruneExpired(cutoff)
            self._lastPrune = now

        timestamps = self._events.get(key)
        if timestamps is None:
            if len(self._events) >= self.maxKeys:
                self._pruneExpired(cutoff)
            if len(self._events) >= self.maxKeys:
                self._events.popitem(last=False)
            timestamps = self._events[key] = deque()
        self._events.move_to_end(key)

        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        if len(timestamps) >= self.maxEvents:
            return False
        timestamps.append(now)
        return True

    def _pruneExpired(self, cutoff: float) -> None:
        expiredKeys = [key for key, timestamps in self._events.items() if not timestamps or timestamps[-1] <= cutoff]
        for key in expiredKeys:
            del self._events[key]
