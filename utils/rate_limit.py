import time
import threading

_lock = threading.Lock()
_hits: dict[str, list[float]] = {}


def check_and_record(key: str, limit: int = 3, window_seconds: int = 3600) -> tuple[bool, int]:
    """Return (allowed, remaining). Sliding-window counter, in-memory."""
    now = time.time()
    cutoff = now - window_seconds
    with _lock:
        stamps = [t for t in _hits.get(key, []) if t > cutoff]
        if len(stamps) >= limit:
            _hits[key] = stamps
            return False, 0
        stamps.append(now)
        _hits[key] = stamps
        return True, limit - len(stamps)
