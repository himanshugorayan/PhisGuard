import threading
import time


class TTLCache:
    """Tiny thread-safe in-memory cache (keeps us inside VirusTotal's free quota)."""

    def __init__(self, ttl: float = 3600, maxsize: int = 2048):
        self.ttl, self.maxsize = ttl, maxsize
        self._d: dict = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._d.get(key)
            if not item:
                return None
            value, expires = item
            if expires < time.time():
                del self._d[key]
                return None
            return value

    def set(self, key, value):
        with self._lock:
            if len(self._d) >= self.maxsize:
                self._d.pop(next(iter(self._d)))
            self._d[key] = (value, time.time() + self.ttl)
