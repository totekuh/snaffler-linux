"""Generic thread-local connection cache with health checks.

Replaces the duplicated connection caching pattern across SMBFileAccessor,
SMBTreeWalker, ShareFinder, FTPFileAccessor, and FTPTreeWalker.
"""

import threading
from typing import Callable, TypeVar

T = TypeVar("T")


class ThreadLocalConnectionCache:
    """Thread-local connection cache with health checks, eviction, and bulk close.

    Each worker thread maintains its own cache dict keyed by *key*.
    Before returning a cached connection, the health check is run; stale
    connections are evicted and replaced transparently.

    Parameters:
        connect_fn: ``(key) -> connection`` — creates a new connection.
        health_check_fn: ``(conn) -> None`` — raises on dead connection.
        disconnect_fn: ``(conn) -> None`` — cleanup (logoff / quit).
        cache_attr: Name of the thread-local attribute storing the cache dict.
    """

    def __init__(
        self,
        connect_fn: Callable,
        health_check_fn: Callable,
        disconnect_fn: Callable,
        cache_attr: str = "cache",
    ):
        self._connect_fn = connect_fn
        self._health_check_fn = health_check_fn
        self._disconnect_fn = disconnect_fn
        self._cache_attr = cache_attr

        self._thread_local = threading.local()
        self._all_connections = []
        self._conn_lock = threading.Lock()

    def get(self, key):
        """Return a cached connection for *key*, creating one if needed."""
        cache = getattr(self._thread_local, self._cache_attr, None)
        if cache is None:
            cache = {}
            setattr(self._thread_local, self._cache_attr, cache)

        conn = cache.get(key)
        if conn is not None:
            try:
                self._health_check_fn(conn)
                return conn
            except Exception:
                self._evict(cache, key, conn)

        conn = self._connect_fn(key)
        cache[key] = conn
        with self._conn_lock:
            self._all_connections.append(conn)
        return conn

    def invalidate(self, key):
        """Disconnect and remove a cached connection for *key*."""
        cache = getattr(self._thread_local, self._cache_attr, None)
        if cache is None:
            return
        conn = cache.pop(key, None)
        if conn is not None:
            with self._conn_lock:
                try:
                    self._all_connections.remove(conn)
                except ValueError:
                    pass
            try:
                self._disconnect_fn(conn)
            except Exception:
                pass

    def close_all(self):
        """Close all cached connections across all threads."""
        with self._conn_lock:
            for conn in self._all_connections:
                try:
                    self._disconnect_fn(conn)
                except Exception:
                    pass
            self._all_connections.clear()

    def _evict(self, cache, key, conn):
        """Remove a stale connection from the cache and global list."""
        with self._conn_lock:
            try:
                self._all_connections.remove(conn)
            except ValueError:
                pass
        try:
            self._disconnect_fn(conn)
        except Exception:
            pass
        cache.pop(key, None)
