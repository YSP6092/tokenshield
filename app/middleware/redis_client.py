"""
TokenShield — Step 1.3: Redis Connection Manager
=================================================
Single shared Redis client for the entire application.
All TokenShield subsystems import from here — never create their own client.

Key design decisions:
  - Lazy connection: Redis is not required at startup.  If it is
    unavailable, every get/set/incr returns a safe fallback value so
    the app keeps running in degraded mode (in-process tracking only).
  - decode_responses=True throughout — all keys and values are str.
  - Connection pool (max 20) shared across all threads.
  - REDIS_URL env var controls the connection string.
    Default: redis://localhost:6379/0

Environment variables:
  REDIS_URL=redis://localhost:6379/0      # standalone
  REDIS_URL=redis://:password@host:6379/0 # with auth
  REDIS_URL=redis://redis-cache:6379/0    # Docker service name (Step 8.1)
"""

import os
import logging
from typing import Optional

logger = logging.getLogger("tokenshield.redis")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

_client = None          # module-level singleton
_available = None       # None = untested, True/False = known state


def get_redis():
    """
    Return the shared Redis client, or None if Redis is unavailable.
    Performs a lazy PING on first call to confirm connectivity.
    Subsequent calls return the cached client/None without re-pinging.
    """
    global _client, _available

    if _available is True:
        return _client

    if _available is False:
        return None

    # First call — attempt connection
    try:
        import redis
        pool = redis.ConnectionPool.from_url(
            REDIS_URL,
            max_connections=20,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        candidate = redis.Redis(connection_pool=pool)
        candidate.ping()            # raises if Redis is down
        _client    = candidate
        _available = True
        logger.info("✅ tokenshield.redis: connected to %s", REDIS_URL)
        return _client

    except Exception as exc:
        _available = False
        logger.warning(
            "⚠️  tokenshield.redis: Redis unavailable (%s) — "
            "falling back to in-process tracking", exc
        )
        return None


def is_available() -> bool:
    """Return True if Redis is reachable."""
    get_redis()
    return _available is True


def reset_connection() -> None:
    """
    Force a reconnection attempt on the next get_redis() call.
    Useful after Docker brings the Redis container up after Flask.
    Call this from an admin endpoint if needed.
    """
    global _client, _available
    _client    = None
    _available = None
    logger.info("tokenshield.redis: connection reset — will retry on next request")