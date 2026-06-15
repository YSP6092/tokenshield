"""
TokenShield — Step 1.3: Redis Velocity Tracker + Session Blocklist
==================================================================
Two responsibilities:

1. VELOCITY TRACKING  (replaces _VelocityTracker in detection.py)
   Redis key: ts:vel:{ip}
   Strategy:  INCR + EXPIRE (sliding approximation with 60s window).
              Each request increments a counter.  The key expires 60s
              after it was first created.  On miss the key is re-created.
   Scores:
     ≥ 200 req/60s → 0.30
     ≥ 100 req/60s → 0.20
     ≥  50 req/60s → 0.10
     ≥  20 req/60s → 0.05

2. SESSION BLOCKLIST  (instant token revocation without a DB query)
   Redis key: ts:block:{token_hash}
   Value:     reason string
   TTL:       matches JWT expiry (24h by default)
   On revoke: write key to Redis AND update DB (belt + suspenders).
   On check:  Redis EXISTS is O(1) — far faster than a DB query.
   Fallback:  if Redis is down, falls back to DB query (existing behaviour).

All functions fail gracefully — if Redis is unavailable they return
the in-process fallback so the rest of the pipeline is unaffected.
"""

import logging
import hashlib
from typing import Optional
from datetime import timedelta

from app.middleware.redis_client import get_redis

logger = logging.getLogger("tokenshield.velocity")

# ---------------------------------------------------------------------------
# Key schema
# ---------------------------------------------------------------------------

VELOCITY_PREFIX  = "ts:vel:"      # ts:vel:<ip>
BLOCKLIST_PREFIX = "ts:block:"    # ts:block:<token_hash>

VELOCITY_WINDOW  = 60             # seconds
BLOCKLIST_TTL    = 60 * 60 * 24  # 24 hours (matches JWT expiry)

# Velocity thresholds → score
VELOCITY_THRESHOLDS = [
    (200, 0.30),
    (100, 0.20),
    (50,  0.10),
    (20,  0.05),
]

# ---------------------------------------------------------------------------
# In-process fallback (used when Redis is down — imported from detection.py)
# ---------------------------------------------------------------------------

from collections import defaultdict, deque
from datetime import datetime

class _InProcessFallback:
    """Identical to the original _VelocityTracker in detection.py."""
    def __init__(self):
        from datetime import timedelta as _td
        self._td = _td
        self._windows: dict[str, deque] = defaultdict(deque)

    def record_and_score(self, ip: str) -> tuple[float, Optional[str]]:
        now    = datetime.utcnow()
        cutoff = now - self._td(seconds=VELOCITY_WINDOW)
        q = self._windows[ip]
        q.append(now)
        while q and q[0] < cutoff:
            q.popleft()
        count = len(q)
        for threshold, score in VELOCITY_THRESHOLDS:
            if count >= threshold:
                return score, f"velocity:{count}_req/60s"
        return 0.0, None


_fallback = _InProcessFallback()

# ---------------------------------------------------------------------------
# Velocity — public API
# ---------------------------------------------------------------------------

def record_and_score_velocity(ip: str) -> tuple[float, Optional[str]]:
    """
    Increment the request counter for this IP and return (score, reason).
    Uses Redis when available, falls back to in-process dict.
    """
    r = get_redis()

    if r is None:
        return _fallback.record_and_score(ip)

    key = VELOCITY_PREFIX + ip
    try:
        pipe  = r.pipeline()
        pipe.incr(key)
        pipe.ttl(key)
        count, ttl = pipe.execute()

        # Set expiry only on first increment (ttl == -1 means no expiry set)
        if ttl == -1:
            r.expire(key, VELOCITY_WINDOW)

        for threshold, score in VELOCITY_THRESHOLDS:
            if count >= threshold:
                logger.debug("tokenshield.velocity: ip=%s count=%d score=%.2f", ip, count, score)
                return score, f"velocity:{count}_req/60s"

        return 0.0, None

    except Exception as exc:
        logger.error("tokenshield.velocity: Redis error (%s) — using fallback", exc)
        return _fallback.record_and_score(ip)


def get_request_count(ip: str) -> int:
    """Return current 60s request count for an IP (0 if unknown)."""
    r = get_redis()
    if r is None:
        return 0
    try:
        val = r.get(VELOCITY_PREFIX + ip)
        return int(val) if val else 0
    except Exception:
        return 0


def reset_velocity(ip: str) -> None:
    """Delete the velocity counter for an IP (e.g. after a successful CAPTCHA)."""
    r = get_redis()
    if r is None:
        return
    try:
        r.delete(VELOCITY_PREFIX + ip)
    except Exception as exc:
        logger.error("tokenshield.velocity: reset failed for %s — %s", ip, exc)


# ---------------------------------------------------------------------------
# Session blocklist — public API
# ---------------------------------------------------------------------------

def block_token(token: str, reason: str, ttl_seconds: int = BLOCKLIST_TTL) -> bool:
    """
    Add a token to the Redis blocklist.
    Returns True if written successfully, False if Redis is unavailable.
    The DB revocation in _mitigate() still runs regardless of this return value.
    """
    r = get_redis()
    if r is None:
        return False

    token_hash = _hash_token(token)
    key = BLOCKLIST_PREFIX + token_hash
    try:
        r.setex(key, ttl_seconds, reason)
        logger.info("tokenshield.blocklist: token blocked hash=%s reason=%s", token_hash[:8], reason)
        return True
    except Exception as exc:
        logger.error("tokenshield.blocklist: block_token failed — %s", exc)
        return False


def is_token_blocked(token: str) -> tuple[bool, Optional[str]]:
    """
    Check whether a token is on the blocklist.
    Returns (blocked: bool, reason: str | None).
    Falls back to False (not blocked) if Redis is unavailable —
    the DB session check in token_required() still catches it.
    """
    r = get_redis()
    if r is None:
        return False, None

    token_hash = _hash_token(token)
    key = BLOCKLIST_PREFIX + token_hash
    try:
        reason = r.get(key)
        if reason:
            return True, reason
        return False, None
    except Exception as exc:
        logger.error("tokenshield.blocklist: is_token_blocked failed — %s", exc)
        return False, None


def unblock_token(token: str) -> bool:
    """Remove a token from the blocklist (e.g. after manual review)."""
    r = get_redis()
    if r is None:
        return False
    try:
        r.delete(BLOCKLIST_PREFIX + _hash_token(token))
        return True
    except Exception:
        return False


def blocklist_stats() -> dict:
    """Return count of currently blocked tokens (admin dashboard use)."""
    r = get_redis()
    if r is None:
        return {"available": False, "blocked_count": 0}
    try:
        keys = r.keys(BLOCKLIST_PREFIX + "*")
        return {"available": True, "blocked_count": len(keys)}
    except Exception:
        return {"available": False, "blocked_count": 0}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_token(token: str) -> str:
    """SHA-256 hash of a raw JWT — matches hash_token() in utils.py."""
    return hashlib.sha256(token.encode()).hexdigest()