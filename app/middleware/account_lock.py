"""
TokenShield — Step 3.4: Account 2FA Lock
=========================================
When a session is auto-revoked (score >= 0.85), the associated user
account is locked behind mandatory TOTP 2FA.

What this achieves
------------------
Steps 1–3 block the current session / IP / device.
Step 4 goes one level deeper: even if the attacker:
  - Gets past IP blocking (new VPN)
  - Clears cookies / gets a new fingerprint
  - Has the victim's username + password

...they still cannot log in without the TOTP code from the
victim's authenticator app. The account is protected at the
authentication layer, not just the session layer.

Two lock modes
--------------
SOFT LOCK  (default on auto-revoke)
  failed_login_attempts set to 99.
  Auth route already gates on this (>= 99 → requires 2FA).
  User must complete /api/auth/login-2fa with their TOTP code.
  If they don't have TOTP set up, they call /api/auth/request-unlock
  which emails them a one-time code (Step 3.5 hooks in here).

HARD LOCK  (admin-triggered, or coordinated attack detected)
  is_active set to False.
  Account is completely disabled until admin unlocks it.
  Used by Step 6.1 (coordinated attack detection).

Redis state
-----------
  ts:lock:{user_id}   →  JSON { reason, locked_at, lock_type, session_id }
  TTL: 24 hours
  Survives Flask restart. Admin dashboard reads this key to show
  which accounts are currently locked.

Fallback
--------
If Redis is unavailable, the lock is still written to the DB
(failed_login_attempts = 99). Redis is the fast read path;
DB is the source of truth.
"""

import json
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger("tokenshield.account_lock")

LOCK_PREFIX  = "ts:lock:"
LOCK_TTL     = 24 * 3600       # 24 hours
SOFT_LOCK_THRESHOLD = 99       # matches auth.py gate


# ---------------------------------------------------------------------------
# Core lock / unlock
# ---------------------------------------------------------------------------

def soft_lock_account(user_id: int, session_id: int, reason: str) -> bool:
    """
    Apply a soft lock to a user account:
      - Sets failed_login_attempts = 99 in DB (triggers 2FA gate in auth.py)
      - Writes lock record to Redis (fast read by dashboard)

    Returns True if DB write succeeded.
    """
    success = _write_db_lock(user_id, soft=True)
    _write_redis_lock(user_id, session_id, reason, lock_type="soft")
    if success:
        logger.warning(
            "tokenshield.account_lock: SOFT LOCK uid=%d sid=%d reason=%s",
            user_id, session_id, reason,
        )
    return success


def hard_lock_account(user_id: int, session_id: int, reason: str) -> bool:
    """
    Apply a hard lock to a user account:
      - Sets is_active = False in DB (blocks all logins)
      - Writes lock record to Redis

    Returns True if DB write succeeded.
    Admin must call unlock_account() to restore access.
    """
    success = _write_db_lock(user_id, soft=False)
    _write_redis_lock(user_id, session_id, reason, lock_type="hard")
    if success:
        logger.warning(
            "tokenshield.account_lock: HARD LOCK uid=%d sid=%d reason=%s",
            user_id, session_id, reason,
        )
    return success


def unlock_account(user_id: int) -> bool:
    """
    Clear all locks on a user account:
      - Resets failed_login_attempts = 0, is_active = True in DB
      - Removes Redis lock key

    Returns True if DB write succeeded.
    """
    success = _clear_db_lock(user_id)
    _clear_redis_lock(user_id)
    if success:
        logger.info("tokenshield.account_lock: UNLOCKED uid=%d", user_id)
    return success


def is_account_locked(user_id: int) -> tuple[bool, Optional[dict]]:
    """
    Check whether a user account is currently locked.
    Reads from Redis first (fast), falls back to DB.
    Returns (locked: bool, lock_info: dict | None).
    """
    # Redis fast path
    try:
        from app.middleware.redis_client import get_redis
        r = get_redis()
        if r:
            raw = r.get(LOCK_PREFIX + str(user_id))
            if raw:
                return True, json.loads(raw)
    except Exception as exc:
        logger.debug("tokenshield.account_lock: Redis read failed — %s", exc)

    # DB fallback
    try:
        from app.models import User
        user = User.query.get(user_id)
        if user is None:
            return False, None
        if not user.is_active:
            return True, {"lock_type": "hard", "reason": "account_disabled"}
        if (user.failed_login_attempts or 0) >= SOFT_LOCK_THRESHOLD:
            return True, {"lock_type": "soft", "reason": "failed_attempts_threshold"}
        return False, None
    except Exception as exc:
        logger.error("tokenshield.account_lock: DB check failed — %s", exc)
        return False, None


def get_lock_info(user_id: int) -> Optional[dict]:
    """Return the Redis lock record for a user, or None if not locked."""
    try:
        from app.middleware.redis_client import get_redis
        r = get_redis()
        if r:
            raw = r.get(LOCK_PREFIX + str(user_id))
            if raw:
                return json.loads(raw)
    except Exception:
        pass
    return None


def locked_accounts_count() -> int:
    """Return number of currently locked accounts tracked in Redis."""
    try:
        from app.middleware.redis_client import get_redis
        r = get_redis()
        if r:
            return len(r.keys(LOCK_PREFIX + "*"))
    except Exception:
        pass
    return 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _write_db_lock(user_id: int, soft: bool) -> bool:
    """Write the DB-side lock. Returns True on success."""
    try:
        from app.extensions import db
        from app.models import User
        user = User.query.get(user_id)
        if user is None:
            return False
        if soft:
            user.failed_login_attempts = SOFT_LOCK_THRESHOLD
        else:
            user.is_active             = False
            user.failed_login_attempts = SOFT_LOCK_THRESHOLD
        db.session.commit()
        return True
    except Exception as exc:
        logger.error("tokenshield.account_lock: DB write failed — %s", exc)
        try:
            from app.extensions import db
            db.session.rollback()
        except Exception:
            pass
        return False


def _clear_db_lock(user_id: int) -> bool:
    """Clear the DB-side lock. Returns True on success."""
    try:
        from app.extensions import db
        from app.models import User
        user = User.query.get(user_id)
        if user is None:
            return False
        user.failed_login_attempts = 0
        user.is_active             = True
        user.totp_secret           = None
        user.totp_enabled          = False
        db.session.commit()
        return True
    except Exception as exc:
        logger.error("tokenshield.account_lock: DB clear failed — %s", exc)
        try:
            from app.extensions import db
            db.session.rollback()
        except Exception:
            pass
        return False


def _write_redis_lock(
    user_id: int,
    session_id: int,
    reason: str,
    lock_type: str,
) -> None:
    """Write lock metadata to Redis. Fails silently."""
    try:
        from app.middleware.redis_client import get_redis
        r = get_redis()
        if r is None:
            return
        record = json.dumps({
            "user_id":    user_id,
            "session_id": session_id,
            "reason":     reason,
            "lock_type":  lock_type,
            "locked_at":  datetime.utcnow().isoformat(),
        })
        r.setex(LOCK_PREFIX + str(user_id), LOCK_TTL, record)
    except Exception as exc:
        logger.debug("tokenshield.account_lock: Redis write failed — %s", exc)


def _clear_redis_lock(user_id: int) -> None:
    """Remove lock key from Redis. Fails silently."""
    try:
        from app.middleware.redis_client import get_redis
        r = get_redis()
        if r:
            r.delete(LOCK_PREFIX + str(user_id))
    except Exception:
        pass