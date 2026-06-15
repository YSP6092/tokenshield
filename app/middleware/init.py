# app/middleware/__init__.py
from .detection import init_detection_middleware
from .ip_reputation import score_ip_reputation, get_ip_details, cache_stats, invalidate_cache
from .velocity import (
    record_and_score_velocity, get_request_count, reset_velocity,
    block_token, is_token_blocked, unblock_token, blocklist_stats,
)
from .redis_client import get_redis, is_available as redis_available, reset_connection
from .geo import score_geographic_impossibility, get_session_location
from .fingerprint import (
    ban_fingerprint, is_fingerprint_banned, unban_fingerprint,
    ban_session_fingerprint, get_request_fingerprint,
    banlist_stats as fingerprint_banlist_stats,
)
from .account_lock import (
    soft_lock_account, hard_lock_account, unlock_account,
    is_account_locked, get_lock_info, locked_accounts_count,
)
# app/middleware/__init__.py  — Step 3.5 update
# Add these two lines to your existing __init__.py

from .mitigation_timeline import (
    record_step,
    get_timeline,
    get_all_summaries,
    subscribe,
    unsubscribe,
    subscriber_count,
    STEPS as MITIGATION_STEPS,
)

# Also add to __all__:
# "record_step", "get_timeline", "get_all_summaries",
# "subscribe", "unsubscribe", "subscriber_count", "MITIGATION_STEPS",

__all__ = [
    "init_detection_middleware",
    # Step 1.2
    "score_ip_reputation", "get_ip_details", "cache_stats", "invalidate_cache",
    # Step 1.3
    "record_and_score_velocity", "get_request_count", "reset_velocity",
    "block_token", "is_token_blocked", "unblock_token", "blocklist_stats",
    "get_redis", "redis_available", "reset_connection",
    # Step 1.4
    "score_geographic_impossibility", "get_session_location",
    # Step 3.3
    "ban_fingerprint", "is_fingerprint_banned", "unban_fingerprint",
    "ban_session_fingerprint", "get_request_fingerprint", "fingerprint_banlist_stats",
    # Step 3.4
    "soft_lock_account", "hard_lock_account", "unlock_account",
    "is_account_locked", "get_lock_info", "locked_accounts_count",
]