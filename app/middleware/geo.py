"""
TokenShield — Step 1.4: Geographic Impossibility (Signal 6)
============================================================
Detects when a session's current IP location is physically
unreachable given the elapsed time since the last known location.

Algorithm
---------
1. Resolve current request IP → (lat, lon) via IPinfo cache
2. Look up the last recorded location for this session from Redis
   (falls back to BehaviorLog DB scan if Redis is unavailable)
3. Compute great-circle distance (Haversine formula)
4. Compute minimum travel time at MAX_SPEED_KMH (commercial aviation)
5. Compare against actual elapsed time

Scoring
-------
  Impossible travel (would require > MAX_SPEED_KMH)  → +0.35
  Highly suspicious (> 0.75× of max speed threshold) → +0.20
  Mildly suspicious (> 0.50× of max speed threshold) → +0.10
  First request / same location / private IP          → +0.00

Location storage
----------------
  Redis key : ts:geo:{session_id}
  Value     : JSON  { lat, lon, ip, ts (ISO-8601) }
  TTL       : 25 hours  (slightly longer than JWT lifetime)
  Fallback  : BehaviorLog.fingerprint_data scan (last 10 rows)

Important edge cases handled
-----------------------------
  - Private / Docker IPs          → skip (no geo data)
  - IPinfo returns no coordinates → skip gracefully
  - Same IP as last request       → skip (no movement)
  - First request in session      → store location, score 0.0
  - Redis unavailable             → fall back to DB location lookup
  - IPinfo token not set          → no coordinates → score 0.0
"""

import json
import math
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("tokenshield.geo")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_SPEED_KMH    = 900.0    # ~commercial jet cruising speed
EARTH_RADIUS_KM  = 6_371.0
GEO_KEY_PREFIX   = "ts:geo:"
GEO_TTL_SECONDS  = 25 * 3600   # 25 hours

# Score thresholds — fraction of what would be required speed vs MAX_SPEED
# ratio = required_speed / MAX_SPEED_KMH
SCORE_IMPOSSIBLE   = 0.35   # ratio > 1.0  — truly impossible
SCORE_HIGH         = 0.20   # ratio > 0.75 — e.g. supersonic
SCORE_MEDIUM       = 0.10   # ratio > 0.50 — very fast but conceivable (private jet)

# Minimum distance worth checking (ignore micro-movements / IP geolocation noise)
MIN_DISTANCE_KM = 50.0

# ---------------------------------------------------------------------------
# Haversine great-circle distance
# ---------------------------------------------------------------------------

def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return distance in kilometres between two (lat, lon) points."""
    r  = EARTH_RADIUS_KM
    p  = math.pi / 180
    a  = (
        math.sin((lat2 - lat1) * p / 2) ** 2
        + math.cos(lat1 * p) * math.cos(lat2 * p)
        * math.sin((lon2 - lon1) * p / 2) ** 2
    )
    return 2 * r * math.asin(math.sqrt(a))


# ---------------------------------------------------------------------------
# Coordinate resolution
# ---------------------------------------------------------------------------

def _coords_from_ip(ip: str) -> Optional[tuple[float, float]]:
    """
    Resolve an IP to (lat, lon) using the IPinfo cache from Step 1.2.
    Returns None if:
      - IP is private/internal
      - IPinfo token not configured
      - IPinfo returned no location data
    """
    try:
        from app.middleware.ip_reputation import get_ip_details, _is_private, _parse_ip
        addr = _parse_ip(ip)
        if addr and _is_private(addr if hasattr(addr, 'packed') else ip):
            return None

        details = get_ip_details(ip)
        if not details:
            return None

        # IPinfo returns "loc": "37.3860,-122.0840"
        loc = details.get("loc", "")
        if not loc or "," not in loc:
            return None

        parts = loc.split(",")
        return float(parts[0]), float(parts[1])

    except Exception as exc:
        logger.debug("tokenshield.geo: coords_from_ip failed for %s — %s", ip, exc)
        return None


# ---------------------------------------------------------------------------
# Location store / retrieve  (Redis primary, DB fallback)
# ---------------------------------------------------------------------------

def _store_location(session_id: int, lat: float, lon: float, ip: str) -> None:
    """Write current location to Redis with TTL."""
    record = json.dumps({
        "lat": lat,
        "lon": lon,
        "ip":  ip,
        "ts":  datetime.utcnow().isoformat(),
    })
    try:
        from app.middleware.redis_client import get_redis
        r = get_redis()
        if r:
            r.setex(f"{GEO_KEY_PREFIX}{session_id}", GEO_TTL_SECONDS, record)
            return
    except Exception as exc:
        logger.debug("tokenshield.geo: Redis store failed — %s", exc)

    # DB fallback: location is embedded in BehaviorLog.fingerprint_data
    # by the main middleware — no extra write needed here.


def _retrieve_last_location(session_id: int, current_ip: str) -> Optional[dict]:
    """
    Return the last known location dict { lat, lon, ip, ts } or None.
    Tries Redis first, then scans recent BehaviorLog rows.
    """
    # 1. Redis
    try:
        from app.middleware.redis_client import get_redis
        r = get_redis()
        if r:
            raw = r.get(f"{GEO_KEY_PREFIX}{session_id}")
            if raw:
                return json.loads(raw)
    except Exception as exc:
        logger.debug("tokenshield.geo: Redis retrieve failed — %s", exc)

    # 2. DB fallback — scan last 10 BehaviorLog rows for fingerprint_data
    try:
        from app.models import BehaviorLog
        logs = (
            BehaviorLog.query
            .filter_by(session_id=session_id)
            .filter(BehaviorLog.ip_address != current_ip)   # different IP = possible movement
            .order_by(BehaviorLog.timestamp.desc())
            .limit(10)
            .all()
        )
        for log in logs:
            if not log.fingerprint_data:
                continue
            try:
                data = json.loads(log.fingerprint_data)
                # fingerprint_data written by detection.py has signals/reasons/total
                # fingerprint_data written by threat-detect has full metadata
                lat = data.get("latitude") or data.get("lat")
                lon = data.get("longitude") or data.get("lon")
                if lat is not None and lon is not None:
                    return {
                        "lat": float(lat),
                        "lon": float(lon),
                        "ip":  log.ip_address,
                        "ts":  log.timestamp.isoformat(),
                    }
            except Exception:
                continue
    except Exception as exc:
        logger.debug("tokenshield.geo: DB fallback failed — %s", exc)

    return None


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------

def _score_travel(
    distance_km: float,
    elapsed_seconds: float,
) -> tuple[float, str]:
    """
    Given distance and elapsed time, return (score, reason).
    """
    if elapsed_seconds <= 0:
        elapsed_seconds = 1  # guard against zero / negative

    required_speed = (distance_km / elapsed_seconds) * 3600  # km/h
    ratio          = required_speed / MAX_SPEED_KMH

    elapsed_min = round(elapsed_seconds / 60, 1)
    dist_str    = f"{distance_km:.0f}km/{elapsed_min}min"

    if ratio > 1.0:
        return SCORE_IMPOSSIBLE, f"impossible_travel:{dist_str}:{required_speed:.0f}kmh_required"
    if ratio > 0.75:
        return SCORE_HIGH, f"high_speed_travel:{dist_str}:{required_speed:.0f}kmh_required"
    if ratio > 0.50:
        return SCORE_MEDIUM, f"suspicious_travel:{dist_str}:{required_speed:.0f}kmh_required"

    return 0.0, ""


# ---------------------------------------------------------------------------
# Public API — called by detection.py Signal 6
# ---------------------------------------------------------------------------

def score_geographic_impossibility(session) -> tuple[float, Optional[str]]:
    """
    Main entry point for Signal 6.
    Returns (score: float, reason: str | None).

    Fast paths that return (0.0, None) immediately:
      - No session
      - Current IP is private / unresolvable
      - No previous location stored (first request)
      - Same IP as last known location
      - Distance below noise floor (< MIN_DISTANCE_KM)
    """
    if session is None:
        return 0.0, None

    from flask import request as flask_request
    current_ip = _get_client_ip()

    # Resolve current coordinates
    current_coords = _coords_from_ip(current_ip)
    if current_coords is None:
        return 0.0, None   # Private IP or no geo data — skip

    current_lat, current_lon = current_coords

    # Retrieve previous location
    last = _retrieve_last_location(session.id, current_ip)

    # First request or same IP — just store and return clean
    if last is None or last.get("ip") == current_ip:
        _store_location(session.id, current_lat, current_lon, current_ip)
        return 0.0, None

    prev_lat = last.get("lat")
    prev_lon = last.get("lon")
    prev_ts  = last.get("ts")

    if prev_lat is None or prev_lon is None or prev_ts is None:
        _store_location(session.id, current_lat, current_lon, current_ip)
        return 0.0, None

    # Compute distance
    distance_km = _haversine(prev_lat, prev_lon, current_lat, current_lon)

    if distance_km < MIN_DISTANCE_KM:
        # Within noise floor — update location and return clean
        _store_location(session.id, current_lat, current_lon, current_ip)
        return 0.0, None

    # Compute elapsed time
    try:
        prev_dt  = datetime.fromisoformat(prev_ts)
        now_dt   = datetime.utcnow()
        # Normalise both to naive UTC for comparison
        if prev_dt.tzinfo is not None:
            prev_dt = prev_dt.astimezone(timezone.utc).replace(tzinfo=None)
        elapsed_seconds = (now_dt - prev_dt).total_seconds()
    except Exception as exc:
        logger.warning("tokenshield.geo: timestamp parse failed — %s", exc)
        _store_location(session.id, current_lat, current_lon, current_ip)
        return 0.0, None

    if elapsed_seconds <= 0:
        # Clock skew / same instant — treat as suspicious but not impossible
        elapsed_seconds = 1

    # Score
    score, reason = _score_travel(distance_km, elapsed_seconds)

    logger.info(
        "tokenshield.geo: sid=%s %s→%s dist=%.0fkm elapsed=%.0fs score=%.2f reason=%s",
        session.id,
        last.get("ip", "?"), current_ip,
        distance_km, elapsed_seconds,
        score, reason,
    )

    # Update stored location to current (always advance the pointer)
    _store_location(session.id, current_lat, current_lon, current_ip)

    return score, (reason if reason else None)


# ---------------------------------------------------------------------------
# Admin helper — expose last known location for dashboard
# ---------------------------------------------------------------------------

def get_session_location(session_id: int) -> Optional[dict]:
    """
    Returns the last stored location for a session.
    Used by the attacker-info and live-threats dashboard endpoints.
    """
    try:
        from app.middleware.redis_client import get_redis
        r = get_redis()
        if r:
            raw = r.get(f"{GEO_KEY_PREFIX}{session_id}")
            if raw:
                return json.loads(raw)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Internal helper (mirrors detection.py to avoid circular import)
# ---------------------------------------------------------------------------

def _get_client_ip() -> str:
    try:
        from flask import request
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        return request.remote_addr or "unknown"
    except Exception:
        return "unknown"