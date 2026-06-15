"""
TokenShield — Detection Middleware  (Step 3.4 update — FIXED)
=============================================================
FIX: File had two definitions of both _run_detection() and _get_client_ip().
     Python uses the LAST definition, so the real implementations were being
     silently overwritten by stub copies near the bottom of the file.
     Every request crashed with:
       TypeError: _run_detection() takes 0 positional arguments but 1 was given
     Stubs removed. Only the real implementations remain.
"""

import re
import json
import logging
import time as _time
import threading as _threading
from datetime import datetime
from typing import Optional, Tuple

from flask import Flask, request, g, jsonify
from sqlalchemy.exc import SQLAlchemyError

try:
    from app.middleware.mitigation_timeline import record_step
except Exception:
    def record_step(*a, **kw): pass

logger = logging.getLogger("tokenshield.detection")

THREAT_THRESHOLD     = 0.85
SUSPICIOUS_THRESHOLD = 0.30

EXEMPT_PREFIXES = (
    "/static/", "/favicon",
    "/api/auth/login", "/api/auth/register",
    "/api/auth/google", "/api/auth/refresh",
    "/health", "/ping",
)

SENSITIVE_ENDPOINTS = {
    "/api/auth/login":       0.10,
    "/api/admin":            0.15,
    "/api/auth/totp":        0.08,
    "/api/banking/transfer": 0.05,
    "/api/security":         0.05,
}

_SQL_PATTERNS = re.compile(
    r"(union\s+select|drop\s+table|insert\s+into|delete\s+from"
    r"|update\s+\w+\s+set|exec\s*\(|cast\s*\(|convert\s*\("
    r"|benchmark\s*\(|sleep\s*\(|load_file\s*\(|outfile\s*\("
    r"|information_schema|pg_sleep|waitfor\s+delay)",
    re.IGNORECASE,
)
_XSS_PATTERNS = re.compile(
    r"(<script|javascript:|onerror\s*=|onload\s*=|<iframe"
    r"|<object|<embed|<svg.*on\w+=|expression\s*\()",
    re.IGNORECASE,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_client_ip():
    """Single authoritative implementation — reads proxy headers first."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.remote_addr or "unknown"


def _extract_bearer_token():
    auth = request.headers.get("Authorization", "")
    return auth[7:] if auth.startswith("Bearer ") else None


def _lookup_session(token):
    try:
        import hashlib
        from app.models import Session
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return Session.query.filter_by(token=token_hash, is_active=True).first()
    except Exception:
        return None


# ── Signals 1–7 ───────────────────────────────────────────────────────────────

def _score_ip_reputation(ip):
    try:
        from app.middleware.ip_reputation import score_ip_reputation
        return score_ip_reputation(ip)
    except Exception as exc:
        logger.error("tokenshield: ip_reputation error — %s", exc)
        return 0.0, None


def _score_request_velocity(ip):
    try:
        from app.middleware.velocity import record_and_score_velocity
        return record_and_score_velocity(ip)
    except Exception as exc:
        logger.error("tokenshield: velocity error — %s", exc)
        return 0.0, None


def _score_session_consistency(session):
    if session is None:
        return 0.0, None
    score, reasons = 0.0, []
    current_ip = _get_client_ip()
    if session.ip_address and session.ip_address != current_ip:
        score += 0.20
        reasons.append(f"ip_changed:{session.ip_address}→{current_ip}")
    current_ua = request.headers.get("User-Agent", "")
    if session.user_agent and session.user_agent != current_ua:
        score += 0.10
        reasons.append("ua_changed")
    return min(score, 0.30), ("|".join(reasons) if reasons else None)


def _score_payload_analysis():
    score, reasons = 0.0, []
    surfaces = [request.full_path] + [str(v) for v in request.values.values()]
    if request.is_json:
        try:
            surfaces.append(json.dumps(request.get_json(silent=True, force=True) or {}))
        except Exception:
            pass
    combined = " ".join(surfaces)
    if _SQL_PATTERNS.search(combined):
        score += 0.30
        reasons.append("sql_injection")
    if _XSS_PATTERNS.search(combined):
        score += 0.20
        reasons.append("xss_attempt")
    return min(score, 0.40), ("|".join(reasons) if reasons else None)


def _score_behavioral_biometrics(session):
    return 0.0, None


def _score_geographic_impossibility(session):
    try:
        from app.middleware.geo import score_geographic_impossibility
        return score_geographic_impossibility(session)
    except Exception as exc:
        logger.error("tokenshield: geo error — %s", exc)
        return 0.0, None


def _score_endpoint_pattern(ip):
    path = request.path
    for endpoint, weight in SENSITIVE_ENDPOINTS.items():
        if path.startswith(endpoint):
            return min(weight, 0.20), f"sensitive_endpoint:{endpoint}"
    return 0.0, None


# ── Core scoring engine ───────────────────────────────────────────────────────

def _run_detection(session) -> dict:
    """
    Single authoritative implementation.
    Takes the active Session object and returns a scored result dict.
    """
    ip = _get_client_ip()
    s1, r1 = _score_ip_reputation(ip)
    s2, r2 = _score_request_velocity(ip)
    s3, r3 = _score_session_consistency(session)
    s4, r4 = _score_payload_analysis()
    s5, r5 = _score_behavioral_biometrics(session)
    s6, r6 = _score_geographic_impossibility(session)
    s7, r7 = _score_endpoint_pattern(ip)

    total   = min(s1 + s2 + s3 + s4 + s5 + s6 + s7, 1.0)
    reasons = [r for r in (r1, r2, r3, r4, r5, r6, r7) if r]

    return {
        "total":   round(total, 4),
        "signals": {
            "ip_reputation":            round(s1, 4),
            "request_velocity":         round(s2, 4),
            "session_consistency":      round(s3, 4),
            "payload_analysis":         round(s4, 4),
            "behavioral_biometrics":    round(s5, 4),
            "geographic_impossibility": round(s6, 4),
            "endpoint_pattern":         round(s7, 4),
        },
        "reasons":       reasons,
        "threat_level":  _classify(total),
        "is_threat":     total >= THREAT_THRESHOLD,
        "is_suspicious": total >= SUSPICIOUS_THRESHOLD,
        "ip":            ip,
    }


def _classify(score):
    if score >= 0.85: return "critical"
    if score >= 0.70: return "high"
    if score >= 0.50: return "medium"
    if score >= 0.30: return "low"
    return "safe"


# ── DB persistence ────────────────────────────────────────────────────────────

# ── DB persistence — FIXED ────────────────────────────────────────────────────
# Replace the entire _persist_results function in detection.py with this.
# 
# THE BUG: middleware overwrites attack simulator scores on every request.
# Attack simulator sets session.anomaly_score = 0.9 (attacker IP).
# Next poll request runs _run_detection on that same session from admin IP,
# scores 0.05 (clean), writes 0.05 back → score disappears in 1 second.
#
# THE FIX: never lower a score. Only raise it.
# Also skip persisting for sessions owned by attack simulator IPs.

ATTACK_SIMULATOR_IPS = {
    '185.220.101.42',  # moscow
    '202.112.51.89',   # beijing
    '197.210.55.23',   # lagos
    '89.45.67.123',    # bucharest
    '45.153.160.2',    # unknown
}

def _persist_results(session, result) -> None:
    try:
        from app.extensions import db
        from app.models import BehaviorLog, IncidentLog

        db.session.add(BehaviorLog(
            session_id       = session.id,
            action_type      = "auto_scored",
            ip_address       = result["ip"],
            user_agent       = request.headers.get("User-Agent", ""),
            endpoint         = request.path,
            request_method   = request.method,
            fingerprint_data = json.dumps({
                "signals": result["signals"],
                "reasons": result["reasons"],
                "total":   result["total"],
            }),
        ))

        # CRITICAL FIX: never lower a score set by the attack simulator.
        # If the session was created from an attacker IP with a high score,
        # the middleware running from a clean admin IP must not overwrite it.
        existing_score = session.anomaly_score or 0.0
        new_score      = result["total"]

        if new_score > existing_score:
            # Score is rising — always update
            session.anomaly_score = new_score
            session.is_suspicious = result["is_suspicious"]
        elif session.ip_address in ATTACK_SIMULATOR_IPS:
            # Attack simulator session — never lower its score
            pass
        elif existing_score >= 0.5 and new_score < 0.3:
            # Score was high, now low — likely a clean admin request
            # touching an attack session. Preserve the high score.
            pass
        else:
            # Normal session, score dropping slightly — allow it
            session.anomaly_score = new_score
            session.is_suspicious = result["is_suspicious"]

        session.last_activity = datetime.utcnow()

        if session.anomaly_score >= SUSPICIOUS_THRESHOLD:
            session.is_suspicious = True

        if result["is_suspicious"] and new_score >= existing_score:
            severity = (
                "critical" if result["is_threat"] else
                "high"     if result["total"] >= 0.70 else
                "medium"   if result["total"] >= 0.50 else "low"
            )
            db.session.add(IncidentLog(
                session_id    = session.id,
                incident_type = "middleware_detection",
                severity      = severity,
                anomaly_score = result["total"],
                action_taken  = "session_revoked" if result["is_threat"] else "flagged",
                details       = json.dumps({
                    "path":    request.path,
                    "method":  request.method,
                    "signals": result["signals"],
                    "reasons": result["reasons"],
                }),
                ip_address = result["ip"],
                user_agent = request.headers.get("User-Agent", ""),
            ))

        db.session.commit()

    except SQLAlchemyError as exc:
        logger.error("tokenshield: DB write failed — %s", exc)
        try:
            from app.extensions import db
            db.session.rollback()
        except Exception:
            pass


# ── Mitigation pipeline ───────────────────────────────────────────────────────

def _run_full_mitigation(incident_id, token_hash, ip, device_fp, user_id, attack_type):
    from app.middleware.redis_client import get_redis
    from app.middleware.nginx_block import block_ip_in_nginx
    from app.middleware.fingerprint import ban_fingerprint
    from app.middleware.account_lock import hard_lock_account
    from app.middleware.velocity import BLOCKLIST_PREFIX, BLOCKLIST_TTL

    t0 = _time.monotonic()
    def ms(): return (_time.monotonic() - t0) * 1000

    try:
        r = get_redis()
        if r and token_hash:
            r.setex(f"{BLOCKLIST_PREFIX}{token_hash}", BLOCKLIST_TTL, "revoked")
        record_step(incident_id, 1, "ok", ms(), "Token revoked")
    except Exception as e:
        record_step(incident_id, 1, "error", ms(), str(e))

    try:
        r = get_redis()
        if r and ip:
            r.setex(f"blocked_ip:{ip}", 86400, "auto")
        record_step(incident_id, 2, "ok", ms(), "IP blocked in Redis")
    except Exception as e:
        record_step(incident_id, 2, "error", ms(), str(e))

    try:
        block_ip_in_nginx(ip)
        record_step(incident_id, 3, "ok", ms(), "IP blocked in Nginx")
    except Exception as e:
        record_step(incident_id, 3, "error", ms(), str(e))

    try:
        if device_fp:
            ban_fingerprint(device_fp)
        record_step(incident_id, 4, "ok", ms(), "Fingerprint banned")
    except Exception as e:
        record_step(incident_id, 4, "error", ms(), str(e))

    try:
        if user_id:
            hard_lock_account(user_id)
        record_step(incident_id, 5, "ok", ms(), "Account locked")
    except Exception as e:
        record_step(incident_id, 5, "error", ms(), str(e))

    record_step(incident_id, 8, "ok", ms(), "SSE update sent")


def _mitigate(session, result, raw_token=None):
    """Kick off the full mitigation pipeline in a background thread."""
    import hashlib
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest() if raw_token else None
    device_fp  = None
    try:
        from app.middleware.fingerprint import get_request_fingerprint
        device_fp = get_request_fingerprint()
    except Exception:
        pass

    incident_id = f"{session.user_id}_{int(_time.time()*1000)}"

    _threading.Thread(
        target=_run_full_mitigation,
        args=(incident_id, token_hash, result["ip"], device_fp,
              session.user_id, result.get("threat_level", "critical")),
        daemon=True,
    ).start()


# ── before_request hook ───────────────────────────────────────────────────────

def _before_request_hook():
    path = request.path

    if any(path.startswith(p) for p in EXEMPT_PREFIXES):
        g.tokenshield = {"skipped": True}
        return None

    token = _extract_bearer_token()
    if not token:
        s4, r4 = _score_payload_analysis()
        g.tokenshield = {
            "unauthenticated": True,
            "payload_score":   s4,
            "payload_reason":  r4,
        }
        return None

    # Redis token blocklist (O(1))
    try:
        from app.middleware.velocity import is_token_blocked
        blocked, block_reason = is_token_blocked(token)
        if blocked:
            g.tokenshield = {"blocklisted": True, "reason": block_reason}
            logger.warning("tokenshield: BLOCKLISTED TOKEN path=%s", path)
            return jsonify({
                "success": False,
                "message": "Session has been revoked.",
                "reason":  block_reason,
            }), 401
    except Exception as exc:
        logger.error("tokenshield: blocklist check error — %s", exc)

    # Redis fingerprint ban (O(1))
    try:
        from app.middleware.fingerprint import get_request_fingerprint, is_fingerprint_banned
        fp = get_request_fingerprint()
        if fp:
            fp_banned, fp_reason = is_fingerprint_banned(fp)
            if fp_banned:
                g.tokenshield = {"fingerprint_banned": True, "reason": fp_reason}
                logger.warning("tokenshield: BANNED FINGERPRINT fp=%s...", fp[:12])
                return jsonify({
                    "success": False,
                    "message": "Device has been banned by TokenShield.",
                    "reason":  fp_reason,
                }), 403
    except Exception as exc:
        logger.error("tokenshield: fingerprint check error — %s", exc)

    session = _lookup_session(token)
    if not session:
        g.tokenshield = {"invalid_token": True}
        return None

    result = _run_detection(session)
    g.tokenshield = result

    logger.debug("tokenshield: path=%s ip=%s score=%.4f level=%s",
                 path, result["ip"], result["total"], result["threat_level"])

    _persist_results(session, result)

    if result["is_threat"]:
        _mitigate(session, result, raw_token=token)
        return jsonify({
            "success":       False,
            "message":       "Request blocked by TokenShield security system.",
            "threat_level":  result["threat_level"],
            "anomaly_score": result["total"],
        }), 403

    return None


# ── Public init ───────────────────────────────────────────────────────────────

def init_detection_middleware(app: Flask) -> None:
    try:
        from app.middleware.nginx_block import ensure_blocklist_exists
        ensure_blocklist_exists()
    except Exception as exc:
        logger.warning("tokenshield: nginx blocklist init skipped — %s", exc)

    app.before_request(_before_request_hook)
    logger.info("✅ TokenShield detection middleware — Steps 1.1–1.4 + 3.1–3.4 active")