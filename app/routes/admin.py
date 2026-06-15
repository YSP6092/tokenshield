"""
TokenShield Admin Routes — Final Fixed Edition
===============================================
WHAT'S NEW vs the old file:
  GET /api/admin/live-threat       — rolling 5-min avg anomaly from IncidentLogs
  GET /api/admin/recent-sessions   — last 100 sessions sorted by score (incl revoked)
  GET /api/admin/transfer-feed     — recent transactions for admin view
  GET /api/admin/stats             — now includes avg_anomaly_score + max_anomaly_score
  GET /api/admin/sessions          — default active_only=FALSE so attack sessions visible
"""

from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models import User, Session, IncidentLog, BehaviorLog
from app.utils import token_required
from datetime import datetime, timedelta

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


# ─── AUTH GUARD ──────────────────────────────────────────────────────────────

def admin_required(f):
    from functools import wraps
    from app.utils import hash_token

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({'success': False, 'message': 'Missing or invalid token'}), 401

        raw_token  = parts[1]
        token_hash = hash_token(raw_token)
        session    = Session.query.filter_by(token=token_hash, is_active=True).first()
        if not session:
            return jsonify({'success': False, 'message': 'Session not found or expired'}), 401

        user = User.query.get(session.user_id)
        if not user or not user.is_active:
            return jsonify({'success': False, 'message': 'User not found or inactive'}), 401
        if not user.is_admin:
            return jsonify({'success': False, 'message': 'Admin access required'}), 403

        session.last_activity = datetime.utcnow()
        db.session.commit()
        return f(user, session, *args, **kwargs)
    return decorated


# ─── GET /api/admin/stats ────────────────────────────────────────────────────

@admin_bp.route('/stats', methods=['GET'])
@admin_required
def get_stats(current_user, current_session):
    now = datetime.utcnow()

    total_users         = User.query.count()
    active_users        = User.query.filter_by(is_active=True).count()
    active_sessions     = Session.query.filter_by(is_active=True).count()
    suspicious_sessions = Session.query.filter_by(is_active=True, is_suspicious=True).count()
    total_sessions      = Session.query.count()
    revoked_sessions    = Session.query.filter_by(is_active=False).count()

    cutoff_24h    = now - timedelta(hours=24)
    cutoff_7d     = now - timedelta(days=7)
    incidents_24h = IncidentLog.query.filter(IncidentLog.timestamp >= cutoff_24h).count()
    incidents_7d  = IncidentLog.query.filter(IncidentLog.timestamp >= cutoff_7d).count()

    by_severity = {
        sev: IncidentLog.query.filter_by(severity=sev).count()
        for sev in ['low', 'medium', 'high', 'critical']
    }

    # avg_anomaly from IncidentLogs (never deleted, always accurate)
    cutoff_1h = now - timedelta(hours=1)
    recent_incidents = IncidentLog.query.filter(
        IncidentLog.timestamp >= cutoff_1h,
        IncidentLog.anomaly_score > 0
    ).all()

    avg_anomaly = 0.0
    max_anomaly = 0.0
    critical_1h = 0
    if recent_incidents:
        scores = [i.anomaly_score for i in recent_incidents if i.anomaly_score]
        if scores:
            avg_anomaly = round(sum(scores) / len(scores), 4)
            max_anomaly = round(max(scores), 4)
        critical_1h = sum(1 for i in recent_incidents if i.severity == 'critical')

    activity_trend = []
    for i in range(6, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end   = day_start + timedelta(days=1)
        inc_count = IncidentLog.query.filter(
            IncidentLog.timestamp >= day_start,
            IncidentLog.timestamp < day_end
        ).count()
        activity_trend.append({'date': day_start.strftime('%Y-%m-%d'), 'count': inc_count})

    redis_info = {}
    try:
        from app.middleware.redis_client import is_available
        from app.middleware.velocity import blocklist_stats
        from app.middleware.fingerprint import banlist_stats as fp_stats
        from app.middleware.account_lock import locked_accounts_count
        redis_info = {
            'available':       is_available(),
            'blocked_tokens':  blocklist_stats().get('blocked_count', 0),
            'banned_devices':  fp_stats().get('banned_count', 0),
            'locked_accounts': locked_accounts_count(),
        }
    except Exception:
        redis_info = {'available': False}

    return jsonify({
        'success': True,
        'stats': {
            'users':             {'total': total_users, 'active': active_users},
            'sessions':          {
                'active':     active_sessions,
                'suspicious': suspicious_sessions,
                'total':      total_sessions,
                'revoked':    revoked_sessions,
            },
            'incidents':         {
                'recent_24h':  incidents_24h,
                'recent_7d':   incidents_7d,
                'by_severity': by_severity,
                'critical_1h': critical_1h,
            },
            'avg_anomaly_score': avg_anomaly,
            'max_anomaly_score': max_anomaly,
            'threat_posture':    'critical' if critical_1h > 0 else 'high' if avg_anomaly >= 0.5 else 'safe',
            'activity_trend':    activity_trend,
            'redis':             redis_info,
        }
    }), 200


# ─── GET /api/admin/live-threat ───────────────────────────────────────────────

@admin_bp.route('/live-threat', methods=['GET'])
@admin_required
def get_live_threat(current_user, current_session):
    """Rolling 5-minute anomaly from IncidentLogs. Drives the score gauge."""
    now    = datetime.utcnow()
    cutoff = now - timedelta(minutes=5)

    recent = IncidentLog.query.filter(
        IncidentLog.timestamp >= cutoff,
        IncidentLog.anomaly_score > 0
    ).order_by(IncidentLog.timestamp.desc()).limit(50).all()

    if not recent:
        return jsonify({'success': True, 'avg_score': 0.0, 'max_score': 0.0,
                        'count': 0, 'threat_level': 'safe'}), 200

    scores       = [i.anomaly_score for i in recent]
    avg_score    = round(sum(scores) / len(scores), 4)
    max_score    = round(max(scores), 4)
    threat_level = (
        'critical' if max_score >= 0.85 else
        'high'     if max_score >= 0.70 else
        'medium'   if max_score >= 0.50 else
        'low'      if max_score >= 0.30 else 'safe'
    )

    latest = recent[0]
    return jsonify({
        'success':      True,
        'avg_score':    avg_score,
        'max_score':    max_score,
        'count':        len(recent),
        'threat_level': threat_level,
        'latest': {
            'id':            latest.id,
            'type':          latest.incident_type,
            'severity':      latest.severity,
            'anomaly_score': latest.anomaly_score,
            'ip':            latest.ip_address,
            'timestamp':     latest.timestamp.isoformat() if latest.timestamp else None,
        }
    }), 200


# ─── GET /api/admin/sessions ─────────────────────────────────────────────────

@admin_bp.route('/sessions', methods=['GET'])
@admin_required
def get_sessions(current_user, current_session):
    # Default active_only=FALSE — attack sessions are immediately revoked
    # so with active_only=true the dashboard would see 0 high-score sessions
    active_only     = request.args.get('active_only', 'false').lower() == 'true'
    suspicious_only = request.args.get('suspicious_only', 'false').lower() == 'true'

    query = Session.query
    if active_only:     query = query.filter_by(is_active=True)
    if suspicious_only: query = query.filter_by(is_suspicious=True)

    sessions = query.order_by(Session.last_activity.desc()).limit(200).all()
    return jsonify({
        'success':  True,
        'sessions': [s.to_dict() for s in sessions],
        'count':    len(sessions),
    }), 200


# ─── GET /api/admin/recent-sessions ──────────────────────────────────────────

@admin_bp.route('/recent-sessions', methods=['GET'])
@admin_required
def get_recent_sessions(current_user, current_session):
    """Returns last N sessions by score DESC — includes revoked attack sessions."""
    limit = int(request.args.get('limit', 100))
    sessions = Session.query\
        .order_by(Session.anomaly_score.desc(), Session.last_activity.desc())\
        .limit(limit).all()
    return jsonify({
        'success':  True,
        'sessions': [s.to_dict() for s in sessions],
        'count':    len(sessions),
    }), 200


# ─── POST /api/admin/sessions/<id>/revoke ────────────────────────────────────

@admin_bp.route('/sessions/<int:session_id>/revoke', methods=['POST'])
@admin_required
def revoke_session(current_user, current_session, session_id):
    data              = request.get_json() or {}
    reason            = data.get('reason', 'Revoked by admin')
    also_lock_account = data.get('lock_account', True)

    sess = Session.query.get(session_id)
    if not sess:
        return jsonify({'success': False, 'message': 'Session not found'}), 404
    if not sess.is_active:
        return jsonify({'success': False, 'message': 'Session is already revoked'}), 400

    full_reason = f"admin_revoke:{reason}:by={current_user.username}"
    sess.is_active      = False
    sess.revoked_at     = datetime.utcnow()
    sess.revoked_reason = full_reason
    db.session.add(IncidentLog(
        session_id=sess.id, incident_type='admin_revoke', severity='low',
        anomaly_score=sess.anomaly_score or 0.0,
        action_taken='session_revoked_by_admin',
        details=f'{{"reason": "{reason}", "admin": "{current_user.username}"}}',
        ip_address=sess.ip_address, user_agent=sess.user_agent,
    ))
    db.session.commit()

    redis_blocked = False
    fp_banned     = False
    account_locked = False

    try:
        from app.middleware.redis_client import get_redis
        from app.middleware.velocity import BLOCKLIST_PREFIX, BLOCKLIST_TTL
        r = get_redis()
        if r:
            r.setex(BLOCKLIST_PREFIX + sess.token, BLOCKLIST_TTL, full_reason)
            redis_blocked = True
    except Exception as exc:
        import logging; logging.getLogger("tokenshield.admin").error("Redis block: %s", exc)

    try:
        from app.middleware.fingerprint import ban_session_fingerprint
        fp_banned, _ = ban_session_fingerprint(sess.id, full_reason)
    except Exception as exc:
        import logging; logging.getLogger("tokenshield.admin").error("FP ban: %s", exc)

    if also_lock_account:
        try:
            from app.middleware.account_lock import soft_lock_account
            account_locked = soft_lock_account(
                user_id=sess.user_id, session_id=sess.id, reason=full_reason)
        except Exception as exc:
            import logging; logging.getLogger("tokenshield.admin").error("Account lock: %s", exc)

    return jsonify({
        'success': True, 'message': f'Session {session_id} revoked',
        'session_id': session_id, 'reason': reason,
        'redis_blocked': redis_blocked, 'fp_banned': fp_banned,
        'account_locked': account_locked,
    }), 200


# ─── GET /api/admin/incidents ────────────────────────────────────────────────

@admin_bp.route('/incidents', methods=['GET'])
@admin_required
def get_incidents(current_user, current_session):
    days     = int(request.args.get('days', 7))
    severity = request.args.get('severity')
    limit    = int(request.args.get('limit', 100))

    cutoff = datetime.utcnow() - timedelta(days=days)
    query  = IncidentLog.query.filter(IncidentLog.timestamp >= cutoff)
    if severity:
        query = query.filter_by(severity=severity)

    incidents = query.order_by(IncidentLog.timestamp.desc()).limit(limit).all()
    result = []
    for inc in incidents:
        d    = inc.to_dict()
        sess = Session.query.get(inc.session_id)
        d['username'] = sess.user.username if (sess and sess.user) else None
        result.append(d)

    return jsonify({'success': True, 'incidents': result, 'count': len(result), 'days': days}), 200


# ─── GET /api/admin/transfer-feed ────────────────────────────────────────────

@admin_bp.route('/transfer-feed', methods=['GET'])
@admin_required
def get_transfer_feed(current_user, current_session):
    """Recent transactions visible in the admin view."""
    try:
        from app.models import Transaction
        limit = int(request.args.get('limit', 20))
        txns  = Transaction.query.order_by(Transaction.timestamp.desc()).limit(limit).all()
        result = []
        for t in txns:
            d = t.to_dict() if hasattr(t, 'to_dict') else {
                'id': t.id, 'amount': float(t.amount),
                'type': getattr(t, 'transaction_type', 'transfer'),
                'description': getattr(t, 'description', ''),
                'timestamp': t.timestamp.isoformat() if t.timestamp else None,
            }
            result.append(d)
        return jsonify({'success': True, 'transactions': result, 'count': len(result)}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ─── GET /api/admin/users ────────────────────────────────────────────────────

@admin_bp.route('/users', methods=['GET'])
@admin_required
def get_users(current_user, current_session):
    users  = User.query.order_by(User.created_at.desc()).all()
    result = []
    for u in users:
        d = u.to_dict()
        d['active_sessions']       = Session.query.filter_by(user_id=u.id, is_active=True).count()
        d['failed_login_attempts'] = u.failed_login_attempts or 0
        d['security_lockout']      = (u.failed_login_attempts or 0) >= 99
        try:
            from app.middleware.account_lock import get_lock_info
            d['lock_info'] = get_lock_info(u.id)
        except Exception:
            d['lock_info'] = None
        result.append(d)
    return jsonify({'success': True, 'users': result, 'count': len(result)}), 200


# ─── GET /api/admin/account-locks ────────────────────────────────────────────

@admin_bp.route('/account-locks', methods=['GET'])
@admin_required
def get_account_locks(current_user, current_session):
    try:
        import json
        from app.middleware.redis_client import get_redis
        from app.middleware.account_lock import LOCK_PREFIX
        r = get_redis()
        locks = []
        if r:
            for key in r.keys(LOCK_PREFIX + "*"):
                raw = r.get(key)
                if not raw: continue
                try:
                    info = json.loads(raw)
                    uid  = info.get('user_id')
                    user = User.query.get(uid) if uid else None
                    locks.append({**info, 'username': user.username if user else 'Unknown',
                                  'email': user.email if user else 'Unknown', 'ttl': r.ttl(key)})
                except Exception:
                    continue
        else:
            for u in User.query.filter(User.failed_login_attempts >= 99).all():
                locks.append({'user_id': u.id, 'username': u.username, 'email': u.email,
                              'lock_type': 'soft' if u.is_active else 'hard',
                              'reason': 'failed_attempts_threshold', 'source': 'db_fallback'})
        return jsonify({'success': True, 'locks': locks, 'count': len(locks)}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ─── POST /api/admin/users/<id>/unlock ───────────────────────────────────────

@admin_bp.route('/users/<int:user_id>/unlock', methods=['POST'])
@admin_required
def unlock_user(current_user, current_session, user_id):
    try:
        from app.middleware.account_lock import unlock_account
        success = unlock_account(user_id)
        user    = User.query.get(user_id)
        if not success or not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        return jsonify({'success': True, 'message': f'User {user.username} unlocked',
                        'user_id': user_id, 'username': user.username}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ─── POST /api/admin/users/<id>/hard-lock ────────────────────────────────────

@admin_bp.route('/users/<int:user_id>/hard-lock', methods=['POST'])
@admin_required
def hard_lock_user(current_user, current_session, user_id):
    if user_id == current_user.id:
        return jsonify({'success': False, 'message': 'Cannot hard-lock your own account'}), 400
    data   = request.get_json() or {}
    reason = data.get('reason', f'Hard locked by admin {current_user.username}')
    try:
        from app.middleware.account_lock import hard_lock_account
        success = hard_lock_account(user_id=user_id, session_id=current_session.id, reason=reason)
        user    = User.query.get(user_id)
        if not success or not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        active = Session.query.filter_by(user_id=user_id, is_active=True).all()
        for s in active:
            s.is_active = False; s.revoked_at = datetime.utcnow()
            s.revoked_reason = f"hard_lock:{reason}"
        db.session.commit()
        return jsonify({'success': True, 'message': f'User {user.username} hard-locked',
                        'user_id': user_id, 'sessions_revoked': len(active)}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ─── GET /api/admin/fingerprint-stats ────────────────────────────────────────

@admin_bp.route('/fingerprint-stats', methods=['GET'])
@admin_required
def fingerprint_stats(current_user, current_session):
    try:
        from app.middleware.fingerprint import banlist_stats
        return jsonify({'success': True, **banlist_stats()}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ─── POST /api/admin/fingerprint-unban ───────────────────────────────────────

@admin_bp.route('/fingerprint-unban', methods=['POST'])
@admin_required
def fingerprint_unban(current_user, current_session):
    data        = request.get_json() or {}
    fingerprint = data.get('fingerprint', '').strip()
    if not fingerprint:
        return jsonify({'success': False, 'message': 'fingerprint is required'}), 400
    try:
        from app.middleware.fingerprint import unban_fingerprint
        removed = unban_fingerprint(fingerprint)
        return jsonify({'success': True, 'removed': removed,
                        'message': 'Removed' if removed else 'Not found in banlist'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500