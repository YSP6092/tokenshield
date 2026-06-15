"""
Dashboard Routes — FIXED
=========================
Removed the duplicate /api/admin blueprint that was conflicting with
app/routes/admin.py. Both were registered on url_prefix='/api/admin'
causing random 500s on every admin endpoint.

This file now ONLY handles /api/dashboard/* (user-facing dashboard).
All /api/admin/* routes live exclusively in app/routes/admin.py.
"""

from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models import User, Session, BehaviorLog, IncidentLog
from datetime import datetime, timedelta
from functools import wraps
from sqlalchemy import and_
import hashlib, jwt, os

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')


# ── Auth helper ───────────────────────────────────────────────────────────────

def _resolve_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None
    token = auth[7:]
    try:
        secret  = os.getenv("JWT_SECRET_KEY", "jwt-secret-change-in-production")
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        user_id = payload.get("user_id")
    except Exception:
        return None, None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    session    = Session.query.filter_by(token=token_hash, is_active=True).first()
    if not session:
        return None, None
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return None, None
    return user, session


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user, session = _resolve_token()
        if not user:
            return jsonify({"success": False, "message": "Authentication required"}), 401
        return f(*args, current_user=user, current_session=session, **kwargs)
    return decorated


# ── /api/dashboard/stats ──────────────────────────────────────────────────────

@dashboard_bp.route('/stats', methods=['GET'])
@token_required
def get_dashboard_stats(current_user, current_session):
    try:
        active_sessions = Session.query.filter_by(
            user_id=current_user.id, is_active=True
        ).count()

        last_24h      = datetime.utcnow() - timedelta(hours=24)
        total_actions = BehaviorLog.query.join(Session).filter(
            Session.user_id == current_user.id,
            BehaviorLog.timestamp >= last_24h
        ).count()

        session_duration = (
            datetime.utcnow() - current_session.created_at
        ).total_seconds() / 60

        return jsonify({
            'success': True,
            'stats': {
                'active_sessions':  active_sessions,
                'total_actions':    total_actions,
                'session_duration': round(session_duration, 1),
                'current_session': {
                    'id':            current_session.id,
                    'anomaly_score': current_session.anomaly_score,
                    'is_suspicious': current_session.is_suspicious,
                    'is_active':     current_session.is_active,
                    'created_at':    current_session.created_at.isoformat(),
                    'last_activity': current_session.last_activity.isoformat(),
                    'ip_address':    current_session.ip_address,
                    'user_agent':    current_session.user_agent,
                }
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ── /api/dashboard/recent-activity ───────────────────────────────────────────

@dashboard_bp.route('/recent-activity', methods=['GET'])
@token_required
def get_recent_activity(current_user, current_session):
    try:
        limit       = request.args.get('limit', 20, type=int)
        session_ids = [
            s.id for s in Session.query.filter_by(user_id=current_user.id).all()
        ]
        activities = BehaviorLog.query.filter(
            BehaviorLog.session_id.in_(session_ids)
        ).order_by(BehaviorLog.timestamp.desc()).limit(limit).all()

        return jsonify({
            'success':    True,
            'activities': [a.to_dict() for a in activities]
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ── register ──────────────────────────────────────────────────────────────────

def register_dashboard_blueprints(app):
    app.register_blueprint(dashboard_bp)
    # NOTE: admin_bp is registered in __init__.py via app/routes/admin.py
    # Do NOT register a second admin blueprint here.