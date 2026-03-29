"""
Dashboard Routes - MINIMAL VERSION FOR DEMO
Provides API endpoints for user and admin security dashboards
"""

from flask import Blueprint, request, jsonify
from app import db
from app.models import User, Session, BehaviorLog, IncidentLog
from app.utils import token_required, admin_required
from datetime import datetime, timedelta
from sqlalchemy import func, and_

# Create blueprints
dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')
admin_bp = Blueprint('admin_api', __name__, url_prefix='/api/admin')


# ============================================================================
# USER DASHBOARD ENDPOINTS
# ============================================================================

@dashboard_bp.route('/stats', methods=['GET'])
@token_required
def get_dashboard_stats(current_user, current_session):
    """Get security stats for current user"""
    
    try:
        # Get active sessions count
        active_sessions = Session.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).count()
        
        # Get total actions in last 24 hours
        last_24h = datetime.utcnow() - timedelta(hours=24)
        total_actions = BehaviorLog.query.join(Session).filter(
            Session.user_id == current_user.id,
            BehaviorLog.timestamp >= last_24h
        ).count()
        
        # Calculate session duration (in minutes)
        session_duration = (datetime.utcnow() - current_session.created_at).total_seconds() / 60
        
        return jsonify({
            'success': True,
            'stats': {
                'active_sessions': active_sessions,
                'total_actions': total_actions,
                'session_duration': round(session_duration, 1),
                'current_session': {
                    'id': current_session.id,
                    'anomaly_score': current_session.anomaly_score,
                    'is_suspicious': current_session.is_suspicious,
                    'is_active': current_session.is_active,
                    'created_at': current_session.created_at.isoformat(),
                    'last_activity': current_session.last_activity.isoformat(),
                    'ip_address': current_session.ip_address,
                    'user_agent': current_session.user_agent
                }
            }
        })
    except Exception as e:
        print(f"Error in get_dashboard_stats: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch stats'
        }), 500


@dashboard_bp.route('/recent-activity', methods=['GET'])
@token_required
def get_recent_activity(current_user, current_session):
    """Get recent user activities"""
    
    try:
        limit = request.args.get('limit', 20, type=int)
        
        # Get user's sessions
        session_ids = [s.id for s in Session.query.filter_by(user_id=current_user.id).all()]
        
        # Get activities
        activities = BehaviorLog.query.filter(
            BehaviorLog.session_id.in_(session_ids)
        ).order_by(BehaviorLog.timestamp.desc()).limit(limit).all()
        
        return jsonify({
            'success': True,
            'activities': [activity.to_dict() for activity in activities]
        })
    except Exception as e:
        print(f"Error in get_recent_activity: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch activity'
        }), 500


# ============================================================================
# ADMIN DASHBOARD ENDPOINTS
# ============================================================================

@admin_bp.route('/stats', methods=['GET'])
@token_required
@admin_required
def get_admin_stats(current_user, current_session):
    """Get comprehensive admin statistics"""
    
    try:
        # User stats
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        
        # Session stats
        total_sessions = Session.query.filter_by(is_active=True).count()
        suspicious_sessions = Session.query.filter_by(is_active=True, is_suspicious=True).count()
        
        # Incident stats
        last_24h = datetime.utcnow() - timedelta(hours=24)
        recent_incidents = IncidentLog.query.filter(
            IncidentLog.timestamp >= last_24h
        ).count()
        
        # Incidents by severity (last 7 days)
        last_7d = datetime.utcnow() - timedelta(days=7)
        severity_counts = db.session.query(
            IncidentLog.severity,
            func.count(IncidentLog.id)
        ).filter(
            IncidentLog.timestamp >= last_7d
        ).group_by(IncidentLog.severity).all()
        
        by_severity = {}
        for sev, count in severity_counts:
            by_severity[sev] = count
        
        # Average anomaly score
        avg_score = db.session.query(
            func.avg(Session.anomaly_score)
        ).filter(Session.is_active == True).scalar() or 0.0
        
        # Activity trend (last 7 days)
        activity_trend = []
        for i in range(7):
            day_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
            day_end = day_start + timedelta(days=1)
            
            count = BehaviorLog.query.filter(
                and_(
                    BehaviorLog.timestamp >= day_start,
                    BehaviorLog.timestamp < day_end
                )
            ).count()
            
            activity_trend.insert(0, {
                'date': day_start.strftime('%Y-%m-%d'),
                'count': count
            })
        
        return jsonify({
            'success': True,
            'stats': {
                'users': {
                    'total': total_users,
                    'active': active_users
                },
                'sessions': {
                    'active': total_sessions,
                    'suspicious': suspicious_sessions
                },
                'incidents': {
                    'recent_24h': recent_incidents,
                    'by_severity': by_severity
                },
                'anomaly': {
                    'average_score': float(avg_score)
                },
                'activity_trend': activity_trend
            }
        })
    except Exception as e:
        print(f"Error in get_admin_stats: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch admin stats'
        }), 500


@admin_bp.route('/sessions', methods=['GET'])
@token_required
@admin_required
def get_admin_sessions(current_user, current_session):
    """Get all sessions with user info"""
    
    try:
        active_only = request.args.get('active_only', 'true').lower() == 'true'
        suspicious_only = request.args.get('suspicious_only', 'false').lower() == 'true'
        
        query = Session.query
        
        if active_only:
            query = query.filter_by(is_active=True)
        
        if suspicious_only:
            query = query.filter_by(is_suspicious=True)
        
        sessions = query.order_by(Session.last_activity.desc()).all()
        
        # Enrich with user data
        session_data = []
        for sess in sessions:
            user = User.query.get(sess.user_id)
            sess_dict = sess.to_dict()
            sess_dict['username'] = user.username if user else 'Unknown'
            sess_dict['email'] = user.email if user else 'Unknown'
            session_data.append(sess_dict)
        
        return jsonify({
            'success': True,
            'sessions': session_data
        })
    except Exception as e:
        print(f"Error in get_admin_sessions: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch sessions'
        }), 500


@admin_bp.route('/sessions/<int:session_id>/revoke', methods=['POST'])
@token_required
@admin_required
def admin_revoke_session(session_id, current_user, current_session):
    """Admin revoke any session"""
    
    try:
        session = Session.query.get(session_id)
        
        if not session:
            return jsonify({'success': False, 'message': 'Session not found'}), 404
        
        session.is_active = False
        session.revoked_at = datetime.utcnow()
        session.revoked_reason = 'Revoked by admin'
        
        # Log incident
        data = request.get_json() or {}
        reason = data.get('reason', 'Revoked by admin')
        
        incident = IncidentLog(
            session_id=session.id,
            incident_type='admin_revoke',
            severity='medium',
            anomaly_score=session.anomaly_score,
            action_taken='session_revoked',
            details=reason,
            ip_address=session.ip_address,
            user_agent=session.user_agent
        )
        
        db.session.add(incident)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Session revoked'})
    except Exception as e:
        db.session.rollback()
        print(f"Error in admin_revoke_session: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to revoke session'
        }), 500


@admin_bp.route('/incidents', methods=['GET'])
@token_required
@admin_required
def get_incidents(current_user, current_session):
    """Get incident logs"""
    
    try:
        severity = request.args.get('severity')
        days = request.args.get('days', 7, type=int)
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        query = IncidentLog.query.filter(IncidentLog.timestamp >= start_date)
        
        if severity:
            query = query.filter_by(severity=severity)
        
        incidents = query.order_by(IncidentLog.timestamp.desc()).all()
        
        # Enrich with user data
        incident_data = []
        for inc in incidents:
            inc_dict = inc.to_dict()
            
            # Get session and user
            session = Session.query.get(inc.session_id) if inc.session_id else None
            if session:
                user = User.query.get(session.user_id)
                inc_dict['username'] = user.username if user else 'Unknown'
            else:
                inc_dict['username'] = 'Unknown'
            
            incident_data.append(inc_dict)
        
        return jsonify({
            'success': True,
            'incidents': incident_data
        })
    except Exception as e:
        print(f"Error in get_incidents: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch incidents'
        }), 500


@admin_bp.route('/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user, current_session):
    """Get all users with session counts"""
    
    try:
        users = User.query.all()
        
        user_data = []
        for user in users:
            user_dict = user.to_dict()
            
            # Add session count
            active_sessions = Session.query.filter_by(
                user_id=user.id,
                is_active=True
            ).count()
            
            user_dict['active_sessions'] = active_sessions
            user_data.append(user_dict)
        
        return jsonify({
            'success': True,
            'users': user_data
        })
    except Exception as e:
        print(f"Error in get_users: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch users'
        }), 500


# ============================================================================
# REGISTER BLUEPRINTS FUNCTION
# ============================================================================

def register_dashboard_blueprints(app):
    """Register all dashboard blueprints"""
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)