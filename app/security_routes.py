"""
TokenShield Security Engine Routes  (Step 1.2 update)
======================================================
Changes from Step 1.1:
  - Added /api/security/ip-reputation/<ip>   — on-demand IP enrichment
  - Added /api/security/ip-cache-stats       — cache diagnostics
  - Added /api/security/ip-cache-invalidate  — force-evict IPs from cache
  - Added /api/security/middleware-status    — per-request signal breakdown
  - Added /api/security/middleware-config    — signal roadmap for admin UI

All existing endpoints are unchanged.
"""

from flask import Blueprint, request, jsonify, current_app, g
from datetime import datetime, timedelta
from app import db
from app.models import Session, BehaviorLog, IncidentLog, User
from app.utils import token_required, admin_required, get_client_ip, get_user_agent
import json, hashlib, re

security_bp = Blueprint('security', __name__, url_prefix='/api/security')


# =============================================================================
# EXISTING ENDPOINTS  (unchanged from Step 1.1)
# =============================================================================

@security_bp.route('/threat-detect', methods=['POST'])
@token_required
def threat_detect(current_user, current_session):
    try:
        data = request.get_json() or {}

        metadata = {
            'ip_address':        get_client_ip(),
            'user_agent':        get_user_agent(),
            'referrer':          request.referrer,
            'origin':            request.headers.get('Origin'),
            'screen_width':      data.get('screen_width'),
            'screen_height':     data.get('screen_height'),
            'screen_depth':      data.get('screen_depth'),
            'timezone_offset':   data.get('timezone_offset'),
            'timezone':          data.get('timezone'),
            'language':          data.get('language'),
            'platform':          data.get('platform'),
            'cpu_cores':         data.get('cpu_cores'),
            'memory':            data.get('memory'),
            'canvas_fingerprint':data.get('canvas_fingerprint'),
            'webgl_fingerprint': data.get('webgl_fingerprint'),
            'audio_fingerprint': data.get('audio_fingerprint'),
            'fonts':             data.get('fonts'),
            'plugins':           data.get('plugins'),
            'do_not_track':      data.get('do_not_track'),
            'ad_blocker':        data.get('ad_blocker'),
            'mouse_speed':       data.get('mouse_speed'),
            'typing_speed':      data.get('typing_speed'),
            'scroll_pattern':    data.get('scroll_pattern'),
            'click_pattern':     data.get('click_pattern'),
            'latitude':          data.get('latitude'),
            'longitude':         data.get('longitude'),
            'accuracy':          data.get('accuracy'),
            'action_type':       data.get('action_type', 'unknown'),
            'endpoint':          data.get('endpoint'),
            'timestamp':         datetime.utcnow().isoformat()
        }

        device_fingerprint = generate_device_fingerprint(metadata)
        metadata['device_fingerprint'] = device_fingerprint

        threat_analysis = analyze_threat(current_session, metadata)

        current_session.anomaly_score = threat_analysis['anomaly_score']
        current_session.is_suspicious = threat_analysis['is_suspicious']
        current_session.last_activity = datetime.utcnow()

        behavior_log = BehaviorLog(
            session_id     = current_session.id,
            action_type    = metadata['action_type'],
            ip_address     = metadata['ip_address'],
            user_agent     = metadata['user_agent'],
            endpoint       = metadata.get('endpoint', '/unknown'),
            request_method = 'POST',
            fingerprint_data = json.dumps(metadata)
        )
        db.session.add(behavior_log)

        if threat_analysis['anomaly_score'] >= 0.7:
            incident = IncidentLog(
                session_id    = current_session.id,
                incident_type = 'high_threat_detected',
                severity      = 'critical' if threat_analysis['anomaly_score'] >= 0.85 else 'high',
                anomaly_score = threat_analysis['anomaly_score'],
                action_taken  = 'monitored',
                details       = json.dumps({
                    'threat_factors':    threat_analysis['threat_factors'],
                    'device_fingerprint': device_fingerprint,
                    'metadata':          metadata,
                    'recommendations':   threat_analysis['recommendations']
                }),
                ip_address = metadata['ip_address'],
                user_agent = metadata['user_agent']
            )
            db.session.add(incident)

        db.session.commit()

        return jsonify({
            'success': True,
            'threat_analysis': {
                'anomaly_score':      threat_analysis['anomaly_score'],
                'threat_level':       threat_analysis['threat_level'],
                'is_suspicious':      threat_analysis['is_suspicious'],
                'threat_factors':     threat_analysis['threat_factors'],
                'device_fingerprint': device_fingerprint,
                'recommendations':    threat_analysis['recommendations']
            },
            'session_status': {
                'is_active':        current_session.is_active,
                'should_challenge': threat_analysis['anomaly_score'] >= 0.5,
                'should_revoke':    threat_analysis['anomaly_score'] >= 0.85
            }
        }), 200

    except Exception as e:
        current_app.logger.error(f"Threat detection error: {str(e)}")
        return jsonify({'success': False, 'message': 'Threat detection failed'}), 500


@security_bp.route('/analyze-session/<int:session_id>', methods=['GET'])
@token_required
@admin_required
def analyze_session(current_user, current_session, session_id):
    try:
        target = Session.query.get(session_id)
        if not target:
            return jsonify({'success': False, 'message': 'Session not found'}), 404

        user = User.query.get(target.user_id)
        logs = (BehaviorLog.query
                .filter_by(session_id=session_id)
                .order_by(BehaviorLog.timestamp.desc())
                .limit(100).all())

        time_gaps = [l.time_gap for l in logs if l.time_gap is not None]
        methods   = [l.request_method for l in logs if l.request_method]
        endpoints = list({l.endpoint for l in logs if l.endpoint})
        session_age = (datetime.utcnow() - target.created_at).total_seconds() / 60
        post_count  = sum(1 for m in methods if m == 'POST')
        total       = len(methods) or 1

        import statistics as stats
        features = {
            'time_gap_mean':       round(stats.mean(time_gaps), 2) if time_gaps else 0,
            'time_gap_std':        round(stats.stdev(time_gaps), 2) if len(time_gaps) > 1 else 0,
            'requests_per_minute': round(len(logs) / max(session_age, 0.01), 2),
            'unique_endpoints':    len(endpoints),
            'post_ratio':          round(post_count / total, 2),
            'session_age_minutes': round(session_age, 1),
            'ip_change':           0,
            'user_agent_change':   0,
            'transaction_count':   target.transactions.count()
                                   if hasattr(target, 'transactions') else 0
        }

        geo      = get_geolocation_from_ip(target.ip_address)
        parsed_ua = parse_user_agent(target.user_agent)
        incidents = (IncidentLog.query
                     .filter_by(session_id=session_id)
                     .order_by(IncidentLog.timestamp.desc())
                     .limit(10).all())

        return jsonify({
            'success': True,
            'analysis': {
                'session_id': target.id,
                'user': {
                    'id':       user.id if user else None,
                    'username': user.username if user else 'Unknown',
                    'email':    user.email if user else 'Unknown'
                },
                'network': {
                    'ip':         target.ip_address,
                    'geolocation': geo,
                    'user_agent': parsed_ua,
                    'raw_ua':     target.user_agent
                },
                'risk': {
                    'anomaly_score':  target.anomaly_score,
                    'threat_level':   classify_threat_level(target.anomaly_score),
                    'is_suspicious':  target.is_suspicious,
                    'is_active':      target.is_active,
                    'revoked_reason': target.revoked_reason
                },
                'ml_features':   features,
                'timeline': {
                    'created_at':    target.created_at.isoformat(),
                    'last_activity': target.last_activity.isoformat(),
                    'revoked_at':    target.revoked_at.isoformat() if target.revoked_at else None,
                    'total_actions': len(logs)
                },
                'incidents':      [i.to_dict() for i in incidents],
                'recent_actions': [l.to_dict() for l in logs[:20]]
            }
        }), 200

    except Exception as e:
        current_app.logger.error(f"Analyze session error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@security_bp.route('/live-feed', methods=['GET'])
@token_required
@admin_required
def live_feed(current_user, current_session):
    try:
        suspicious = (Session.query
                      .filter(Session.anomaly_score >= 0.3)
                      .filter(Session.is_active == True)
                      .order_by(Session.anomaly_score.desc())
                      .limit(20).all())

        cutoff = datetime.utcnow() - timedelta(minutes=30)
        recent_incidents = (IncidentLog.query
                            .filter(IncidentLog.timestamp >= cutoff)
                            .order_by(IncidentLog.timestamp.desc())
                            .limit(10).all())

        threats = []
        for s in suspicious:
            user = User.query.get(s.user_id)
            geo  = get_geolocation_from_ip(s.ip_address)
            threats.append({
                'session_id':    s.id,
                'username':      user.username if user else 'Unknown',
                'ip':            s.ip_address,
                'city':          geo.get('city', 'Unknown'),
                'country':       geo.get('country', 'Unknown'),
                'anomaly_score': s.anomaly_score,
                'threat_level':  classify_threat_level(s.anomaly_score),
                'last_activity': s.last_activity.isoformat(),
                'is_suspicious': s.is_suspicious
            })

        incidents_data = []
        for inc in recent_incidents:
            s    = Session.query.get(inc.session_id) if inc.session_id else None
            user = User.query.get(s.user_id) if s else None
            incidents_data.append({
                **inc.to_dict(),
                'username': user.username if user else 'Unknown'
            })

        return jsonify({
            'success':          True,
            'timestamp':        datetime.utcnow().isoformat(),
            'active_threats':   threats,
            'recent_incidents': incidents_data,
            'summary': {
                'critical': sum(1 for t in threats if t['anomaly_score'] >= 0.85),
                'high':     sum(1 for t in threats if 0.70 <= t['anomaly_score'] < 0.85),
                'medium':   sum(1 for t in threats if 0.50 <= t['anomaly_score'] < 0.70),
                'low':      sum(1 for t in threats if 0.30 <= t['anomaly_score'] < 0.50)
            }
        }), 200

    except Exception as e:
        current_app.logger.error(f"Live feed error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@security_bp.route('/attacker-info/<int:session_id>', methods=['GET'])
@token_required
@admin_required
def get_attacker_info(current_user, current_session, session_id):
    try:
        target_session = Session.query.get(session_id)
        if not target_session:
            return jsonify({'success': False, 'message': 'Session not found'}), 404

        behavior_logs = (BehaviorLog.query.filter_by(session_id=session_id)
                         .order_by(BehaviorLog.timestamp.desc()).limit(50).all())

        metadata_history = []
        for log in behavior_logs:
            if log.fingerprint_data:
                try:
                    meta = json.loads(log.fingerprint_data)
                    metadata_history.append({
                        'timestamp': log.timestamp.isoformat(),
                        'action':    log.action_type,
                        'metadata':  meta
                    })
                except Exception:
                    pass

        latest_metadata = metadata_history[0] if metadata_history else {}
        geolocation     = get_geolocation_from_ip(target_session.ip_address)
        incidents       = (IncidentLog.query.filter_by(session_id=session_id)
                           .order_by(IncidentLog.timestamp.desc()).limit(10).all())

        return jsonify({
            'success': True,
            'attacker_profile': {
                'session_id':    target_session.id,
                'user_id':       target_session.user_id,
                'username':      target_session.user.username if target_session.user else 'Unknown',
                'ip_address':    target_session.ip_address,
                'geolocation':   geolocation,
                'user_agent':    target_session.user_agent,
                'parsed_user_agent': parse_user_agent(target_session.user_agent),
                'device_fingerprint': latest_metadata.get('metadata', {}).get('device_fingerprint'),
                'device_info':   extract_device_info(latest_metadata.get('metadata', {})),
                'browser_fingerprint': {
                    'canvas':  latest_metadata.get('metadata', {}).get('canvas_fingerprint'),
                    'webgl':   latest_metadata.get('metadata', {}).get('webgl_fingerprint'),
                    'audio':   latest_metadata.get('metadata', {}).get('audio_fingerprint'),
                    'fonts':   latest_metadata.get('metadata', {}).get('fonts'),
                    'plugins': latest_metadata.get('metadata', {}).get('plugins')
                },
                'anomaly_score':   target_session.anomaly_score,
                'is_suspicious':   target_session.is_suspicious,
                'threat_level':    classify_threat_level(target_session.anomaly_score),
                'created_at':      target_session.created_at.isoformat(),
                'last_activity':   target_session.last_activity.isoformat(),
                'is_active':       target_session.is_active,
                'revoked_at':      target_session.revoked_at.isoformat() if target_session.revoked_at else None,
                'revoked_reason':  target_session.revoked_reason,
                'total_actions':   len(behavior_logs),
                'metadata_history': metadata_history,
                'incidents':       [inc.to_dict() for inc in incidents]
            }
        }), 200

    except Exception as e:
        current_app.logger.error(f"Get attacker info error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to get attacker information'}), 500


@security_bp.route('/live-threats', methods=['GET'])
@token_required
@admin_required
def get_live_threats(current_user, current_session):
    try:
        suspicious_sessions = (Session.query
                               .filter(Session.is_active == True,
                                       Session.anomaly_score >= 0.3)
                               .order_by(Session.anomaly_score.desc()).all())

        threats = []
        for session in suspicious_sessions:
            latest_behavior = (BehaviorLog.query.filter_by(session_id=session.id)
                               .order_by(BehaviorLog.timestamp.desc()).first())
            metadata = {}
            if latest_behavior and latest_behavior.fingerprint_data:
                try:
                    metadata = json.loads(latest_behavior.fingerprint_data)
                except Exception:
                    pass
            geo = get_geolocation_from_ip(session.ip_address)
            threats.append({
                'session_id':         session.id,
                'user_id':            session.user_id,
                'username':           session.user.username if session.user else 'Unknown',
                'ip_address':         session.ip_address,
                'geolocation':        geo,
                'user_agent':         parse_user_agent(session.user_agent),
                'device_fingerprint': metadata.get('device_fingerprint'),
                'anomaly_score':      session.anomaly_score,
                'threat_level':       classify_threat_level(session.anomaly_score),
                'last_activity':      session.last_activity.isoformat(),
                'created_at':         session.created_at.isoformat(),
                'is_suspicious':      session.is_suspicious
            })

        return jsonify({
            'success':        True,
            'threats':        threats,
            'total_threats':  len(threats),
            'critical_count': sum(1 for t in threats if t['anomaly_score'] >= 0.85),
            'high_count':     sum(1 for t in threats if 0.7  <= t['anomaly_score'] < 0.85),
            'medium_count':   sum(1 for t in threats if 0.5  <= t['anomaly_score'] < 0.7),
            'low_count':      sum(1 for t in threats if 0.3  <= t['anomaly_score'] < 0.5)
        }), 200

    except Exception as e:
        current_app.logger.error(f"Get live threats error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to get live threats'}), 500


@security_bp.route('/threat-map-data', methods=['GET'])
@token_required
@admin_required
def get_threat_map_data(current_user, current_session):
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        suspicious_sessions = (Session.query
                               .filter(Session.created_at >= cutoff_time,
                                       Session.anomaly_score >= 0.3).all())
        map_data = []
        for session in suspicious_sessions:
            geo = get_geolocation_from_ip(session.ip_address)
            if geo.get('latitude') and geo.get('longitude'):
                map_data.append({
                    'session_id':    session.id,
                    'latitude':      geo['latitude'],
                    'longitude':     geo['longitude'],
                    'city':          geo.get('city', 'Unknown'),
                    'country':       geo.get('country', 'Unknown'),
                    'ip_address':    session.ip_address,
                    'anomaly_score': session.anomaly_score,
                    'threat_level':  classify_threat_level(session.anomaly_score),
                    'timestamp':     session.created_at.isoformat(),
                    'is_active':     session.is_active
                })

        return jsonify({
            'success':         True,
            'map_data':        map_data,
            'total_locations': len(map_data)
        }), 200

    except Exception as e:
        current_app.logger.error(f"Get threat map data error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to get threat map data'}), 500


# =============================================================================
# STEP 1.1 — Middleware inspection routes
# =============================================================================

@security_bp.route('/middleware-status', methods=['GET'])
@token_required
def middleware_status(current_user, current_session):
    """
    Returns the TokenShield score computed for THIS request by the
    before_request hook. Frontend can call this after any action to get
    a live risk score + per-signal breakdown without a separate API call.
    """
    ts = getattr(g, 'tokenshield', {})

    if ts.get('skipped'):
        return jsonify({'success': True, 'status': 'exempt', 'score': 0.0}), 200

    if ts.get('unauthenticated'):
        return jsonify({
            'success':        True,
            'status':         'unauthenticated',
            'payload_score':  ts.get('payload_score', 0.0),
            'payload_reason': ts.get('payload_reason'),
        }), 200

    if ts.get('invalid_token'):
        return jsonify({'success': True, 'status': 'invalid_token'}), 200

    return jsonify({
        'success':       True,
        'status':        'scored',
        'score':         ts.get('total', 0.0),
        'threat_level':  ts.get('threat_level', 'safe'),
        'is_threat':     ts.get('is_threat', False),
        'is_suspicious': ts.get('is_suspicious', False),
        'signals':       ts.get('signals', {}),
        'reasons':       ts.get('reasons', []),
        'ip':            ts.get('ip'),
    }), 200


@security_bp.route('/middleware-config', methods=['GET'])
@token_required
@admin_required
def middleware_config(current_user, current_session):
    """
    Admin-only: returns current middleware thresholds and live/stub
    status of each signal. Used by the Security Engine UI roadmap panel.
    """
    return jsonify({
        'success': True,
        'config': {
            'threat_threshold':     0.85,
            'suspicious_threshold': 0.30,
        },
        'signals': {
            'ip_reputation':            {'max': 0.25, 'status': 'live',           'step': '1.2'},
            'request_velocity':         {'max': 0.30, 'status': 'live_inprocess', 'step': '1.1'},
            'session_consistency':      {'max': 0.30, 'status': 'live',           'step': '1.1'},
            'payload_analysis':         {'max': 0.40, 'status': 'live',           'step': '1.1'},
            'behavioral_biometrics':    {'max': 0.25, 'status': 'stub',           'step': '4.1'},
            'geographic_impossibility': {'max': 0.35, 'status': 'stub',           'step': '1.4'},
            'endpoint_pattern':         {'max': 0.20, 'status': 'live',           'step': '1.1'},
        },
    }), 200


# =============================================================================
# STEP 1.2 — IP Reputation routes
# =============================================================================

@security_bp.route('/ip-reputation/<string:ip_address>', methods=['GET'])
@token_required
@admin_required
def ip_reputation_lookup(current_user, current_session, ip_address):
    """
    On-demand IP enrichment for any IP address.
    Used by the admin threat detail panel to show full IP profile.
    Cache-backed — repeated calls for the same IP are instant.

    GET /api/security/ip-reputation/185.220.101.42
    """
    from app.middleware.ip_reputation import get_ip_details, score_ip_reputation

    try:
        details       = get_ip_details(ip_address)
        score, reason = score_ip_reputation(ip_address)

        return jsonify({
            'success': True,
            'ip':      ip_address,
            'score':   round(score, 4),
            'reason':  reason,
            'details': details,
        }), 200

    except Exception as e:
        current_app.logger.error(f"IP reputation lookup error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@security_bp.route('/ip-cache-stats', methods=['GET'])
@token_required
@admin_required
def ip_cache_stats(current_user, current_session):
    """
    Returns IP reputation cache diagnostics.
    Confirms cache is working and whether IPINFO_TOKEN is configured.

    GET /api/security/ip-cache-stats
    """
    from app.middleware.ip_reputation import cache_stats

    return jsonify({'success': True, 'cache': cache_stats()}), 200


@security_bp.route('/ip-cache-invalidate', methods=['POST'])
@token_required
@admin_required
def ip_cache_invalidate(current_user, current_session):
    """
    Force-evict one or more IPs from the reputation cache.
    Use after a ban is lifted or when testing new scoring logic.

    POST /api/security/ip-cache-invalidate
    Body: { "ips": ["1.2.3.4", "5.6.7.8"] }
    """
    from app.middleware.ip_reputation import invalidate_cache

    data = request.get_json() or {}
    ips  = data.get('ips', [])

    if not isinstance(ips, list) or not ips:
        return jsonify({'success': False, 'message': 'Provide a non-empty list of IPs'}), 400

    for ip in ips:
        invalidate_cache(ip)

    return jsonify({'success': True, 'invalidated': ips}), 200

"""
TokenShield Step 1.3 — Routes to add to security_routes.py
===========================================================
Paste these endpoints into security_routes.py after the Step 1.2 routes.
They expose Redis health, velocity data, and blocklist management
to the admin dashboard.
"""


# =============================================================================
# STEP 1.3 — Redis / Velocity / Blocklist routes
# =============================================================================

@security_bp.route('/redis-status', methods=['GET'])
@token_required
@admin_required
def redis_status(current_user, current_session):
    """
    Returns Redis connectivity status and blocklist stats.
    Admin dashboard uses this to show the Redis health indicator.

    GET /api/security/redis-status
    """
    from app.middleware.redis_client import is_available, REDIS_URL
    from app.middleware.velocity import blocklist_stats

    available = is_available()
    stats     = blocklist_stats()

    return jsonify({
        'success':   True,
        'redis': {
            'available':     available,
            'url':           REDIS_URL if available else 'unreachable',
            'mode':          'redis' if available else 'in-process-fallback',
        },
        'blocklist': stats,
    }), 200


@security_bp.route('/redis-reconnect', methods=['POST'])
@token_required
@admin_required
def redis_reconnect(current_user, current_session):
    """
    Force a Redis reconnection attempt.
    Useful when the Redis container starts after Flask.

    POST /api/security/redis-reconnect
    """
    from app.middleware.redis_client import reset_connection, get_redis

    reset_connection()
    client    = get_redis()
    available = client is not None

    return jsonify({
        'success':   True,
        'reconnected': available,
        'message':   'Redis connected' if available else 'Redis still unavailable — using fallback',
    }), 200


@security_bp.route('/velocity/<string:ip_address>', methods=['GET'])
@token_required
@admin_required
def velocity_lookup(current_user, current_session, ip_address):
    """
    Returns the current 60-second request count for an IP address.
    Lets the admin see how close an IP is to a velocity threshold.

    GET /api/security/velocity/1.2.3.4
    """
    from app.middleware.velocity import get_request_count

    count = get_request_count(ip_address)

    # Map count to score for display
    score = 0.0
    if   count >= 200: score = 0.30
    elif count >= 100: score = 0.20
    elif count >=  50: score = 0.10
    elif count >=  20: score = 0.05

    return jsonify({
        'success':       True,
        'ip':            ip_address,
        'request_count': count,
        'window_seconds': 60,
        'velocity_score': score,
        'thresholds': {
            '20_req': 0.05,
            '50_req': 0.10,
            '100_req': 0.20,
            '200_req': 0.30,
        }
    }), 200


@security_bp.route('/velocity-reset/<string:ip_address>', methods=['POST'])
@token_required
@admin_required
def velocity_reset(current_user, current_session, ip_address):
    """
    Reset the velocity counter for an IP (e.g. after a successful CAPTCHA).

    POST /api/security/velocity-reset/1.2.3.4
    """
    from app.middleware.velocity import reset_velocity

    reset_velocity(ip_address)
    return jsonify({
        'success': True,
        'message': f'Velocity counter reset for {ip_address}',
    }), 200


@security_bp.route('/blocklist-add', methods=['POST'])
@token_required
@admin_required
def blocklist_add(current_user, current_session):
    """
    Manually add a token to the Redis blocklist.
    Used when an admin wants to force-revoke a specific session
    from the dashboard without waiting for the score threshold.

    POST /api/security/blocklist-add
    Body: { "token": "<raw_jwt>", "reason": "manual_admin_revoke" }
    """
    from app.middleware.velocity import block_token
    from app.models import Session
    import hashlib

    data   = request.get_json() or {}
    token  = data.get('token', '').strip()
    reason = data.get('reason', 'manual_admin_revoke')

    if not token:
        return jsonify({'success': False, 'message': 'token is required'}), 400

    # Write to Redis
    blocked = block_token(token, reason)

    # Also revoke in DB for persistence
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db_session = Session.query.filter_by(token=token_hash).first()
    if db_session:
        db_session.is_active      = False
        db_session.revoked_at     = datetime.utcnow()
        db_session.revoked_reason = reason
        db.session.commit()

    return jsonify({
        'success':        True,
        'redis_blocked':  blocked,
        'db_revoked':     db_session is not None,
        'message':        f'Session revoked (redis={blocked}, db={db_session is not None})',
    }), 200


@security_bp.route('/blocklist-remove', methods=['POST'])
@token_required
@admin_required
def blocklist_remove(current_user, current_session):
    """
    Remove a token from the Redis blocklist.
    Does NOT reactivate the DB session — that requires a fresh login.

    POST /api/security/blocklist-remove
    Body: { "token": "<raw_jwt>" }
    """
    from app.middleware.velocity import unblock_token

    data  = request.get_json() or {}
    token = data.get('token', '').strip()

    if not token:
        return jsonify({'success': False, 'message': 'token is required'}), 400

    removed = unblock_token(token)
    return jsonify({
        'success': True,
        'removed': removed,
        'message': 'Token removed from blocklist' if removed else 'Token not in blocklist or Redis unavailable',
    }), 200

"""
TokenShield Step 1.4 — Routes to add to security_routes.py
===========================================================
Paste these two endpoints after the Step 1.3 routes in security_routes.py.
They expose geo data for the admin threat map and session detail panels.
"""


# =============================================================================
# STEP 1.4 — Geographic Impossibility routes
# =============================================================================

@security_bp.route('/session-location/<int:session_id>', methods=['GET'])
@token_required
@admin_required
def session_location(current_user, current_session, session_id):
    """
    Returns the last known location for a session from Redis.
    Used by the threat map and attacker-info panel to show
    where the session IP was last geolocated.

    GET /api/security/session-location/42
    """
    from app.middleware.geo import get_session_location

    location = get_session_location(session_id)
    if not location:
        return jsonify({
            'success':  False,
            'message':  'No location data available for this session',
        }), 404

    return jsonify({
        'success':    True,
        'session_id': session_id,
        'location':   location,
    }), 200

"""
TokenShield Step 3.1 — Nginx IP Block Routes
=============================================
Paste these endpoints into security_routes.py after the Step 1.4 routes.

Three new admin endpoints:
  POST /api/security/block-ip      — manually ban an IP at Nginx edge
  POST /api/security/unblock-ip   — lift a ban
  GET  /api/security/blocked-ips  — list all currently blocked IPs
"""

# =============================================================================
# STEP 3.1 — Nginx IP Block / Unblock endpoints
# =============================================================================

@security_bp.route('/block-ip', methods=['POST'])
@token_required
@admin_required
def block_ip(current_user, current_session):
    """
    Manually block an IP at the Nginx network edge.
    The ban takes effect within 5 seconds (Nginx watcher reload interval).

    POST /api/security/block-ip
    Body: {
        "ip":     "185.220.101.42",
        "reason": "manual_admin_block"   (optional)
    }
    """
    from app.middleware.nginx_block import block_ip_in_nginx, is_ip_blocked

    data   = request.get_json() or {}
    ip     = data.get("ip", "").strip()
    reason = data.get("reason", "manual_admin_block")

    if not ip:
        return jsonify({"success": False, "message": "ip is required"}), 400

    # Basic IP format validation
    import re
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return jsonify({"success": False, "message": "Invalid IP address format"}), 400

    if is_ip_blocked(ip):
        return jsonify({
            "success": False,
            "message": f"{ip} is already blocked",
            "already_blocked": True,
        }), 200

    blocked = block_ip_in_nginx(ip, reason)

    return jsonify({
        "success":        blocked,
        "ip":             ip,
        "reason":         reason,
        "nginx_blocked":  blocked,
        "message":        (
            f"{ip} added to Nginx blocklist — takes effect within 5 seconds"
            if blocked else
            f"Failed to block {ip} — check server logs"
        ),
    }), 200 if blocked else 500


@security_bp.route('/unblock-ip', methods=['POST'])
@token_required
@admin_required
def unblock_ip(current_user, current_session):
    """
    Remove an IP from the Nginx blocklist.

    POST /api/security/unblock-ip
    Body: { "ip": "185.220.101.42" }
    """
    from app.middleware.nginx_block import unblock_ip_in_nginx

    data = request.get_json() or {}
    ip   = data.get("ip", "").strip()

    if not ip:
        return jsonify({"success": False, "message": "ip is required"}), 400

    removed = unblock_ip_in_nginx(ip)

    return jsonify({
        "success": removed,
        "ip":      ip,
        "message": (
            f"{ip} removed from Nginx blocklist — takes effect within 5 seconds"
            if removed else
            f"{ip} was not in the blocklist"
        ),
    }), 200


@security_bp.route('/blocked-ips', methods=['GET'])
@token_required
@admin_required
def list_blocked_ips(current_user, current_session):
    """
    Return all IPs currently blocked at the Nginx network edge.

    GET /api/security/blocked-ips
    """
    from app.middleware.nginx_block import get_blocked_ips, blocked_ip_count

    ips   = get_blocked_ips()
    count = blocked_ip_count()

    return jsonify({
        "success":       True,
        "blocked_count": count,
        "blocked_ips":   ips,
        "blocklist_path": "/etc/nginx/blocked_ips.conf",
    }), 200

"""
TokenShield Step 3.2 — Redis Session Revocation Routes
=======================================================
Paste these endpoints into security_routes.py after the Step 3.1 routes.

New admin endpoints:
  POST /api/security/revoke-session    — instantly revoke a session via Redis
  POST /api/security/revoke-ip-sessions — revoke all sessions for an IP
  GET  /api/security/blocklist-stats   — Redis blocklist health + counts
"""

# =============================================================================
# STEP 3.2 — Redis Session Revocation endpoints
# =============================================================================

@security_bp.route('/revoke-session', methods=['POST'])
@token_required
@admin_required
def revoke_session(current_user, current_session):
    """
    Instantly revoke a session by session ID.
    Writes token to Redis blocklist (O(1) check on every request)
    AND updates the DB — belt + suspenders.

    Token revocation takes effect on the NEXT request from that session
    — no need to wait for JWT expiry.

    POST /api/security/revoke-session
    Body: {
        "session_id": 42,
        "reason":     "manual_admin_revoke"   (optional)
    }
    """
    from app.middleware.velocity import block_token
    from app.models import Session as SessionModel
    import hashlib

    data       = request.get_json() or {}
    session_id = data.get('session_id')
    reason     = data.get('reason', 'manual_admin_revoke')

    if not session_id:
        return jsonify({'success': False, 'message': 'session_id is required'}), 400

    target = SessionModel.query.get(session_id)
    if not target:
        return jsonify({'success': False, 'message': f'Session {session_id} not found'}), 404

    if not target.is_active:
        return jsonify({
            'success': False,
            'message': f'Session {session_id} is already inactive',
            'revoked_at':     target.revoked_at.isoformat() if target.revoked_at else None,
            'revoked_reason': target.revoked_reason,
        }), 200

    # Step 1: Redis blocklist — instant effect on next request
    redis_blocked = False
    if target.token:
        # token field stores the hash — we need raw token for block_token()
        # but block_token() hashes it again, so pass the hash directly
        # by using the internal key format
        from app.middleware.redis_client import get_redis
        from app.middleware.velocity import BLOCKLIST_PREFIX, BLOCKLIST_TTL
        r = get_redis()
        if r:
            try:
                # token in DB is already sha256 hashed — store directly
                key = BLOCKLIST_PREFIX + target.token
                r.setex(key, BLOCKLIST_TTL, reason)
                redis_blocked = True
            except Exception as exc:
                current_app.logger.error(f"Redis block failed: {exc}")

    # Step 2: DB revocation — persistent
    target.is_active      = False
    target.revoked_at     = datetime.utcnow()
    target.revoked_reason = reason

    # Step 3: Log the incident
    db.session.add(IncidentLog(
        session_id    = session_id,
        incident_type = 'manual_session_revocation',
        severity      = 'medium',
        anomaly_score = target.anomaly_score,
        action_taken  = f'session_revoked_redis={redis_blocked}_db=true',
        details       = json.dumps({
            'revoked_by':  current_user.username,
            'reason':      reason,
            'redis':       redis_blocked,
            'session_ip':  target.ip_address,
        }),
        ip_address = target.ip_address,
        user_agent = target.user_agent,
    ))
    db.session.commit()

    return jsonify({
        'success':       True,
        'session_id':    session_id,
        'redis_blocked': redis_blocked,
        'db_revoked':    True,
        'reason':        reason,
        'message':       (
            f'Session {session_id} revoked instantly via Redis + DB'
            if redis_blocked else
            f'Session {session_id} revoked in DB (Redis unavailable)'
        ),
    }), 200


@security_bp.route('/revoke-ip-sessions', methods=['POST'])
@token_required
@admin_required
def revoke_ip_sessions(current_user, current_session):
    """
    Revoke ALL active sessions originating from a given IP address.
    Useful when an attacker IP is identified — wipes every session
    they may have stolen or created.

    Combines Nginx IP block (Step 3.1) + Redis token revocation (Step 3.2)
    in one admin action.

    POST /api/security/revoke-ip-sessions
    Body: {
        "ip":           "185.220.101.42",
        "reason":       "attacker_ip_sweep",
        "block_nginx":  true    (also add to Nginx blocklist, default true)
    }
    """
    from app.middleware.velocity import BLOCKLIST_PREFIX, BLOCKLIST_TTL
    from app.middleware.redis_client import get_redis
    from app.middleware.nginx_block import block_ip_in_nginx
    from app.models import Session as SessionModel

    data        = request.get_json() or {}
    ip          = data.get('ip', '').strip()
    reason      = data.get('reason', 'attacker_ip_sweep')
    block_nginx = data.get('block_nginx', True)

    if not ip:
        return jsonify({'success': False, 'message': 'ip is required'}), 400

    # Find all active sessions from this IP
    sessions = SessionModel.query.filter_by(
        ip_address=ip, is_active=True
    ).all()

    r             = get_redis()
    redis_blocked = 0
    db_revoked    = 0
    now           = datetime.utcnow()

    for s in sessions:
        # Redis blocklist
        if r and s.token:
            try:
                r.setex(BLOCKLIST_PREFIX + s.token, BLOCKLIST_TTL, reason)
                redis_blocked += 1
            except Exception:
                pass

        # DB revocation
        s.is_active      = False
        s.revoked_at     = now
        s.revoked_reason = reason
        db_revoked += 1

    # Nginx IP block
    nginx_blocked = False
    if block_nginx:
        nginx_blocked = block_ip_in_nginx(ip, reason)

    # Single incident log for the sweep
    if sessions:
        db.session.add(IncidentLog(
            session_id    = sessions[0].id,
            incident_type = 'ip_session_sweep',
            severity      = 'high',
            anomaly_score = max((s.anomaly_score for s in sessions), default=0),
            action_taken  = f'swept_{db_revoked}_sessions_nginx={nginx_blocked}',
            details       = json.dumps({
                'ip':            ip,
                'reason':        reason,
                'sessions_found': len(sessions),
                'redis_blocked': redis_blocked,
                'db_revoked':    db_revoked,
                'nginx_blocked': nginx_blocked,
                'revoked_by':    current_user.username,
            }),
            ip_address = ip,
            user_agent = '',
        ))

    db.session.commit()

    return jsonify({
        'success':        True,
        'ip':             ip,
        'sessions_found': len(sessions),
        'redis_blocked':  redis_blocked,
        'db_revoked':     db_revoked,
        'nginx_blocked':  nginx_blocked,
        'message':        (
            f'Swept {db_revoked} sessions from {ip} — '
            f'Redis: {redis_blocked} blocked, Nginx: {"blocked" if nginx_blocked else "already blocked or skipped"}'
        ),
    }), 200


@security_bp.route('/blocklist-stats', methods=['GET'])
@token_required
@admin_required
def blocklist_stats_endpoint(current_user, current_session):
    """
    Redis blocklist health check and token count.
    Used by the admin dashboard Redis status indicator.

    GET /api/security/blocklist-stats
    """
    from app.middleware.velocity import blocklist_stats
    from app.middleware.redis_client import is_available, REDIS_URL
    from app.middleware.nginx_block import blocked_ip_count, get_blocked_ips

    stats        = blocklist_stats()
    redis_up     = is_available()
    nginx_count  = blocked_ip_count()
    nginx_ips    = get_blocked_ips()

    return jsonify({
        'success': True,
        'redis': {
            'available':     redis_up,
            'url':           REDIS_URL if redis_up else 'unreachable',
            'mode':          'redis' if redis_up else 'in-process-fallback',
            'blocked_tokens': stats.get('blocked_count', 0),
        },
        'nginx': {
            'blocked_ips':   nginx_count,
            'ip_list':       nginx_ips,
        },
        'summary': {
            'total_redis_blocks': stats.get('blocked_count', 0),
            'total_nginx_blocks': nginx_count,
        }
    }), 200

@security_bp.route('/geo-test', methods=['POST'])
@token_required
@admin_required
def geo_test(current_user, current_session):
    """
    Admin test endpoint — simulates an impossible travel scenario.
    Injects a fake previous location into Redis for the given session,
    then scores the given current IP against it.

    Useful for verifying Signal 6 without needing two real IPs.

    POST /api/security/geo-test
    Body: {
        "session_id": 1,
        "prev_lat":  40.7128,   // New York
        "prev_lon": -74.0060,
        "prev_ip":  "1.2.3.4",
        "prev_minutes_ago": 2,
        "current_ip": "35.197.91.185"  // Tokyo
    }
    """
    import json
    from datetime import datetime, timedelta
    from app.middleware.redis_client import get_redis
    from app.middleware.geo import GEO_KEY_PREFIX, GEO_TTL_SECONDS, _haversine, _score_travel, _coords_from_ip

    data = request.get_json() or {}

    session_id      = data.get('session_id')
    prev_lat        = data.get('prev_lat')
    prev_lon        = data.get('prev_lon')
    prev_ip         = data.get('prev_ip', 'injected')
    minutes_ago     = data.get('prev_minutes_ago', 2)
    current_ip      = data.get('current_ip')

    if not all([session_id, prev_lat, prev_lon, current_ip]):
        return jsonify({'success': False, 'message': 'session_id, prev_lat, prev_lon, current_ip required'}), 400

    # Inject fake previous location into Redis
    prev_ts = (datetime.utcnow() - timedelta(minutes=minutes_ago)).isoformat()
    record  = json.dumps({'lat': prev_lat, 'lon': prev_lon, 'ip': prev_ip, 'ts': prev_ts})

    r = get_redis()
    if r:
        r.setex(f"{GEO_KEY_PREFIX}{session_id}", GEO_TTL_SECONDS, record)

    # Resolve current IP coords
    current_coords = _coords_from_ip(current_ip)
    if not current_coords:
        return jsonify({
            'success': False,
            'message': f'Could not resolve coordinates for {current_ip} — is IPINFO_TOKEN set?',
        }), 422

    current_lat, current_lon = current_coords
    distance_km     = _haversine(prev_lat, prev_lon, current_lat, current_lon)
    elapsed_seconds = minutes_ago * 60
    score, reason   = _score_travel(distance_km, elapsed_seconds)

    return jsonify({
        'success':          True,
        'prev_location':    {'lat': prev_lat, 'lon': prev_lon, 'ip': prev_ip, 'ts': prev_ts},
        'current_location': {'lat': current_lat, 'lon': current_lon, 'ip': current_ip},
        'distance_km':      round(distance_km, 1),
        'elapsed_minutes':  minutes_ago,
        'required_speed_kmh': round((distance_km / elapsed_seconds) * 3600, 1),
        'max_speed_kmh':    900,
        'geo_score':        score,
        'reason':           reason,
        'verdict':          'IMPOSSIBLE' if score >= 0.35 else
                            'HIGHLY_SUSPICIOUS' if score >= 0.20 else
                            'SUSPICIOUS' if score >= 0.10 else 'CLEAN',
    }), 200

"""
TokenShield — Step 3.5 Security Route Additions
================================================
File: PASTE INTO app/security_routes.py  (after your Step 3.4 routes at the bottom)

Three new endpoints that feed the simulation dashboard timeline panel:
  GET  /api/security/mitigation/live      — SSE stream (EventSource)
  GET  /api/security/mitigation/timeline  — REST poll fallback
  POST /api/security/mitigation/simulate  — trigger demo sequence for testing
  GET  /api/security/mitigation/stats     — aggregate performance stats
"""

import time as _time
import threading as _threading
import json as _json
from flask import Response, stream_with_context
from app.middleware.mitigation_timeline import (
    record_step, get_timeline, get_all_summaries,
    subscribe, unsubscribe, subscriber_count, STEPS,
)


# =============================================================================
# STEP 3.5 — Mitigation Timeline endpoints
# =============================================================================

@security_bp.route('/mitigation/live')
def mitigation_live():
    """
    Server-Sent Events stream — the simulation dashboard connects here.
    Receives one JSON event per mitigation step as it fires in real-time.

    No auth required so the dashboard page can connect before the
    full JWT bootstrap.  The data is non-sensitive (scores + step names).

    Client usage (JS):
        const es = new EventSource('/api/security/mitigation/live');
        es.onmessage = e => handleStep(JSON.parse(e.data));
    """
    q = subscribe()

    def generate():
        yield "retry: 3000\n\n"   # tell browser to reconnect after 3 s if dropped
        try:
            while True:
                try:
                    event = q.get(timeout=20)
                    yield f"data: {_json.dumps(event)}\n\n"
                except Exception:
                    yield ": heartbeat\n\n"   # keep connection alive through proxies
        finally:
            unsubscribe(q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "X-Accel-Buffering": "no",   # disable Nginx response buffering
        },
    )


@security_bp.route('/mitigation/timeline')
@token_required
def mitigation_timeline(current_user, current_session):
    """
    REST fallback for browsers that block EventSource, or for polling.

    GET /api/security/mitigation/timeline               → recent incident summaries
    GET /api/security/mitigation/timeline?id=<inc_id>  → full step list for one incident
    """
    incident_id = request.args.get("id") or request.args.get("incident_id")
    limit       = int(request.args.get("limit", 30))

    if incident_id:
        steps = get_timeline(str(incident_id))
        return jsonify({"success": True, "incident_id": incident_id, "steps": steps})

    summaries = get_all_summaries(limit=limit)

    # Enrich with DB incident data
    enriched = []
    for s in summaries:
        inc = IncidentLog.query.get(int(s["incident_id"])) if s["incident_id"].isdigit() else None
        enriched.append({
            **s,
            "attack_type":  inc.incident_type if inc else "—",
            "threat_score": round(inc.anomaly_score, 3) if inc else 0,
            "ip":           inc.ip_address if inc else "—",
            "severity":     inc.severity if inc else "—",
            "timestamp":    inc.timestamp.isoformat() if inc else s.get("first_ts"),
        })

    return jsonify({
        "success":   True,
        "incidents": enriched,
        "live_subscribers": subscriber_count(),
    })


@security_bp.route('/mitigation/simulate', methods=['POST'])
@token_required
@admin_required
def mitigation_simulate(current_user, current_session):
    """
    Trigger a synthetic mitigation sequence for demo / testing.
    Perfect for showing the timeline panel without needing a real attack.

    POST /api/security/mitigation/simulate
    Body: {
        "attack_type":  "sql_injection",     (default: "demo_attack")
        "ip":           "10.0.0.99",         (default: "192.168.1.99")
        "threat_score": 0.92,               (default: 0.92)
        "fast":         false               (if true: fire all steps instantly)
    }
    """
    import random
    data        = request.get_json(force=True) or {}
    attack_type = data.get("attack_type", "demo_attack")
    ip          = data.get("ip", "192.168.1.99")
    score       = float(data.get("threat_score", 0.92))
    fast        = bool(data.get("fast", False))

    # Create a real IncidentLog so the timeline can be enriched
    inc = IncidentLog(
        session_id    = current_session.id,
        incident_type = attack_type,
        severity      = "critical" if score >= 0.85 else "high",
        anomaly_score = score,
        action_taken  = "simulated_mitigation",
        ip_address    = ip,
        user_agent    = request.headers.get("User-Agent", ""),
        details       = _json.dumps({"simulated": True, "triggered_by": current_user.username}),
    )
    db.session.add(inc)
    db.session.commit()
    incident_id = str(inc.id)

    detail_map = {
        1: f"token revoked → blocklist",
        2: f"{ip} → blocked_ip:86400s",
        3: f"nginx deny rule written + reload queued",
        4: f"device fingerprint banned",
        5: f"account hard-locked, TOTP required",
        6: f"coordinated check: 0 similar in 5 min",
        7: f"alert queued → security@neovault.local",
        8: f"pushed to {subscriber_count()} subscriber(s)",
    }

    def _run():
        base = _time.monotonic()
        for step_info in STEPS:
            nominal_s = step_info["nominal_ms"] / 1000.0
            if not fast:
                elapsed = _time.monotonic() - base
                sleep_for = nominal_s - elapsed
                if sleep_for > 0:
                    _time.sleep(sleep_for)
            actual_ms = (_time.monotonic() - base) * 1000
            jitter    = random.uniform(-1.5, 4.0)
            status    = "ok" if random.random() > 0.04 else "error"
            record_step(
                incident_id,
                step_info["step"],
                status,
                actual_ms + jitter,
                detail_map.get(step_info["step"], ""),
            )

    _threading.Thread(target=_run, daemon=True).start()

    return jsonify({
        "success":     True,
        "incident_id": incident_id,
        "message":     f"Mitigation sequence started (fast={fast})",
        "stream_url":  "/api/security/mitigation/live",
        "poll_url":    f"/api/security/mitigation/timeline?id={incident_id}",
    }), 202


@security_bp.route('/mitigation/stats')
@token_required
@admin_required
def mitigation_stats(current_user, current_session):
    """
    Aggregate performance stats across all recorded mitigation sequences.
    Used by the stats panel in the timeline UI.

    GET /api/security/mitigation/stats
    """
    summaries = get_all_summaries(limit=500)

    total          = len(summaries)
    fully_done     = sum(1 for s in summaries if s["status"] == "complete")
    avg_total_ms   = (sum(s["total_ms"] for s in summaries) / total) if total else 0

    # Per-step success / error counts across all incidents
    step_agg = {n: {"ok": 0, "error": 0, "skipped": 0, "ms_sum": 0.0}
                for n in range(1, 9)}
    for s in summaries:
        steps = get_timeline(s["incident_id"])
        for ev in steps:
            sn = ev["step"]
            step_agg[sn][ev["status"]] = step_agg[sn].get(ev["status"], 0) + 1
            step_agg[sn]["ms_sum"] += ev["actual_ms"]

    step_summary = []
    for sn in range(1, 9):
        agg   = step_agg[sn]
        calls = agg["ok"] + agg.get("error", 0) + agg.get("skipped", 0)
        step_summary.append({
            "step":    sn,
            "name":    STEPS[sn - 1]["name"],
            "target":  STEPS[sn - 1]["target"],
            "nominal_ms": STEPS[sn - 1]["nominal_ms"],
            "ok":      agg["ok"],
            "error":   agg.get("error", 0),
            "skipped": agg.get("skipped", 0),
            "avg_ms":  round(agg["ms_sum"] / calls, 1) if calls else 0,
        })

    return jsonify({
        "success":           True,
        "total_incidents":   total,
        "fully_mitigated":   fully_done,
        "partial":           total - fully_done,
        "avg_total_ms":      round(avg_total_ms, 1),
        "live_subscribers":  subscriber_count(),
        "steps":             step_summary,
    })

# =============================================================================
# HELPER FUNCTIONS  (unchanged from original)
# =============================================================================

def generate_device_fingerprint(metadata):
    components = [
        str(metadata.get('screen_width', '')),
        str(metadata.get('screen_height', '')),
        str(metadata.get('screen_depth', '')),
        str(metadata.get('timezone_offset', '')),
        str(metadata.get('platform', '')),
        str(metadata.get('cpu_cores', '')),
        str(metadata.get('canvas_fingerprint', '')),
        str(metadata.get('webgl_fingerprint', '')),
        metadata.get('user_agent', '')[:100]
    ]
    combined    = '|'.join(components)
    fingerprint = hashlib.sha256(combined.encode()).hexdigest()[:16]
    return fingerprint


def analyze_threat(session, metadata):
    threat_score   = session.anomaly_score
    threat_factors = []

    if session.ip_address != metadata['ip_address']:
        threat_score += 0.3
        threat_factors.append('IP address changed mid-session')

    if session.user_agent != metadata['user_agent']:
        threat_score += 0.25
        threat_factors.append('User agent changed')

    geo = get_geolocation_from_ip(metadata['ip_address'])
    if geo.get('country') in ['Russia', 'China', 'North Korea', 'Iran']:
        threat_score += 0.15
        threat_factors.append(f"Access from high-risk country: {geo.get('country')}")

    if is_vpn_or_proxy(metadata['ip_address']):
        threat_score += 0.20
        threat_factors.append('VPN or proxy detected')

    if metadata.get('timezone_offset'):
        expected_offset = get_expected_timezone_offset(geo)
        if abs(metadata['timezone_offset'] - expected_offset) > 2:
            threat_score += 0.10
            threat_factors.append('Timezone mismatch')

    threat_score = min(threat_score, 1.0)

    if threat_score >= 0.85:   threat_level = 'critical'
    elif threat_score >= 0.7:  threat_level = 'high'
    elif threat_score >= 0.5:  threat_level = 'medium'
    elif threat_score >= 0.3:  threat_level = 'low'
    else:                      threat_level = 'safe'

    recommendations = []
    if threat_score >= 0.85:
        recommendations += ['Immediately revoke session',
                            'Notify user of suspicious activity',
                            'Require 2FA for re-authentication']
    elif threat_score >= 0.7:
        recommendations += ['Challenge with additional verification',
                            'Monitor closely for further suspicious activity']
    elif threat_score >= 0.5:
        recommendations += ['Increase monitoring frequency',
                            'Log all actions for review']

    return {
        'anomaly_score':   round(threat_score, 4),
        'threat_level':    threat_level,
        'is_suspicious':   threat_score >= 0.3,
        'threat_factors':  threat_factors,
        'recommendations': recommendations
    }


def get_geolocation_from_ip(ip_address):
    """
    Thin wrapper — delegates to the live IPinfo cache when available,
    falls back to the original mock table otherwise.
    Step 1.4 will replace this entirely with real geo + distance math.
    """
    try:
        from app.middleware.ip_reputation import get_ip_details
        details = get_ip_details(ip_address)
        if details and details.get('city'):
            loc = details.get('loc', ',').split(',')
            return {
                'city':         details.get('city', 'Unknown'),
                'country':      details.get('country_name', details.get('country', 'Unknown')),
                'country_code': details.get('country', 'XX'),
                'latitude':     float(loc[0]) if len(loc) == 2 else None,
                'longitude':    float(loc[1]) if len(loc) == 2 else None,
                'timezone':     details.get('timezone', 'Unknown'),
                'isp':          details.get('org', 'Unknown'),
            }
    except Exception:
        pass

    # Original mock fallback
    mock_locations = {
        '185.220.101.42': {
            'city': 'Moscow', 'country': 'Russia', 'country_code': 'RU',
            'latitude': 55.7558, 'longitude': 37.6173,
            'timezone': 'Europe/Moscow', 'isp': 'Unknown ISP'
        },
        '202.112.51.89': {
            'city': 'Beijing', 'country': 'China', 'country_code': 'CN',
            'latitude': 39.9042, 'longitude': 116.4074,
            'timezone': 'Asia/Shanghai', 'isp': 'China Telecom'
        },
        '197.210.55.23': {
            'city': 'Lagos', 'country': 'Nigeria', 'country_code': 'NG',
            'latitude': 6.5244, 'longitude': 3.3792,
            'timezone': 'Africa/Lagos', 'isp': 'MTN Nigeria'
        },
    }
    return mock_locations.get(ip_address, {
        'city': 'Unknown', 'country': 'Unknown', 'country_code': 'XX',
        'latitude': None, 'longitude': None,
        'timezone': 'Unknown', 'isp': 'Unknown'
    })


def parse_user_agent(user_agent):
    if not user_agent:
        return {'browser': 'Unknown', 'version': 'Unknown', 'os': 'Unknown', 'device': 'Unknown'}
    browser, version, os_name, device = 'Unknown', 'Unknown', 'Unknown', 'Desktop'
    if 'Chrome' in user_agent:
        browser = 'Chrome'
        m = re.search(r'Chrome/(\d+)', user_agent)
        if m: version = m.group(1)
    elif 'Firefox' in user_agent:
        browser = 'Firefox'
        m = re.search(r'Firefox/(\d+)', user_agent)
        if m: version = m.group(1)
    elif 'Safari' in user_agent and 'Chrome' not in user_agent:
        browser = 'Safari'
    if 'Windows NT 10.0' in user_agent:    os_name = 'Windows 10'
    elif 'Mac OS X' in user_agent:         os_name = 'macOS'
    elif 'Linux' in user_agent:            os_name = 'Linux'
    elif 'Android' in user_agent:          os_name = 'Android';  device = 'Mobile'
    elif 'iPhone' in user_agent:           os_name = 'iOS';      device = 'Mobile'
    elif 'iPad' in user_agent:             os_name = 'iOS';      device = 'Tablet'
    return {'browser': browser, 'version': version, 'os': os_name,
            'device': device, 'full': user_agent}


def extract_device_info(metadata):
    return {
        'screen':      f"{metadata.get('screen_width')}x{metadata.get('screen_height')}"
                       if metadata.get('screen_width') else 'Unknown',
        'color_depth': f"{metadata.get('screen_depth')} bit"
                       if metadata.get('screen_depth') else 'Unknown',
        'platform':    metadata.get('platform', 'Unknown'),
        'cpu_cores':   metadata.get('cpu_cores', 'Unknown'),
        'memory':      f"{metadata.get('memory')} GB"
                       if metadata.get('memory') else 'Unknown',
        'timezone':    metadata.get('timezone', 'Unknown'),
        'language':    metadata.get('language', 'Unknown'),
    }


def classify_threat_level(anomaly_score):
    if anomaly_score >= 0.85: return 'critical'
    if anomaly_score >= 0.7:  return 'high'
    if anomaly_score >= 0.5:  return 'medium'
    if anomaly_score >= 0.3:  return 'low'
    return 'safe'


def is_vpn_or_proxy(ip_address):
    vpn_patterns = ['185.220', '197.210']
    return any(ip_address.startswith(p) for p in vpn_patterns)


def get_expected_timezone_offset(geolocation):
    tz_map = {
        'Europe/Moscow':      3,
        'Asia/Shanghai':      8,
        'Africa/Lagos':       1,
        'America/New_York':  -5,
        'America/Los_Angeles': -8,
    }
    return tz_map.get(geolocation.get('timezone', ''), 0)