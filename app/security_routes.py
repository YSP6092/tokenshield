"""
TokenShield Security Engine Routes
Step 3: Advanced threat detection API with attacker metadata capture
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
from app import db
from app.models import Session, BehaviorLog, IncidentLog, User
from app.utils import token_required, admin_required, get_client_ip, get_user_agent
import json
import hashlib
import re

security_bp = Blueprint('security', __name__, url_prefix='/api/security')


# ============================================================================
# THREAT DETECTION ENGINE
# ============================================================================

@security_bp.route('/threat-detect', methods=['POST'])
@token_required
def threat_detect(current_user, current_session):
    """
    Advanced threat detection endpoint
    Captures comprehensive attacker metadata when suspicious token usage detected
    
    Captures:
    - IP address & geolocation
    - Device fingerprint
    - Browser fingerprint
    - Screen resolution & timezone
    - Canvas fingerprint
    - WebGL fingerprint
    - User behavior patterns
    """
    try:
        data = request.get_json() or {}
        
        # Extract comprehensive metadata
        metadata = {
            # Network data
            'ip_address': get_client_ip(),
            'user_agent': get_user_agent(),
            'referrer': request.referrer,
            'origin': request.headers.get('Origin'),
            
            # Device fingerprint (from client)
            'screen_width': data.get('screen_width'),
            'screen_height': data.get('screen_height'),
            'screen_depth': data.get('screen_depth'),
            'timezone_offset': data.get('timezone_offset'),
            'timezone': data.get('timezone'),
            'language': data.get('language'),
            'platform': data.get('platform'),
            'cpu_cores': data.get('cpu_cores'),
            'memory': data.get('memory'),
            
            # Browser fingerprint
            'canvas_fingerprint': data.get('canvas_fingerprint'),
            'webgl_fingerprint': data.get('webgl_fingerprint'),
            'audio_fingerprint': data.get('audio_fingerprint'),
            'fonts': data.get('fonts'),
            'plugins': data.get('plugins'),
            'do_not_track': data.get('do_not_track'),
            'ad_blocker': data.get('ad_blocker'),
            
            # Behavioral data
            'mouse_speed': data.get('mouse_speed'),
            'typing_speed': data.get('typing_speed'),
            'scroll_pattern': data.get('scroll_pattern'),
            'click_pattern': data.get('click_pattern'),
            
            # Location data (from client geolocation API)
            'latitude': data.get('latitude'),
            'longitude': data.get('longitude'),
            'accuracy': data.get('accuracy'),
            
            # Action context
            'action_type': data.get('action_type', 'unknown'),
            'endpoint': data.get('endpoint'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Generate unique device fingerprint
        device_fingerprint = generate_device_fingerprint(metadata)
        metadata['device_fingerprint'] = device_fingerprint
        
        # Perform threat analysis
        threat_analysis = analyze_threat(current_session, metadata)
        
        # Update session anomaly score
        current_session.anomaly_score = threat_analysis['anomaly_score']
        current_session.is_suspicious = threat_analysis['is_suspicious']
        current_session.last_activity = datetime.utcnow()
        
        # Log the behavior with metadata
        behavior_log = BehaviorLog(
            session_id=current_session.id,
            action_type=metadata['action_type'],
            ip_address=metadata['ip_address'],
            user_agent=metadata['user_agent'],
            endpoint=metadata.get('endpoint', '/unknown'),
            request_method='POST',
           fingerprint_data=json.dumps(metadata)
        )
        db.session.add(behavior_log)
        
        # If high threat, create incident
        if threat_analysis['anomaly_score'] >= 0.7:
            incident = IncidentLog(
                session_id=current_session.id,
                incident_type='high_threat_detected',
                severity='critical' if threat_analysis['anomaly_score'] >= 0.85 else 'high',
                anomaly_score=threat_analysis['anomaly_score'],
                action_taken='monitored',
                details=json.dumps({
                    'threat_factors': threat_analysis['threat_factors'],
                    'device_fingerprint': device_fingerprint,
                    'metadata': metadata,
                    'recommendations': threat_analysis['recommendations']
                }),
                ip_address=metadata['ip_address'],
                user_agent=metadata['user_agent']
            )
            db.session.add(incident)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'threat_analysis': {
                'anomaly_score': threat_analysis['anomaly_score'],
                'threat_level': threat_analysis['threat_level'],
                'is_suspicious': threat_analysis['is_suspicious'],
                'threat_factors': threat_analysis['threat_factors'],
                'device_fingerprint': device_fingerprint,
                'recommendations': threat_analysis['recommendations']
            },
            'session_status': {
                'is_active': current_session.is_active,
                'should_challenge': threat_analysis['anomaly_score'] >= 0.5,
                'should_revoke': threat_analysis['anomaly_score'] >= 0.85
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Threat detection error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Threat detection failed'
        }), 500


@security_bp.route('/attacker-info/<int:session_id>', methods=['GET'])
@admin_required
def get_attacker_info(current_user, current_session, session_id):
    """
    Get comprehensive attacker information for a session
    Admin only - used in Security Engine Dashboard
    """
    try:
        target_session = Session.query.get(session_id)
        
        if not target_session:
            return jsonify({
                'success': False,
                'message': 'Session not found'
            }), 404
        
        # Get all behavior logs with metadata
        behavior_logs = BehaviorLog.query.filter_by(session_id=session_id)\
            .order_by(BehaviorLog.timestamp.desc())\
            .limit(50)\
            .all()
        
        # Extract metadata from logs
        metadata_history = []
        for log in behavior_logs:
            if log.fingerprint_data:
                try:
                    meta = json.loads(log.fingerprint_data)
                    metadata_history.append({
                        'timestamp': log.timestamp.isoformat(),
                        'action': log.action_type,
                        'metadata': meta
                    })
                except:
                    pass
        
        # Get latest metadata
        latest_metadata = metadata_history[0] if metadata_history else {}
        
        # Get geolocation from IP (you can integrate with IP geolocation API)
        geolocation = get_geolocation_from_ip(target_session.ip_address)
        
        # Get incidents for this session
        incidents = IncidentLog.query.filter_by(session_id=session_id)\
            .order_by(IncidentLog.timestamp.desc())\
            .limit(10)\
            .all()
        
        attacker_profile = {
            'session_id': target_session.id,
            'user_id': target_session.user_id,
            'username': target_session.user.username if target_session.user else 'Unknown',
            
            # Network info
            'ip_address': target_session.ip_address,
            'geolocation': geolocation,
            'user_agent': target_session.user_agent,
            'parsed_user_agent': parse_user_agent(target_session.user_agent),
            
            # Device fingerprint
            'device_fingerprint': latest_metadata.get('metadata', {}).get('device_fingerprint'),
            'device_info': extract_device_info(latest_metadata.get('metadata', {})),
            
            # Browser fingerprint
            'browser_fingerprint': {
                'canvas': latest_metadata.get('metadata', {}).get('canvas_fingerprint'),
                'webgl': latest_metadata.get('metadata', {}).get('webgl_fingerprint'),
                'audio': latest_metadata.get('metadata', {}).get('audio_fingerprint'),
                'fonts': latest_metadata.get('metadata', {}).get('fonts'),
                'plugins': latest_metadata.get('metadata', {}).get('plugins')
            },
            
            # Threat info
            'anomaly_score': target_session.anomaly_score,
            'is_suspicious': target_session.is_suspicious,
            'threat_level': classify_threat_level(target_session.anomaly_score),
            
            # Session info
            'created_at': target_session.created_at.isoformat(),
            'last_activity': target_session.last_activity.isoformat(),
            'is_active': target_session.is_active,
            'revoked_at': target_session.revoked_at.isoformat() if target_session.revoked_at else None,
            'revoked_reason': target_session.revoked_reason,
            
            # Activity history
            'total_actions': len(behavior_logs),
            'metadata_history': metadata_history,
            'incidents': [incident.to_dict() for incident in incidents]
        }
        
        return jsonify({
            'success': True,
            'attacker_profile': attacker_profile
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get attacker info error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to get attacker information'
        }), 500


@security_bp.route('/live-threats', methods=['GET'])
@admin_required
def get_live_threats(current_user, current_session):
    """
    Get real-time threat feed
    Shows all currently suspicious sessions with attacker metadata
    """
    try:
        # Get all suspicious active sessions
        suspicious_sessions = Session.query.filter(
            Session.is_active == True,
            Session.anomaly_score >= 0.3
        ).order_by(Session.anomaly_score.desc()).all()
        
        threats = []
        for session in suspicious_sessions:
            # Get latest behavior log with metadata
            latest_behavior = BehaviorLog.query.filter_by(session_id=session.id)\
                .order_by(BehaviorLog.timestamp.desc())\
                .first()

            metadata = {}
            if latest_behavior and latest_behavior.fingerprint_data:
                try:
                    metadata = json.loads(latest_behavior.fingerprint_data)
                except:
                    pass
            
            geolocation = get_geolocation_from_ip(session.ip_address)
            
            threats.append({
                'session_id': session.id,
                'user_id': session.user_id,
                'username': session.user.username if session.user else 'Unknown',
                'ip_address': session.ip_address,
                'geolocation': geolocation,
                'user_agent': parse_user_agent(session.user_agent),
                'device_fingerprint': metadata.get('device_fingerprint'),
                'anomaly_score': session.anomaly_score,
                'threat_level': classify_threat_level(session.anomaly_score),
                'last_activity': session.last_activity.isoformat(),
                'created_at': session.created_at.isoformat(),
                'is_suspicious': session.is_suspicious
            })
        
        return jsonify({
            'success': True,
            'threats': threats,
            'total_threats': len(threats),
            'critical_count': sum(1 for t in threats if t['anomaly_score'] >= 0.85),
            'high_count': sum(1 for t in threats if 0.7 <= t['anomaly_score'] < 0.85),
            'medium_count': sum(1 for t in threats if 0.5 <= t['anomaly_score'] < 0.7),
            'low_count': sum(1 for t in threats if 0.3 <= t['anomaly_score'] < 0.5)
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get live threats error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to get live threats'
        }), 500


@security_bp.route('/threat-map-data', methods=['GET'])
@admin_required
def get_threat_map_data(current_user, current_session):
    """
    Get threat data formatted for geographic visualization
    Returns all suspicious sessions with geolocation for map display
    """
    try:
        # Get suspicious sessions from last 24 hours
        from datetime import timedelta
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        
        suspicious_sessions = Session.query.filter(
            Session.created_at >= cutoff_time,
            Session.anomaly_score >= 0.3
        ).all()
        
        map_data = []
        for session in suspicious_sessions:
            geo = get_geolocation_from_ip(session.ip_address)
            
            if geo.get('latitude') and geo.get('longitude'):
                map_data.append({
                    'session_id': session.id,
                    'latitude': geo['latitude'],
                    'longitude': geo['longitude'],
                    'city': geo.get('city', 'Unknown'),
                    'country': geo.get('country', 'Unknown'),
                    'ip_address': session.ip_address,
                    'anomaly_score': session.anomaly_score,
                    'threat_level': classify_threat_level(session.anomaly_score),
                    'timestamp': session.created_at.isoformat(),
                    'is_active': session.is_active
                })
        
        return jsonify({
            'success': True,
            'map_data': map_data,
            'total_locations': len(map_data)
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get threat map data error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to get threat map data'
        }), 500


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def generate_device_fingerprint(metadata):
    """Generate unique device fingerprint from metadata"""
    fingerprint_components = [
        str(metadata.get('screen_width', '')),
        str(metadata.get('screen_height', '')),
        str(metadata.get('screen_depth', '')),
        str(metadata.get('timezone_offset', '')),
        str(metadata.get('platform', '')),
        str(metadata.get('cpu_cores', '')),
        str(metadata.get('canvas_fingerprint', '')),
        str(metadata.get('webgl_fingerprint', '')),
        metadata.get('user_agent', '')[:100]  # First 100 chars of UA
    ]
    
    combined = '|'.join(fingerprint_components)
    fingerprint = hashlib.sha256(combined.encode()).hexdigest()[:16]
    return fingerprint


def analyze_threat(session, metadata):
    """
    Analyze threat level based on session and metadata
    Returns threat score and factors
    """
    threat_score = session.anomaly_score
    threat_factors = []
    
    # Check for IP change
    if session.ip_address != metadata['ip_address']:
        threat_score += 0.3
        threat_factors.append('IP address changed mid-session')
    
    # Check for user agent change
    if session.user_agent != metadata['user_agent']:
        threat_score += 0.25
        threat_factors.append('User agent changed')
    
    # Check for suspicious geolocation
    geo = get_geolocation_from_ip(metadata['ip_address'])
    if geo.get('country') in ['Russia', 'China', 'North Korea', 'Iran']:  # High-risk countries
        threat_score += 0.15
        threat_factors.append(f"Access from high-risk country: {geo.get('country')}")
    
    # Check for VPN/Proxy indicators
    if is_vpn_or_proxy(metadata['ip_address']):
        threat_score += 0.20
        threat_factors.append('VPN or proxy detected')
    
    # Check for unusual timezone
    if metadata.get('timezone_offset'):
        expected_offset = get_expected_timezone_offset(geo)
        if abs(metadata['timezone_offset'] - expected_offset) > 2:
            threat_score += 0.10
            threat_factors.append('Timezone mismatch')
    
    # Cap at 1.0
    threat_score = min(threat_score, 1.0)
    
    # Determine threat level
    if threat_score >= 0.85:
        threat_level = 'critical'
    elif threat_score >= 0.7:
        threat_level = 'high'
    elif threat_score >= 0.5:
        threat_level = 'medium'
    elif threat_score >= 0.3:
        threat_level = 'low'
    else:
        threat_level = 'safe'
    
    # Generate recommendations
    recommendations = []
    if threat_score >= 0.85:
        recommendations.append('Immediately revoke session')
        recommendations.append('Notify user of suspicious activity')
        recommendations.append('Require 2FA for re-authentication')
    elif threat_score >= 0.7:
        recommendations.append('Challenge with additional verification')
        recommendations.append('Monitor closely for further suspicious activity')
    elif threat_score >= 0.5:
        recommendations.append('Increase monitoring frequency')
        recommendations.append('Log all actions for review')
    
    return {
        'anomaly_score': threat_score,
        'threat_level': threat_level,
        'is_suspicious': threat_score >= 0.3,
        'threat_factors': threat_factors,
        'recommendations': recommendations
    }


def get_geolocation_from_ip(ip_address):
    """
    Get geolocation from IP address
    For demo: returns mock data for specific IPs
    In production: integrate with IP geolocation API (ipapi.co, ipstack, etc.)
    """
    # Mock data for demo attackers
    mock_locations = {
        '185.220.101.42': {
            'city': 'Moscow',
            'country': 'Russia',
            'country_code': 'RU',
            'latitude': 55.7558,
            'longitude': 37.6173,
            'timezone': 'Europe/Moscow',
            'isp': 'Unknown ISP'
        },
        '202.112.51.89': {
            'city': 'Beijing',
            'country': 'China',
            'country_code': 'CN',
            'latitude': 39.9042,
            'longitude': 116.4074,
            'timezone': 'Asia/Shanghai',
            'isp': 'China Telecom'
        },
        '197.210.55.23': {
            'city': 'Lagos',
            'country': 'Nigeria',
            'country_code': 'NG',
            'latitude': 6.5244,
            'longitude': 3.3792,
            'timezone': 'Africa/Lagos',
            'isp': 'MTN Nigeria'
        }
    }
    
    if ip_address in mock_locations:
        return mock_locations[ip_address]
    
    # Default location for other IPs
    return {
        'city': 'Unknown',
        'country': 'Unknown',
        'country_code': 'XX',
        'latitude': None,
        'longitude': None,
        'timezone': 'Unknown',
        'isp': 'Unknown'
    }


def parse_user_agent(user_agent):
    """Parse user agent string into components"""
    if not user_agent:
        return {
            'browser': 'Unknown',
            'version': 'Unknown',
            'os': 'Unknown',
            'device': 'Unknown'
        }
    
    # Simple parsing (in production, use user-agents library)
    browser = 'Unknown'
    version = 'Unknown'
    os_name = 'Unknown'
    device = 'Desktop'
    
    if 'Chrome' in user_agent:
        browser = 'Chrome'
        match = re.search(r'Chrome/(\d+)', user_agent)
        if match:
            version = match.group(1)
    elif 'Firefox' in user_agent:
        browser = 'Firefox'
        match = re.search(r'Firefox/(\d+)', user_agent)
        if match:
            version = match.group(1)
    elif 'Safari' in user_agent and 'Chrome' not in user_agent:
        browser = 'Safari'
    
    if 'Windows' in user_agent:
        os_name = 'Windows'
        if 'Windows NT 10.0' in user_agent:
            os_name = 'Windows 10'
    elif 'Mac OS X' in user_agent:
        os_name = 'macOS'
    elif 'Linux' in user_agent:
        os_name = 'Linux'
    elif 'Android' in user_agent:
        os_name = 'Android'
        device = 'Mobile'
    elif 'iPhone' in user_agent or 'iPad' in user_agent:
        os_name = 'iOS'
        device = 'Mobile' if 'iPhone' in user_agent else 'Tablet'
    
    return {
        'browser': browser,
        'version': version,
        'os': os_name,
        'device': device,
        'full': user_agent
    }


def extract_device_info(metadata):
    """Extract device information from metadata"""
    return {
        'screen': f"{metadata.get('screen_width')}x{metadata.get('screen_height')}" if metadata.get('screen_width') else 'Unknown',
        'color_depth': f"{metadata.get('screen_depth')} bit" if metadata.get('screen_depth') else 'Unknown',
        'platform': metadata.get('platform', 'Unknown'),
        'cpu_cores': metadata.get('cpu_cores', 'Unknown'),
        'memory': f"{metadata.get('memory')} GB" if metadata.get('memory') else 'Unknown',
        'timezone': metadata.get('timezone', 'Unknown'),
        'language': metadata.get('language', 'Unknown')
    }


def classify_threat_level(anomaly_score):
    """Classify threat level from anomaly score"""
    if anomaly_score >= 0.85:
        return 'critical'
    elif anomaly_score >= 0.7:
        return 'high'
    elif anomaly_score >= 0.5:
        return 'medium'
    elif anomaly_score >= 0.3:
        return 'low'
    else:
        return 'safe'


def is_vpn_or_proxy(ip_address):
    """
    Check if IP is VPN/Proxy
    In production: integrate with VPN detection API
    """
    # Mock detection for demo
    vpn_patterns = ['185.220', '197.210']  # Common VPN IP ranges
    return any(ip_address.startswith(pattern) for pattern in vpn_patterns)


def get_expected_timezone_offset(geolocation):
    """Get expected timezone offset from geolocation"""
    timezone_map = {
        'Europe/Moscow': 3,
        'Asia/Shanghai': 8,
        'Africa/Lagos': 1,
        'America/New_York': -5,
        'America/Los_Angeles': -8
    }
    
    tz = geolocation.get('timezone', '')
    return timezone_map.get(tz, 0)