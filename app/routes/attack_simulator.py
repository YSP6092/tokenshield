"""
TokenShield Attack Simulator — Final Fixed Edition

ROOT CAUSE FIXES:
1. revoke_and_lock() no longer calls db.session.commit() internally.
   Previously it committed mid-route BEFORE IncidentLog/BehaviorLog were added,
   so those objects were never saved → dashboard went empty after every attack.
2. Every route now owns exactly ONE db.session.commit() at the very end.
   This makes each request atomic: sessions revoked + logs written together.
3. brute_force had NO final commit when score >= 0.50 (revoke_and_lock was
   the only commit, and it happened before the IncidentLog was added).
4. sql_injection, phishing, credential_stuffing, mitm, privilege_escalation
   all had the same missing-final-commit problem.
"""

from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models import User, Session, BehaviorLog, IncidentLog
from datetime import datetime
import jwt, os, json, random, string

attack_bp = Blueprint('attack', __name__, url_prefix='/api/attack')

HACKER_PROFILES = {
    'moscow': {
        'ip': '185.220.101.42', 'city': 'Moscow', 'country': 'Russia',
        'country_code': 'RU', 'flag': '🇷🇺', 'timezone': 'MSK (UTC+3)',
        'isp': 'Tor Exit Node', 'vpn': True, 'threat_tags': ['TOR', 'VPN', 'HIGH-RISK'],
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/96.0.4664.45',
        'device': 'Windows 10 PC', 'browser': 'Chrome 96', 'local_time': '03:47 AM',
    },
    'beijing': {
        'ip': '202.112.51.89', 'city': 'Beijing', 'country': 'China',
        'country_code': 'CN', 'flag': '🇨🇳', 'timezone': 'CST (UTC+8)',
        'isp': 'China Telecom', 'vpn': False, 'threat_tags': ['HIGH-RISK', 'FOREIGN'],
        'user_agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) Gecko/20100101 Firefox/91.0',
        'device': 'Windows 7 PC', 'browser': 'Firefox 91', 'local_time': '02:15 AM',
    },
    'lagos': {
        'ip': '197.210.55.23', 'city': 'Lagos', 'country': 'Nigeria',
        'country_code': 'NG', 'flag': '🇳🇬', 'timezone': 'WAT (UTC+1)',
        'isp': 'MTN Nigeria', 'vpn': True, 'threat_tags': ['VPN', 'FRAUD-REGION'],
        'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36',
        'device': 'Macbook (Spoofed)', 'browser': 'Safari', 'local_time': '04:32 AM',
    },
    'bucharest': {
        'ip': '89.45.67.123', 'city': 'Bucharest', 'country': 'Romania',
        'country_code': 'RO', 'flag': '🇷🇴', 'timezone': 'EET (UTC+2)',
        'isp': 'Anonymous Proxy', 'vpn': True, 'threat_tags': ['PROXY', 'ANONYMOUS'],
        'user_agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/90.0',
        'device': 'Linux Machine', 'browser': 'Chrome 90', 'local_time': '05:11 AM',
    },
    'unknown': {
        'ip': '45.153.160.2', 'city': 'Unknown', 'country': 'Unknown',
        'country_code': '??', 'flag': '🏴\u200d☠️', 'timezone': 'Unknown',
        'isp': 'Dark Web Relay', 'vpn': True, 'threat_tags': ['DARK-WEB', 'ANONYMOUS', 'CRITICAL'],
        'user_agent': 'python-requests/2.26.0',
        'device': 'Automated Bot', 'browser': 'Script', 'local_time': '??:?? AM',
    },
}

ATTACK_TYPES = {
    'token_theft':          {'label': 'Token / Session Hijacking',  'severity': 'high',     'base_score': 0.70},
    'brute_force':          {'label': 'Brute Force Login',          'severity': 'medium',   'base_score': 0.55},
    'sql_injection':        {'label': 'SQL Injection Attempt',      'severity': 'critical', 'base_score': 0.90},
    'phishing':             {'label': 'Phishing / Credential Theft','severity': 'high',     'base_score': 0.75},
    'credential_stuffing':  {'label': 'Credential Stuffing',        'severity': 'high',     'base_score': 0.72},
    'man_in_middle':        {'label': 'Man-in-the-Middle Attack',   'severity': 'critical', 'base_score': 0.88},
    'xss':                  {'label': 'Cross-Site Scripting (XSS)', 'severity': 'medium',   'base_score': 0.60},
    'privilege_escalation': {'label': 'Privilege Escalation',       'severity': 'critical', 'base_score': 0.92},
}


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def _ref_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))


def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow().timestamp() + 86400,
        'iat': datetime.utcnow().timestamp(),
        'jti': _ref_id()
    }
    secret = os.getenv('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
    return jwt.encode(payload, secret, algorithm='HS256')


def decode_bearer(auth_header):
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, None
    token = auth_header.split(' ')[1]
    try:
        secret = os.getenv('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
        payload = jwt.decode(token, secret, algorithms=['HS256'])
        return token, payload['user_id']
    except Exception:
        return None, None


def calc_score(attacker_ip, attacker_ua, victim_ip, victim_ua, amount=0, attack_type='token_theft'):
    score = 0.0
    factors = {}
    profile = next((p for p in HACKER_PROFILES.values() if p['ip'] == attacker_ip), None)

    factors['ip_mismatch'] = attacker_ip != victim_ip
    if factors['ip_mismatch']: score += 0.30

    factors['ua_mismatch'] = attacker_ua != victim_ua
    if factors['ua_mismatch']: score += 0.25

    factors['large_amount'] = amount >= 500
    if factors['large_amount']: score += 0.15

    factors['vpn_detected'] = bool(profile and profile.get('vpn'))
    if factors['vpn_detected']: score += 0.10

    factors['high_risk_country'] = bool(
        profile and profile.get('country') in ['Russia', 'China', 'Nigeria', 'Romania']
    )
    if factors['high_risk_country']: score += 0.10

    factors['rapid_requests'] = False

    base = ATTACK_TYPES.get(attack_type, {}).get('base_score', 0.5)
    score = max(score, base * 0.8)
    return round(min(score, 1.0), 2), factors


def threat_level(score):
    if score >= 0.85: return 'critical'
    if score >= 0.70: return 'high'
    if score >= 0.50: return 'medium'
    if score >= 0.30: return 'low'
    return 'safe'


def build_details(profile, attack_type, amount=0, extra=None):
    type_info = ATTACK_TYPES.get(attack_type, {})
    d = {
        'attack_type': type_info.get('label', attack_type),
        'attack_category': attack_type,
        'origin': f"{profile['city']}, {profile['country']}",
        'city': profile['city'],
        'country': profile['country'],
        'country_code': profile['country_code'],
        'flag': profile['flag'],
        'ip_address': profile['ip'],
        'isp': profile['isp'],
        'vpn_detected': profile['vpn'],
        'threat_tags': profile['threat_tags'],
        'timezone': profile['timezone'],
        'local_time': profile['local_time'],
        'device': profile['device'],
        'browser': profile['browser'],
        'financial_impact': f'${amount:,.2f} attempted — $0.00 lost',
        'response_time': '<2 seconds',
        'actions_taken': [
            'Transaction blocked', 'All sessions revoked',
            'User auto-logged out', '2FA lockout activated', 'Incident logged'
        ],
    }
    if extra:
        d.update(extra)
    return json.dumps(d)


def revoke_and_lock(user_id, reason='Security incident'):
    """
    Mark all active sessions as revoked and set requires_2fa.

    IMPORTANT: Does NOT call db.session.commit().
    The calling route is responsible for the final commit so that
    session revocations + incident/behavior logs are all saved atomically
    in one transaction. This is what prevents dashboard data loss.
    """
    revoked = []
    now = datetime.utcnow()
    for s in Session.query.filter_by(user_id=user_id, is_active=True).all():
        s.is_active = False
        s.revoked_at = now
        s.revoked_reason = reason
        revoked.append(s.id)

    u = User.query.get(user_id)
    if u: 
         u.failed_login_attempts = 99 
    if hasattr(u, 'requires_2fa'):
        u.requires_2fa = True

    # NO db.session.commit() here — caller owns the commit
    return revoked


def make_attacker_session(user_id, profile):
    token = generate_token(user_id)
    sess = Session(
        user_id=user_id, token=token,
        ip_address=profile['ip'], user_agent=profile['user_agent'],
        is_active=True, is_suspicious=True, anomaly_score=0.0
    )
    db.session.add(sess)
    db.session.flush()
    return sess, token


def ensure_victim_session(user_id):
    """Return existing active non-suspicious session, or create a simulated one."""
    victim = Session.query.filter_by(
        user_id=user_id, is_active=True, is_suspicious=False
    ).first()
    if victim:
        return victim
    victim_token = generate_token(user_id)
    victim = Session(
        user_id=user_id, token=victim_token,
        ip_address='127.0.0.1',
        user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        is_active=True, is_suspicious=False, anomaly_score=0.0
    )
    db.session.add(victim)
    db.session.flush()
    return victim


def hacker_dict(profile):
    return {
        'ip': profile['ip'],
        'location': f"{profile['city']}, {profile['country']}",
        'city': profile['city'],
        'country': profile['country'],
        'flag': profile['flag'],
        'device': profile['device'],
        'browser': profile['browser'],
        'isp': profile['isp'],
        'local_time': profile['local_time'],
        'timezone': profile['timezone'],
        'threat_tags': profile['threat_tags'],
        'vpn': profile['vpn'],
    }


# ─── STEAL TOKEN ─────────────────────────────────────────────────────────────

@attack_bp.route('/steal-token', methods=['POST'])
def steal_token():
    data         = request.get_json() or {}
    username     = data.get('username', 'demo')
    location_key = data.get('location', 'moscow')
    profile      = HACKER_PROFILES.get(location_key, HACKER_PROFILES['moscow'])

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': f'User "{username}" not found. Run Step 0a first.'}), 404

    victim = ensure_victim_session(user.id)
    sess, token = make_attacker_session(user.id, profile)
    db.session.commit()  # single commit

    return jsonify({
        'success': True,
        'message': 'Token stolen successfully',
        'stolen_token': token,
        'victim_session_id': victim.id,
        'attacker_session_id': sess.id,
        'hacker': hacker_dict(profile),
    }), 200


# ─── FRAUDULENT TRANSFER ─────────────────────────────────────────────────────

@attack_bp.route('/fraudulent-transfer', methods=['POST'])
def fraudulent_transfer():
    data         = request.get_json() or {}
    amount       = data.get('amount', 5000)
    dest         = data.get('destination', 'offshore-account-XX')
    location_key = data.get('location', 'moscow')
    profile      = HACKER_PROFILES.get(location_key, HACKER_PROFILES['moscow'])

    token, user_id = decode_bearer(request.headers.get('Authorization', ''))
    if not token:
        return jsonify({'error': 'Missing or invalid Bearer token'}), 401

    attacker_sess = Session.query.filter_by(token=token, is_active=True).first()
    if not attacker_sess:
        return jsonify({'error': 'Attacker session not found. Run steal-token first.'}), 404

    victim = Session.query.filter(
        Session.user_id == user_id,
        Session.is_active == True,
        Session.id != attacker_sess.id
    ).first()

    score, factors = calc_score(
        attacker_sess.ip_address, attacker_sess.user_agent,
        victim.ip_address if victim else '127.0.0.1',
        victim.user_agent if victim else '',
        amount, 'token_theft'
    )
    attacker_sess.anomaly_score = score
    attacker_sess.is_suspicious = True
    level   = threat_level(score)
    blocked = score >= 0.50
    revoked = []

    if blocked:
        revoked = revoke_and_lock(user_id, 'Security incident — stolen token detected')
        db.session.add(IncidentLog(
            session_id=attacker_sess.id, incident_type='fraudulent_transfer',
            severity=level, anomaly_score=score,
            action_taken='transfer_blocked_sessions_revoked_2fa_required',
            details=build_details(profile, 'token_theft', amount),
            ip_address=profile['ip'], user_agent=attacker_sess.user_agent
        ))

    db.session.add(BehaviorLog(
        session_id=attacker_sess.id, action_type='fraudulent_transfer_attempt',
        ip_address=attacker_sess.ip_address, user_agent=attacker_sess.user_agent,
        endpoint='/api/attack/fraudulent-transfer', request_method='POST'
    ))
    db.session.commit()  # single commit — saves revocations + logs together

    return jsonify({
        'tokenshield': {
            'anomaly_score': score, 'threat_level': level,
            'transfer_blocked': blocked, 'sessions_revoked': revoked, 'factors': factors
        },
        'hacker': hacker_dict(profile),
        'transfer': {
            'success': not blocked, 'blocked': blocked,
            'amount': amount, 'destination': dest,
            'reason': f'Blocked: {int(score * 100)}% exceeds threshold' if blocked else 'Allowed'
        }
    }), 200


# ─── BRUTE FORCE ─────────────────────────────────────────────────────────────

@attack_bp.route('/brute-force', methods=['POST'])
def brute_force():
    data         = request.get_json() or {}
    username     = data.get('username', 'demo')
    attempts     = int(data.get('attempts', 15))
    location_key = data.get('location', 'moscow')
    profile      = HACKER_PROFILES.get(location_key, HACKER_PROFILES['moscow'])

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': f'User "{username}" not found'}), 404

    score = round(min(0.30 + attempts * 0.03, 0.95), 2)
    level = threat_level(score)
    sess, _ = make_attacker_session(user.id, profile)
    sess.anomaly_score = score

    for _ in range(min(attempts, 5)):
        db.session.add(BehaviorLog(
            session_id=sess.id, action_type='brute_force_login_attempt',
            ip_address=profile['ip'], user_agent=profile['user_agent'],
            endpoint='/api/auth/login', request_method='POST'
        ))

    db.session.add(IncidentLog(
        session_id=sess.id, incident_type='brute_force_attack',
        severity=level, anomaly_score=score,
        action_taken='account_locked_ip_flagged',
        details=build_details(profile, 'brute_force', extra={
            'attempts': attempts, 'attack_tool': 'Hydra',
            'rate': f'{attempts} attempts in 30 seconds'
        }),
        ip_address=profile['ip'], user_agent=profile['user_agent']
    ))

    if score >= 0.50:
        revoke_and_lock(user.id, 'Security incident — brute force detected')

    db.session.commit()  # single commit always — was missing when score >= 0.50

    return jsonify({
        'success': True, 'attack_type': 'Brute Force Login',
        'anomaly_score': score, 'threat_level': level,
        'attempts': attempts, 'account_locked': score >= 0.50,
        'hacker': hacker_dict(profile),
    }), 200


# ─── SQL INJECTION ────────────────────────────────────────────────────────────

@attack_bp.route('/sql-injection', methods=['POST'])
def sql_injection():
    data         = request.get_json() or {}
    username     = data.get('username', 'demo')
    payload      = data.get('payload', "' OR '1'='1'; DROP TABLE users; --")
    location_key = data.get('location', 'unknown')
    profile      = HACKER_PROFILES.get(location_key, HACKER_PROFILES['unknown'])

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': f'User "{username}" not found'}), 404

    score = 0.90
    sess, _ = make_attacker_session(user.id, profile)
    sess.anomaly_score = score

    db.session.add(BehaviorLog(
        session_id=sess.id, action_type='sql_injection_attempt',
        ip_address=profile['ip'], user_agent=profile['user_agent'],
        endpoint='/api/auth/login', request_method='POST'
    ))
    db.session.add(IncidentLog(
        session_id=sess.id, incident_type='sql_injection',
        severity='critical', anomaly_score=score,
        action_taken='request_blocked_waf_triggered',
        details=build_details(profile, 'sql_injection', extra={
            'payload': payload, 'waf_triggered': True,
            'patterns': ["OR '1'='1'", 'DROP TABLE', '--', 'UNION SELECT'],
        }),
        ip_address=profile['ip'], user_agent=profile['user_agent']
    ))
    revoke_and_lock(user.id, 'Security incident — SQL injection detected')
    db.session.commit()  # single commit

    return jsonify({
        'success': True, 'attack_type': 'SQL Injection',
        'blocked': True, 'anomaly_score': score, 'threat_level': 'critical',
        'payload_detected': payload, 'waf_triggered': True,
        'hacker': hacker_dict(profile),
    }), 200


# ─── PHISHING ────────────────────────────────────────────────────────────────

@attack_bp.route('/phishing', methods=['POST'])
def phishing():
    data         = request.get_json() or {}
    username     = data.get('username', 'demo')
    location_key = data.get('location', 'beijing')
    profile      = HACKER_PROFILES.get(location_key, HACKER_PROFILES['beijing'])

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': f'User "{username}" not found'}), 404

    score = 0.75
    sess, _ = make_attacker_session(user.id, profile)
    sess.anomaly_score = score

    db.session.add(BehaviorLog(
        session_id=sess.id, action_type='phishing_credential_theft',
        ip_address=profile['ip'], user_agent=profile['user_agent'],
        endpoint='/api/auth/login', request_method='POST'
    ))
    db.session.add(IncidentLog(
        session_id=sess.id, incident_type='phishing_attack',
        severity='high', anomaly_score=score,
        action_taken='credentials_invalidated_sessions_revoked',
        details=build_details(profile, 'phishing', extra={
            'phishing_domain': 'secure-neovault-login.com',
            'lure': 'Your account requires immediate verification',
            'credential_source': 'Fake login page redirect',
        }),
        ip_address=profile['ip'], user_agent=profile['user_agent']
    ))
    revoke_and_lock(user.id, 'Security incident — phishing credentials used')
    db.session.commit()  # single commit

    return jsonify({
        'success': True, 'attack_type': 'Phishing / Credential Theft',
        'anomaly_score': score, 'threat_level': 'high',
        'phishing_domain': 'secure-neovault-login.com',
        'hacker': hacker_dict(profile),
    }), 200


# ─── CREDENTIAL STUFFING ─────────────────────────────────────────────────────

@attack_bp.route('/credential-stuffing', methods=['POST'])
def credential_stuffing():
    data         = request.get_json() or {}
    username     = data.get('username', 'demo')
    combos       = int(data.get('combos', 500))
    location_key = data.get('location', 'bucharest')
    profile      = HACKER_PROFILES.get(location_key, HACKER_PROFILES['bucharest'])

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': f'User "{username}" not found'}), 404

    score = 0.72
    sess, _ = make_attacker_session(user.id, profile)
    sess.anomaly_score = score

    db.session.add(IncidentLog(
        session_id=sess.id, incident_type='credential_stuffing',
        severity='high', anomaly_score=score,
        action_taken='account_locked_rate_limit_enforced',
        details=build_details(profile, 'credential_stuffing', extra={
            'combo_list_size': combos, 'source': 'Dark web breach dump (2023)',
            'tool': 'OpenBullet 2',
        }),
        ip_address=profile['ip'], user_agent=profile['user_agent']
    ))
    revoke_and_lock(user.id, 'Security incident — credential stuffing detected')
    db.session.commit()  # single commit

    return jsonify({
        'success': True, 'attack_type': 'Credential Stuffing',
        'anomaly_score': score, 'threat_level': 'high',
        'combos_tried': combos, 'hacker': hacker_dict(profile),
    }), 200


# ─── MAN IN THE MIDDLE ───────────────────────────────────────────────────────

@attack_bp.route('/mitm', methods=['POST'])
def mitm():
    data         = request.get_json() or {}
    username     = data.get('username', 'demo')
    location_key = data.get('location', 'moscow')
    profile      = HACKER_PROFILES.get(location_key, HACKER_PROFILES['moscow'])

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': f'User "{username}" not found'}), 404

    score = 0.88
    sess, _ = make_attacker_session(user.id, profile)
    sess.anomaly_score = score

    db.session.add(IncidentLog(
        session_id=sess.id, incident_type='man_in_the_middle',
        severity='critical', anomaly_score=score,
        action_taken='ssl_pinning_enforced_session_terminated',
        details=build_details(profile, 'man_in_middle', extra={
            'ssl_stripped': True, 'tool': 'Ettercap / MITMf',
            'intercepted_data': 'Login credentials + session token',
        }),
        ip_address=profile['ip'], user_agent=profile['user_agent']
    ))
    revoke_and_lock(user.id, 'Security incident — MITM attack detected')
    db.session.commit()  # single commit

    return jsonify({
        'success': True, 'attack_type': 'Man-in-the-Middle',
        'anomaly_score': score, 'threat_level': 'critical',
        'ssl_stripped': True, 'hacker': hacker_dict(profile),
    }), 200


# ─── XSS ─────────────────────────────────────────────────────────────────────

@attack_bp.route('/xss', methods=['POST'])
def xss_attack():
    data         = request.get_json() or {}
    username     = data.get('username', 'demo')
    payload      = data.get('payload', '<script>document.cookie</script>')
    location_key = data.get('location', 'beijing')
    profile      = HACKER_PROFILES.get(location_key, HACKER_PROFILES['beijing'])

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': f'User "{username}" not found'}), 404

    score = 0.60
    sess, _ = make_attacker_session(user.id, profile)
    sess.anomaly_score = score

    db.session.add(IncidentLog(
        session_id=sess.id, incident_type='xss_attack',
        severity='medium', anomaly_score=score,
        action_taken='input_sanitized_csp_enforced',
        details=build_details(profile, 'xss', extra={
            'payload': payload, 'csp_blocked': True, 'cookie_theft_attempted': True,
        }),
        ip_address=profile['ip'], user_agent=profile['user_agent']
    ))
    db.session.commit()  # single commit

    return jsonify({
        'success': True, 'attack_type': 'XSS',
        'anomaly_score': score, 'threat_level': 'medium',
        'payload': payload, 'blocked': True,
        'hacker': hacker_dict(profile),
    }), 200


# ─── PRIVILEGE ESCALATION ────────────────────────────────────────────────────

@attack_bp.route('/privilege-escalation', methods=['POST'])
def privilege_escalation():
    data         = request.get_json() or {}
    username     = data.get('username', 'demo')
    location_key = data.get('location', 'unknown')
    profile      = HACKER_PROFILES.get(location_key, HACKER_PROFILES['unknown'])

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': f'User "{username}" not found'}), 404

    score = 0.92
    sess, _ = make_attacker_session(user.id, profile)
    sess.anomaly_score = score

    db.session.add(IncidentLog(
        session_id=sess.id, incident_type='privilege_escalation',
        severity='critical', anomaly_score=score,
        action_taken='access_denied_account_frozen',
        details=build_details(profile, 'privilege_escalation', extra={
            'attempted_role': 'admin', 'method': 'JWT token manipulation',
            'forged_claim': 'is_admin: true',
        }),
        ip_address=profile['ip'], user_agent=profile['user_agent']
    ))
    revoke_and_lock(user.id, 'Security incident — privilege escalation attempt')
    db.session.commit()  # single commit

    return jsonify({
        'success': True, 'attack_type': 'Privilege Escalation',
        'anomaly_score': score, 'threat_level': 'critical',
        'attempted_role': 'admin', 'blocked': True,
        'hacker': hacker_dict(profile),
    }), 200


# ─── THREAT STATUS ───────────────────────────────────────────────────────────

@attack_bp.route('/threat-status/<int:session_id>', methods=['GET'])
def threat_status(session_id):
    sess = Session.query.get(session_id)
    if not sess:
        return jsonify({'error': 'Session not found'}), 404
    return jsonify({'session': {
        'id': sess.id, 'is_active': sess.is_active,
        'anomaly_score': sess.anomaly_score, 'is_suspicious': sess.is_suspicious,
        'ip_address': sess.ip_address, 'revoked_reason': sess.revoked_reason,
        'revoked_at': sess.revoked_at.isoformat() if sess.revoked_at else None,
    }}), 200


# ─── INJECT SCORE ────────────────────────────────────────────────────────────

@attack_bp.route('/inject-score', methods=['POST'])
def inject_score():
    data       = request.get_json() or {}
    session_id = data.get('session_id')
    score      = float(data.get('score', 0.5))
    sess = (Session.query.get(session_id) if session_id else
            Session.query.filter_by(is_suspicious=True).order_by(Session.id.desc()).first())
    if not sess:
        return jsonify({'error': 'No session found'}), 404
    sess.anomaly_score = score
    sess.is_suspicious = score >= 0.30
    db.session.commit()
    return jsonify({
        'success': True, 'session_id': sess.id,
        'injected_score': score, 'threat_level': threat_level(score)
    }), 200

@attack_bp.route('/make-admin', methods=['POST'])
def make_admin():
    data = request.get_json() or {}
    username = data.get('username', 'demo')
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': f'User "{username}" not found'}), 404
    user.is_admin = True
    db.session.commit()
    return jsonify({'success': True, 'message': f'{username} is now admin'})
# ─── ATTACK TYPES LIST ───────────────────────────────────────────────────────

@attack_bp.route('/types', methods=['GET'])
def list_types():
    return jsonify({
        'attack_types': ATTACK_TYPES,
        'locations': {k: {'city': v['city'], 'country': v['country'],
                          'flag': v['flag'], 'ip': v['ip']}
                      for k, v in HACKER_PROFILES.items()}
    }), 200


# ─── RESET VICTIM ────────────────────────────────────────────────────────────

@attack_bp.route('/reset-victim', methods=['POST'])
def reset_victim():
    data     = request.get_json() or {}
    username = data.get('username', 'demo')
    user     = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': f'User "{username}" not found'}), 404

    user.failed_login_attempts = 0          # ← clears the 2FA gate
    if hasattr(user, 'requires_2fa'):
        user.requires_2fa = False

    now = datetime.utcnow()
    for s in Session.query.filter_by(user_id=user.id).all():
        s.is_active      = False
        s.revoked_at     = now
        s.revoked_reason = 'Victim reset for simulation'

    db.session.commit()
    return jsonify({
        'success': True,
        'message': f'{username} fully reset — login unlocked, 2FA cleared, sessions wiped.'
    }), 200


# ─── RESET ENGINE ────────────────────────────────────────────────────────────

@attack_bp.route('/reset-engine', methods=['POST'])
def reset_engine():
    """
    Full system reset: clears all incidents, behavior logs, deactivates all
    sessions, and resets all users to clean state.
    Uses per-row updates to avoid SQLAlchemy bulk-update column mapping errors.
    """
    try:
        now = datetime.utcnow()

        IncidentLog.query.delete(synchronize_session=False)
        BehaviorLog.query.delete(synchronize_session=False)

        for s in Session.query.all():
            s.is_active      = False
            s.is_suspicious  = False
            s.anomaly_score  = 0.0
            s.revoked_reason = 'Engine reset'
            s.revoked_at     = now

        users = User.query.all()
        for u in users:
            u.failed_login_attempts = 0
            if hasattr(u, 'requires_2fa'):
                u.requires_2fa = False

        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Engine fully reset. All incidents cleared, all sessions wiped, all users unlocked.',
            'users_reset': len(users),
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Reset failed: {str(e)}'}), 500


# ─── FULL SCENARIO ───────────────────────────────────────────────────────────

@attack_bp.route('/full-scenario', methods=['POST'])
def full_scenario():
    data         = request.get_json() or {}
    username     = data.get('username', 'demo')
    location_key = data.get('location', 'moscow')
    attack_type  = data.get('attack_type', 'token_theft')
    amount       = data.get('amount', 5000)
    profile      = HACKER_PROFILES.get(location_key, HACKER_PROFILES['moscow'])

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': f'User "{username}" not found. Run Step 0a first.'}), 404

    victim = ensure_victim_session(user.id)
    sess, stolen_token = make_attacker_session(user.id, profile)
    score, factors = calc_score(
        profile['ip'], profile['user_agent'],
        victim.ip_address, victim.user_agent, amount, attack_type
    )
    sess.anomaly_score = score
    level   = threat_level(score)
    revoked = revoke_and_lock(user.id, f'Security incident — {attack_type} detected')

    db.session.add(IncidentLog(
        session_id=sess.id, incident_type=attack_type,
        severity=level, anomaly_score=score,
        action_taken='full_scenario_sessions_revoked_2fa_required',
        details=build_details(profile, attack_type, amount),
        ip_address=profile['ip'], user_agent=profile['user_agent']
    ))
    db.session.add(BehaviorLog(
        session_id=sess.id, action_type=f'full_scenario_{attack_type}',
        ip_address=profile['ip'], user_agent=profile['user_agent'],
        endpoint='/api/attack/full-scenario', request_method='POST'
    ))
    db.session.commit()  # single commit

    type_info = ATTACK_TYPES.get(attack_type, {})
    return jsonify({
        'success': True,
        'summary': (
            f"Full {type_info.get('label', attack_type)} — "
            f"Score: {int(score * 100)}% ({level.upper()}) — "
            f"{len(revoked)} sessions revoked"
        ),
        'attack': {
            'type': attack_type, 'label': type_info.get('label', attack_type),
            'anomaly_score': score, 'threat_level': level,
            'transfer_blocked': True, 'sessions_revoked': revoked, 'factors': factors,
        },
        'hacker': hacker_dict(profile),
        'victim': {
            'username': username, 'requires_2fa': True,
            'message': 'Account locked. Enter any 6-digit code to restore access.'
        }
    }), 200