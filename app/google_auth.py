"""
TokenShield — Google OAuth Routes
Handles Google Sign-In via OAuth 2.0 authorization code flow.

When GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are not set the endpoints
return a clear JSON error ("not configured") instead of crashing or
showing a confusing "not configured on this server" HTML page.
"""

import os
import requests
from flask import Blueprint, request, jsonify, redirect, current_app
from app.extensions import db
from app.models import User, Session
from datetime import datetime
import jwt
import secrets

google_bp = Blueprint('google_auth', __name__, url_prefix='/api/auth/google')

GOOGLE_TOKEN_URL    = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo'


def _google_configured():
    """Return True only when both OAuth env vars are non-empty and non-placeholder."""
    cid    = os.getenv('GOOGLE_CLIENT_ID', '').strip()
    secret = os.getenv('GOOGLE_CLIENT_SECRET', '').strip()
    placeholders = {'', 'your-google-client-id', 'your-google-client-secret', 'CHANGE_ME'}
    return cid not in placeholders and secret not in placeholders


def _generate_jwt(user_id: int) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow().timestamp() + 86400,
        'iat': datetime.utcnow().timestamp(),
        'jti': secrets.token_urlsafe(16),
    }
    return jwt.encode(
        payload,
        os.getenv('JWT_SECRET_KEY', 'jwt-secret-change-in-production'),
        algorithm='HS256'
    )


def _not_configured_response():
    """
    Returns a JSON 503 response that the frontend can catch and display
    a friendly "Google login is not set up yet" message instead of
    crashing or showing "not configured on this server".
    """
    return jsonify({
        'success': False,
        'error': 'google_not_configured',
        'message': (
            'Google OAuth is not configured on this server. '
            'Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables '
            'and restart the server to enable Google Sign-In.'
        )
    }), 503


# ── GET /api/auth/google/status ───────────────────────────────────────────────
@google_bp.route('/status', methods=['GET'])
def status():
    """
    Frontend polls this at startup to decide whether to show the
    "Sign in with Google" button.
    """
    return jsonify({'configured': _google_configured()}), 200


# ── POST /api/auth/google/callback ───────────────────────────────────────────
@google_bp.route('/callback', methods=['POST'])
def callback():
    """
    Receive the authorization code from the frontend, exchange it for
    tokens, fetch the user profile, and return a JWT.
    """
    if not _google_configured():
        return _not_configured_response()

    data = request.get_json() or {}
    code         = data.get('code')
    redirect_uri = data.get('redirect_uri')

    if not code or not redirect_uri:
        return jsonify({'success': False, 'error': 'Missing code or redirect_uri'}), 400

    # 1. Exchange authorization code for tokens
    try:
        token_resp = requests.post(GOOGLE_TOKEN_URL, json={
            'code':          code,
            'client_id':     os.getenv('GOOGLE_CLIENT_ID'),
            'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
            'redirect_uri':  redirect_uri,
            'grant_type':    'authorization_code',
        }, timeout=10)
        token_resp.raise_for_status()
        token_data = token_resp.json()
    except requests.RequestException as e:
        return jsonify({'success': False, 'error': f'Token exchange failed: {str(e)}'}), 502

    access_token = token_data.get('access_token')
    if not access_token:
        return jsonify({'success': False, 'error': 'No access_token in Google response'}), 502

    # 2. Fetch user profile
    try:
        profile_resp = requests.get(
            GOOGLE_USERINFO_URL,
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        profile_resp.raise_for_status()
        profile = profile_resp.json()
    except requests.RequestException as e:
        return jsonify({'success': False, 'error': f'Profile fetch failed: {str(e)}'}), 502

    google_id  = profile.get('sub')
    email      = profile.get('email', '')
    name       = profile.get('name', email.split('@')[0])
    avatar_url = profile.get('picture', '')

    if not google_id or not email:
        return jsonify({'success': False, 'error': 'Incomplete profile from Google'}), 502

    # 3. Find or create user
    user = User.query.filter_by(google_id=google_id).first()
    if not user:
        # Check if email already exists (local account)
        user = User.query.filter_by(email=email).first()
        if user:
            # Link Google ID to existing local account
            user.google_id     = google_id
            user.avatar_url    = avatar_url
            user.auth_provider = 'google'
        else:
            # Brand new user via Google
            user = User(
                username=name.replace(' ', '_').lower()[:30],
                email=email,
                google_id=google_id,
                avatar_url=avatar_url,
                auth_provider='google',
                # Set a random unusable password for Google-only accounts
                password_hash=secrets.token_hex(32),
            )
            db.session.add(user)

    db.session.flush()

    # 4. Create a session
    jwt_token = _generate_jwt(user.id)
    sess = Session(
        user_id=user.id,
        token=jwt_token,
        ip_address=request.remote_addr or '0.0.0.0',
        user_agent=request.headers.get('User-Agent', '')[:512],
        is_active=True,
        is_suspicious=False,
        anomaly_score=0.0,
    )
    db.session.add(sess)
    db.session.commit()

    return jsonify({
        'success': True,
        'token': jwt_token,
        'user': {
            'id':         user.id,
            'username':   user.username,
            'email':      user.email,
            'avatar_url': user.avatar_url,
            'is_admin':   getattr(user, 'is_admin', False),
        }
    }), 200


# ── GET /api/auth/google/login  (redirect-based flow, optional) ──────────────
@google_bp.route('/login', methods=['GET'])
def login():
    """
    Redirect to Google's OAuth consent page.
    Only used when doing a server-side redirect flow (not the JS popup flow).
    """
    if not _google_configured():
        return redirect('/?error=google_not_configured')

    import urllib.parse
    redirect_uri = request.args.get(
        'redirect_uri',
        request.host_url.rstrip('/') + '/api/auth/google/callback-redirect'
    )
    params = urllib.parse.urlencode({
        'client_id':     os.getenv('GOOGLE_CLIENT_ID'),
        'redirect_uri':  redirect_uri,
        'response_type': 'code',
        'scope':         'openid email profile',
        'access_type':   'online',
        'prompt':        'select_account',
    })
    return redirect(f'https://accounts.google.com/o/oauth2/v2/auth?{params}')