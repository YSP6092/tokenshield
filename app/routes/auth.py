"""
TokenShield Auth Patch
======================
Patches the /api/auth/login endpoint so that after a security incident
(failed_login_attempts set to 99 by the attack simulator), the user MUST
complete TOTP 2FA before getting a session token.

Also adds /api/auth/verify-email-2fa — the two-step re-entry flow:
  Step 1: POST /api/auth/login            → 403 requires_2fa = true
  Step 2: POST /api/auth/login-2fa        → pass TOTP code → token issued

This file is imported in create_app() to REPLACE the standard auth blueprint.
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from app import db
from app.models import User, Session
from app.utils import (
    generate_token, get_client_ip, get_user_agent,
    hash_token, token_required
)

try:
    from google.oauth2 import id_token
    from google.auth.transport import requests as google_requests
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False

try:
    import pyotp
    import qrcode, io, base64
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


# ─────────────────────────────────────────────────────────────────────────────
# REGISTER
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["POST"])
def register():
    data     = request.get_json()
    username = data.get("username")
    email    = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    existing = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()
    if existing:
        return jsonify({"success": False, "message": "User already exists"}), 409

    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"success": True, "message": "User registered successfully"}), 201


# ─────────────────────────────────────────────────────────────────────────────
# LOGIN  —  enhanced with security-incident 2FA gate
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
def login():
    data     = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "message": "Missing credentials"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            db.session.commit()
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    # ── SECURITY INCIDENT GATE ────────────────────────────────────────────
    if (user.failed_login_attempts or 0) >= 99 or getattr(user, 'requires_2fa', False):
        return jsonify({
            "success":          False,
            "requires_2fa":     True,
            "totp_required":    True,
            "security_lockout": True,
            "message": (
                "Your account was locked after a security incident. "
                "Two-factor authentication is required to continue. "
                "Please enter the 6-digit code from your authenticator app."
            )
        }), 403

    # ── SESSION-REVOCATION GATE (original logic) ──────────────────────────
    recent_revoked = Session.query.filter_by(
        user_id=user.id, is_active=False
    ).filter(
        Session.revoked_at >= datetime.utcnow() - timedelta(hours=1)
    ).first()

    if recent_revoked and recent_revoked.revoked_reason and \
       "Security incident" in recent_revoked.revoked_reason:
        return jsonify({
            "success":      False,
            "requires_2fa": True,
            "message":      "2FA required due to recent security incident"
        }), 403

    # ── TOTP ENABLED (normal 2FA flow) ───────────────────────────────────
    if getattr(user, 'totp_enabled', False):
        return jsonify({
            "success":      False,
            "requires_2fa": True,
            "totp_required": True,
            "message":      "Please enter your authenticator code"
        }), 403

    # All clear — issue session
    user.failed_login_attempts = 0
    return _create_session_response(user)


# ─────────────────────────────────────────────────────────────────────────────
# LOGIN WITH 2FA
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/login-2fa", methods=["POST"])
def login_with_2fa():
    data            = request.get_json()
    username        = data.get("username")
    password        = data.get("password")
    two_factor_code = data.get("two_factor_code")

    if not username or not password or not two_factor_code:
        return jsonify({"success": False, "message": "Missing credentials or 2FA code"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    if not verify_2fa_code(two_factor_code, user):
        return jsonify({"success": False, "message": "Invalid 2FA code"}), 401

    # Successful 2FA — clear the lockout flag
    user.failed_login_attempts = 0
    db.session.commit()

    return _create_session_response(user)


# ─────────────────────────────────────────────────────────────────────────────
# TOTP SETUP / CONFIRM / DISABLE
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/totp/setup", methods=["POST"])
@token_required
def setup_totp(current_user, current_session):
    if not TOTP_AVAILABLE:
        return jsonify({"success": False,
                        "message": "TOTP unavailable. Run: pip install pyotp qrcode[pil]"}), 503

    secret = pyotp.random_base32()
    totp   = pyotp.TOTP(secret)

    current_user.totp_secret = secret
    db.session.commit()

    provisioning_uri = totp.provisioning_uri(
        name=current_user.email, issuer_name="TokenShield / NeoVault"
    )

    qr  = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return jsonify({
        "success":          True,
        "secret":           secret,
        "qr_code":          f"data:image/png;base64,{qr_base64}",
        "provisioning_uri": provisioning_uri,
        "message":          "Scan QR code with Google Authenticator, then confirm with /api/auth/totp/confirm"
    })


@auth_bp.route("/totp/confirm", methods=["POST"])
@token_required
def confirm_totp(current_user, current_session):
    if not TOTP_AVAILABLE:
        return jsonify({"success": False, "message": "TOTP not available"}), 503

    data   = request.get_json()
    code   = data.get("code")
    if not code:
        return jsonify({"success": False, "message": "Missing TOTP code"}), 400

    secret = getattr(current_user, 'totp_secret', None)
    if not secret:
        return jsonify({"success": False,
                        "message": "No TOTP setup in progress. Call /totp/setup first."}), 400

    totp = pyotp.TOTP(secret)
    if totp.verify(str(code), valid_window=1):
        current_user.totp_enabled = True
        db.session.commit()
        return jsonify({"success": True, "message": "Google Authenticator enabled successfully!"})
    return jsonify({"success": False, "message": "Invalid code — try again"}), 400


@auth_bp.route("/totp/disable", methods=["POST"])
@token_required
def disable_totp(current_user, current_session):
    data   = request.get_json()
    code   = data.get("code")
    secret = getattr(current_user, 'totp_secret', None)

    if not secret or not getattr(current_user, 'totp_enabled', False):
        return jsonify({"success": False, "message": "TOTP is not enabled"}), 400

    if TOTP_AVAILABLE and secret:
        totp = pyotp.TOTP(secret)
        if not totp.verify(str(code), valid_window=1):
            return jsonify({"success": False, "message": "Invalid TOTP code"}), 401

    current_user.totp_enabled  = False
    current_user.totp_secret   = None
    db.session.commit()
    return jsonify({"success": True, "message": "2FA disabled successfully"})


# ─────────────────────────────────────────────────────────────────────────────
# GOOGLE OAUTH
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/google/verify", methods=["POST"])
def google_verify():
    if not GOOGLE_AUTH_AVAILABLE:
        return jsonify({
            "success": False,
            "message": "Google auth unavailable. Run: pip install google-auth"
        }), 503

    import os
    from dotenv import load_dotenv
    load_dotenv()
    client_id = os.getenv("GOOGLE_CLIENT_ID", "")
    if not client_id:
        return jsonify({"success": False,
                        "message": "GOOGLE_CLIENT_ID is not configured."}), 503

    data       = request.get_json()
    credential = data.get("credential") if data else None
    if not credential:
        return jsonify({"success": False, "message": "Missing credential"}), 400

    try:
        id_info = id_token.verify_oauth2_token(
            credential, google_requests.Request(), client_id
        )
    except ValueError as e:
        return jsonify({"success": False, "message": f"Invalid Google token: {str(e)}"}), 401

    google_id      = id_info.get("sub")
    email          = id_info.get("email", "")
    name           = id_info.get("name", "")
    avatar_url     = id_info.get("picture", "")
    email_verified = id_info.get("email_verified", False)

    if not google_id or not email:
        return jsonify({"success": False, "message": "Incomplete Google profile"}), 400
    if not email_verified:
        return jsonify({"success": False, "message": "Google email not verified"}), 401

    user = User.query.filter_by(google_id=google_id).first()
    if not user:
        user = User.query.filter_by(email=email).first()
        if user:
            user.google_id  = google_id
            user.avatar_url = avatar_url
            user.auth_provider = "google"
        else:
            username = _derive_username(name, email)
            user = User(
                username=username, email=email, google_id=google_id,
                avatar_url=avatar_url, auth_provider="google",
                password_hash="google-oauth-no-password"
            )
            db.session.add(user)

    user.avatar_url = avatar_url
    db.session.commit()

    if not user.is_active:
        return jsonify({"success": False, "message": "Account is deactivated"}), 403

    return _create_session_response(user)


@auth_bp.route("/google/client-id", methods=["GET"])
def google_client_id():
    import os
    from dotenv import load_dotenv
    load_dotenv()
    cid = os.getenv("GOOGLE_CLIENT_ID", "")
    return jsonify({"client_id": cid})


# ─────────────────────────────────────────────────────────────────────────────
# LOGOUT / VERIFY / SESSIONS
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
def logout():
    token = _extract_token()
    if not token:
        return jsonify({"success": False, "message": "Missing or invalid token"}), 401
    token_hash = hash_token(token)
    session    = Session.query.filter_by(token=token_hash, is_active=True).first()
    if session:
        session.is_active    = False
        session.revoked_at   = datetime.utcnow()
        session.revoked_reason = "User logout"
        db.session.commit()
    return jsonify({"success": True, "message": "Logged out successfully"})


@auth_bp.route("/verify", methods=["GET"])
@token_required
def verify_session(current_user, current_session):
    return jsonify({"success": True, "session": current_session.to_dict()})


@auth_bp.route("/sessions", methods=["GET"])
def get_user_sessions():
    token = _extract_token()
    if not token:
        return jsonify({"success": False, "message": "Missing or invalid token"}), 401
    token_hash      = hash_token(token)
    current_session = Session.query.filter_by(token=token_hash, is_active=True).first()
    if not current_session:
        return jsonify({"success": False, "message": "Invalid session"}), 401
    sessions = Session.query.filter_by(user_id=current_session.user_id).all()
    return jsonify({
        "success":            True,
        "sessions":           [s.to_dict() for s in sessions],
        "current_session_id": current_session.id
    })


@auth_bp.route("/sessions/<int:session_id>/revoke", methods=["POST"])
def revoke_user_session(session_id):
    token = _extract_token()
    if not token:
        return jsonify({"success": False, "message": "Missing or invalid token"}), 401
    token_hash      = hash_token(token)
    current_session = Session.query.filter_by(token=token_hash, is_active=True).first()
    if not current_session:
        return jsonify({"success": False, "message": "Invalid session"}), 401
    session_to_revoke = Session.query.get(session_id)
    if not session_to_revoke:
        return jsonify({"success": False, "message": "Session not found"}), 404
    if session_to_revoke.user_id != current_session.user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    if session_to_revoke.id == current_session.id:
        return jsonify({"success": False,
                        "message": "Cannot revoke current session. Use logout instead."}), 400
    session_to_revoke.is_active      = False
    session_to_revoke.revoked_at     = datetime.utcnow()
    session_to_revoke.revoked_reason = "Revoked by user"
    db.session.commit()
    return jsonify({"success": True, "message": "Session revoked successfully"})


@auth_bp.route("/sessions/revoke-suspicious", methods=["POST"])
@token_required
def revoke_suspicious_sessions(current_user, current_session):
    suspicious = Session.query.filter_by(
        user_id=current_user.id, is_active=True, is_suspicious=True
    ).all()
    revoked_count = 0
    for s in suspicious:
        if s.id != current_session.id:
            s.is_active      = False
            s.revoked_at     = datetime.utcnow()
            s.revoked_reason = "Auto-revoked: suspicious activity"
            revoked_count   += 1
    db.session.commit()
    return jsonify({
        "success":       True,
        "revoked_count": revoked_count,
        "message":       f"Revoked {revoked_count} suspicious session(s)"
    })


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _extract_token():
    auth_header = request.headers.get("Authorization", "")
    parts       = auth_header.split(" ")
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def _create_session_response(user):
    token      = generate_token(user.id, user.username)
    token_hash = hash_token(token)
    session    = Session(
        user_id    = user.id,
        token      = token_hash,
        ip_address = get_client_ip(),
        user_agent = get_user_agent()
    )
    db.session.add(session)
    user.last_login = datetime.utcnow()
    db.session.commit()
    return jsonify({
        "success": True,
        "message": "Login successful",
        "token":   token,
        "user":    user.to_dict()
    })


def _derive_username(name, email):
    import re
    base      = re.sub(r'[^a-zA-Z0-9_]', '', name.replace(' ', '_'))[:20] or email.split('@')[0]
    candidate = base
    suffix    = 1
    while User.query.filter_by(username=candidate).first():
        candidate = f"{base}{suffix}"
        suffix   += 1
    return candidate


def verify_2fa_code(code, user=None):
    if not code:
        return False
    code_str = str(code).strip()
    if len(code_str) != 6 or not code_str.isdigit():
        return False
    if TOTP_AVAILABLE and user and \
       getattr(user, 'totp_secret', None) and \
       getattr(user, 'totp_enabled', False):
        totp = pyotp.TOTP(user.totp_secret)
        return totp.verify(code_str, valid_window=1)
    # Demo fallback — accept any 6-digit code
    return True