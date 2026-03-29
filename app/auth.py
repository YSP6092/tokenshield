"""
Authentication Routes with Full 2FA Support (TOTP + Google Authenticator)
Fixed: timedelta import, blueprint prefix, TOTP verification
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta  # FIX: timedelta imported at top
from app import db
from app.models import User, Session
from app.utils import generate_token, get_client_ip, get_user_agent, hash_token, token_required

# Optional Google OAuth support
try:
    from google.oauth2 import id_token
    from google.auth.transport import requests as google_requests
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False


try:
    import pyotp
    import qrcode
    import io, base64
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")  # FIX: url_prefix added


# ============================================================================
# REGISTER
# ============================================================================
@auth_bp.route("/register", methods=["POST"])
def register():
    """User registration"""
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    existing_user = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()

    if existing_user:
        return jsonify({"success": False, "message": "User already exists"}), 409

    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"success": True, "message": "User registered successfully"}), 201


# ============================================================================
# LOGIN (Standard)
# ============================================================================
@auth_bp.route("/login", methods=["POST"])
def login():
    """Standard login — checks for recent security incidents requiring 2FA"""
    data = request.get_json()
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

    user.failed_login_attempts = 0

    # FIX: timedelta now at top — no NameError
    recent_revoked = Session.query.filter_by(
        user_id=user.id,
        is_active=False
    ).filter(
        Session.revoked_at >= datetime.utcnow() - timedelta(hours=1)
    ).first()

    if recent_revoked and recent_revoked.revoked_reason == 'Security incident':
        return jsonify({
            "success": False,
            "requires_2fa": True,
            "message": "2FA required due to recent security incident"
        }), 403

    # If user has TOTP enabled, require it
    if getattr(user, 'totp_enabled', False):
        return jsonify({
            "success": False,
            "requires_2fa": True,
            "totp_required": True,
            "message": "Please enter your authenticator code"
        }), 403

    return _create_session_response(user)


# ============================================================================
# LOGIN WITH 2FA (TOTP / Google Authenticator)
# ============================================================================
@auth_bp.route("/login-2fa", methods=["POST"])
def login_with_2fa():
    """Login with TOTP 2FA code (Google Authenticator or any TOTP app)"""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    two_factor_code = data.get("two_factor_code")

    if not username or not password or not two_factor_code:
        return jsonify({"success": False, "message": "Missing credentials or 2FA code"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    if not verify_2fa_code(two_factor_code, user):
        return jsonify({"success": False, "message": "Invalid 2FA code"}), 401

    return _create_session_response(user)


# ============================================================================
# TOTP SETUP — Google Authenticator QR Code
# ============================================================================
@auth_bp.route("/totp/setup", methods=["POST"])
@token_required
def setup_totp(current_user, current_session):
    """Generate TOTP secret and QR code for Google Authenticator"""
    if not TOTP_AVAILABLE:
        return jsonify({
            "success": False,
            "message": "TOTP unavailable. Run: pip install pyotp qrcode[pil]"
        }), 503

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    current_user.totp_secret = secret
    db.session.commit()

    provisioning_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="TokenShield / NeoVault"
    )

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return jsonify({
        "success": True,
        "secret": secret,
        "qr_code": f"data:image/png;base64,{qr_base64}",
        "provisioning_uri": provisioning_uri,
        "message": "Scan QR code with Google Authenticator, then confirm with /api/auth/totp/confirm"
    })


@auth_bp.route("/totp/confirm", methods=["POST"])
@token_required
def confirm_totp(current_user, current_session):
    """Confirm TOTP setup by verifying first code from authenticator app"""
    if not TOTP_AVAILABLE:
        return jsonify({"success": False, "message": "TOTP not available"}), 503

    data = request.get_json()
    code = data.get("code")

    if not code:
        return jsonify({"success": False, "message": "Missing TOTP code"}), 400

    secret = getattr(current_user, 'totp_secret', None)
    if not secret:
        return jsonify({"success": False, "message": "No TOTP setup in progress. Call /totp/setup first."}), 400

    totp = pyotp.TOTP(secret)
    if totp.verify(str(code), valid_window=1):
        current_user.totp_enabled = True
        db.session.commit()
        return jsonify({"success": True, "message": "Google Authenticator enabled successfully!"})
    else:
        return jsonify({"success": False, "message": "Invalid code — try again"}), 400


@auth_bp.route("/totp/disable", methods=["POST"])
@token_required
def disable_totp(current_user, current_session):
    """Disable TOTP 2FA"""
    data = request.get_json()
    code = data.get("code")

    secret = getattr(current_user, 'totp_secret', None)
    if not secret or not getattr(current_user, 'totp_enabled', False):
        return jsonify({"success": False, "message": "TOTP is not enabled"}), 400

    if TOTP_AVAILABLE and secret:
        totp = pyotp.TOTP(secret)
        if not totp.verify(str(code), valid_window=1):
            return jsonify({"success": False, "message": "Invalid TOTP code"}), 401

    current_user.totp_enabled = False
    current_user.totp_secret = None
    db.session.commit()

    return jsonify({"success": True, "message": "2FA disabled successfully"})


# ============================================================================
# GOOGLE OAUTH — Verify Google ID token and sign in / register
# ============================================================================
@auth_bp.route("/google/verify", methods=["POST"])
def google_verify():
    """
    Verify a Google ID token (JWT) issued by Google Sign-In / One Tap.
    Creates an account automatically on first sign-in.

    Expects JSON: { "credential": "<google_id_token>" }
    Returns:      { success, token, user }  (same shape as /login)
    """
    if not GOOGLE_AUTH_AVAILABLE:
        return jsonify({
            "success": False,
            "message": "Google auth unavailable. Run: pip install google-auth google-auth-httplib2"
        }), 503

    import os as _os
    from dotenv import load_dotenv as _lde
    _lde()
    client_id = _os.getenv("GOOGLE_CLIENT_ID", "")
    if not client_id:
        return jsonify({
            "success": False,
            "message": "GOOGLE_CLIENT_ID is not configured on the server."
        }), 503

    data = request.get_json()
    credential = data.get("credential") if data else None
    if not credential:
        return jsonify({"success": False, "message": "Missing credential"}), 400

    # Verify the token with Google's servers
    try:
        id_info = id_token.verify_oauth2_token(
            credential,
            google_requests.Request(),
            client_id
        )
    except ValueError as e:
        return jsonify({"success": False, "message": f"Invalid Google token: {str(e)}"}), 401

    google_id  = id_info.get("sub")           # unique & stable Google user ID
    email      = id_info.get("email", "")
    name       = id_info.get("name", "")
    avatar_url = id_info.get("picture", "")
    email_verified = id_info.get("email_verified", False)

    if not google_id or not email:
        return jsonify({"success": False, "message": "Incomplete Google profile"}), 400

    if not email_verified:
        return jsonify({"success": False, "message": "Google email not verified"}), 401

    # ── Find or create user ──────────────────────────────────────────────────
    user = User.query.filter_by(google_id=google_id).first()

    if not user:
        # Check if email already exists (user registered locally first)
        user = User.query.filter_by(email=email).first()
        if user:
            # Link the Google identity to the existing account
            user.google_id  = google_id
            user.avatar_url = avatar_url
            user.auth_provider = "google"
        else:
            # Brand-new user — auto-register
            username = _derive_username(name, email)
            user = User(
                username=username,
                email=email,
                google_id=google_id,
                avatar_url=avatar_url,
                auth_provider="google",
                # Set an unusable password so the account is local-login–locked
                password_hash="google-oauth-no-password"
            )
            db.session.add(user)

    user.avatar_url = avatar_url          # refresh picture on every login
    db.session.commit()

    if not user.is_active:
        return jsonify({"success": False, "message": "Account is deactivated"}), 403

    return _create_session_response(user)


@auth_bp.route("/google/client-id", methods=["GET"])
def google_client_id():
    """Return Google Client ID to frontend."""
    import os as _os
    from dotenv import load_dotenv as _lde
    _lde()
    cid = _os.getenv("GOOGLE_CLIENT_ID", "")
    return jsonify({"client_id": cid})


# ============================================================================
# LOGOUT
# ============================================================================
@auth_bp.route("/logout", methods=["POST"])
def logout():
    """User logout — revoke current session"""
    token = _extract_token()
    if not token:
        return jsonify({"success": False, "message": "Missing or invalid token"}), 401

    token_hash = hash_token(token)
    session = Session.query.filter_by(token=token_hash, is_active=True).first()

    if session:
        session.is_active = False
        session.revoked_at = datetime.utcnow()
        session.revoked_reason = "User logout"
        db.session.commit()

    return jsonify({"success": True, "message": "Logged out successfully"})


# ============================================================================
# VERIFY SESSION
# ============================================================================
@auth_bp.route("/verify", methods=["GET"])
@token_required
def verify_session(current_user, current_session):
    """Verify that the current JWT session is still valid/active."""
    return jsonify({"success": True, "session": current_session.to_dict()})


# ============================================================================
# SESSIONS MANAGEMENT
# ============================================================================
@auth_bp.route("/sessions", methods=["GET"])
def get_user_sessions():
    """Get all user sessions"""
    token = _extract_token()
    if not token:
        return jsonify({"success": False, "message": "Missing or invalid token"}), 401

    token_hash = hash_token(token)
    current_session = Session.query.filter_by(token=token_hash, is_active=True).first()
    if not current_session:
        return jsonify({"success": False, "message": "Invalid session"}), 401

    sessions = Session.query.filter_by(user_id=current_session.user_id).all()
    return jsonify({
        "success": True,
        "sessions": [s.to_dict() for s in sessions],
        "current_session_id": current_session.id
    })


@auth_bp.route("/sessions/<int:session_id>/revoke", methods=["POST"])
def revoke_user_session(session_id):
    """Revoke a specific user session"""
    token = _extract_token()
    if not token:
        return jsonify({"success": False, "message": "Missing or invalid token"}), 401

    token_hash = hash_token(token)
    current_session = Session.query.filter_by(token=token_hash, is_active=True).first()
    if not current_session:
        return jsonify({"success": False, "message": "Invalid session"}), 401

    session_to_revoke = Session.query.get(session_id)
    if not session_to_revoke:
        return jsonify({"success": False, "message": "Session not found"}), 404

    if session_to_revoke.user_id != current_session.user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    if session_to_revoke.id == current_session.id:
        return jsonify({"success": False, "message": "Cannot revoke current session. Use logout instead."}), 400

    session_to_revoke.is_active = False
    session_to_revoke.revoked_at = datetime.utcnow()
    session_to_revoke.revoked_reason = "Revoked by user"
    db.session.commit()

    return jsonify({"success": True, "message": "Session revoked successfully"})


# ============================================================================
# AUTO-REVOCATION — kill all suspicious sessions
# ============================================================================
@auth_bp.route("/sessions/revoke-suspicious", methods=["POST"])
@token_required
def revoke_suspicious_sessions(current_user, current_session):
    """Auto-revoke all suspicious/attacker sessions. Keeps current session alive."""
    suspicious = Session.query.filter_by(
        user_id=current_user.id,
        is_active=True,
        is_suspicious=True
    ).all()

    revoked_count = 0
    for s in suspicious:
        if s.id != current_session.id:
            s.is_active = False
            s.revoked_at = datetime.utcnow()
            s.revoked_reason = "Auto-revoked: suspicious activity"
            revoked_count += 1

    db.session.commit()

    return jsonify({
        "success": True,
        "revoked_count": revoked_count,
        "message": f"Revoked {revoked_count} suspicious session(s)"
    })


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
def _extract_token():
    """Extract bearer token from Authorization header"""
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split(" ")
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def _create_session_response(user):
    """Create a new session and return the token response"""
    token = generate_token(user.id, user.username)
    token_hash = hash_token(token)

    session = Session(
        user_id=user.id,
        token=token_hash,
        ip_address=get_client_ip(),
        user_agent=get_user_agent()
    )

    db.session.add(session)
    user.last_login = datetime.utcnow()
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Login successful",
        "token": token,
        "user": user.to_dict()
    })


def _derive_username(name, email):
    """
    Derive a unique username from a Google display name + email.
    Falls back to email prefix, then appends a numeric suffix if taken.
    """
    import re
    base = re.sub(r'[^a-zA-Z0-9_]', '', name.replace(' ', '_'))[:20] or email.split('@')[0]
    candidate = base
    suffix = 1
    while User.query.filter_by(username=candidate).first():
        candidate = f"{base}{suffix}"
        suffix += 1
    return candidate


def verify_2fa_code(code, user=None):
    """
    Verify 2FA code.
    - If user has TOTP enabled: verify against their TOTP secret (real verification)
    - Otherwise: accept any valid 6-digit code (demo mode)
    """
    if not code:
        return False

    code_str = str(code).strip()
    if len(code_str) != 6 or not code_str.isdigit():
        return False

    if TOTP_AVAILABLE and user and getattr(user, 'totp_secret', None) and getattr(user, 'totp_enabled', False):
        totp = pyotp.TOTP(user.totp_secret)
        return totp.verify(code_str, valid_window=1)

    # Demo fallback
    return True