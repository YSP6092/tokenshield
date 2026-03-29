"""
TokenShield Email Service
==========================
Sends security alert emails on events like:
  - Suspicious login detected
  - Session revoked due to anomaly
  - New device / IP login
  - 2FA required after security incident

Setup: add these to your .env file
  MAIL_SERVER=smtp.gmail.com
  MAIL_PORT=587
  MAIL_USERNAME=your@gmail.com
  MAIL_PASSWORD=your-app-password
  MAIL_DEFAULT_SENDER=no-reply@neovault.com
"""

from flask import current_app
from datetime import datetime

try:
    from flask_mail import Mail, Message
    MAIL_AVAILABLE = True
except ImportError:
    MAIL_AVAILABLE = False

mail = Mail() if MAIL_AVAILABLE else None


def init_mail(app):
    """Call this in create_app() after loading config."""
    if not MAIL_AVAILABLE:
        app.logger.warning("Flask-Mail not installed. Email alerts disabled.")
        return

    app.config.setdefault('MAIL_SERVER', 'smtp.gmail.com')
    app.config.setdefault('MAIL_PORT', 587)
    app.config.setdefault('MAIL_USE_TLS', True)
    app.config.setdefault('MAIL_USERNAME', None)
    app.config.setdefault('MAIL_PASSWORD', None)
    app.config.setdefault('MAIL_DEFAULT_SENDER', 'no-reply@neovault.com')
    app.config.setdefault('MAIL_SUPPRESS_SEND', app.config.get('TESTING', False))

    mail.init_app(app)


def _send(subject: str, recipient: str, html_body: str) -> bool:
    """Internal send helper. Returns True on success, False on failure."""
    if not MAIL_AVAILABLE or not mail:
        current_app.logger.info(f"[Email stub] To: {recipient} | Subject: {subject}")
        return True  # Graceful no-op in dev/test

    if not current_app.config.get('MAIL_USERNAME'):
        current_app.logger.warning("MAIL_USERNAME not configured — email not sent.")
        return False

    try:
        msg = Message(subject=subject, recipients=[recipient], html=html_body)
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Email send failed: {e}")
        return False


# ============================================================================
# EMAIL TEMPLATES
# ============================================================================

def _base_template(title: str, body_html: str, cta_text: str = None, cta_url: str = None) -> str:
    cta_block = ""
    if cta_text and cta_url:
        cta_block = f"""
        <div style="text-align:center;margin:28px 0">
          <a href="{cta_url}" style="background:#1652F0;color:#fff;padding:12px 28px;
             border-radius:8px;text-decoration:none;font-weight:600;font-size:14px">
            {cta_text}
          </a>
        </div>"""

    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#F3F4F6;font-family:'Inter',Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:32px 16px">
      <table width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:14px;
             border:1px solid #E5E7EB;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.06)">
        <!-- Header -->
        <tr><td style="background:#1652F0;padding:22px 32px">
          <span style="color:#fff;font-size:18px;font-weight:700;letter-spacing:-.3px">
            🏦 NeoVault · TokenShield
          </span>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:32px">
          <h1 style="margin:0 0 16px;font-size:20px;font-weight:700;color:#111827">{title}</h1>
          {body_html}
          {cta_block}
          <hr style="border:none;border-top:1px solid #E5E7EB;margin:24px 0">
          <p style="margin:0;font-size:11px;color:#9CA3AF;line-height:1.6">
            This is an automated security alert from TokenShield. If you did not perform this
            action, please contact support immediately or log in to review your active sessions.
            <br>© {datetime.utcnow().year} NeoVault · Powered by TokenShield™
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _info_row(label: str, value: str) -> str:
    return f"""
    <tr>
      <td style="padding:8px 12px;font-size:13px;color:#6B7280;font-weight:500;white-space:nowrap">{label}</td>
      <td style="padding:8px 12px;font-size:13px;color:#111827">{value}</td>
    </tr>"""


def _detail_table(rows: list[tuple]) -> str:
    inner = "".join(_info_row(k, v) for k, v in rows)
    return f"""
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:#F9FAFB;border:1px solid #E5E7EB;border-radius:8px;
                  margin:16px 0;border-collapse:collapse">
      {inner}
    </table>"""


# ============================================================================
# PUBLIC API — Call these from your routes
# ============================================================================

def send_suspicious_login_alert(user, session, anomaly_score: float) -> bool:
    """
    Alert user that a suspicious login was detected on their account.
    Called from security_routes.py when anomaly_score > threshold.
    """
    severity = "CRITICAL" if anomaly_score >= 0.7 else "WARNING"
    color = "#DC2626" if severity == "CRITICAL" else "#D97706"

    body = f"""
    <div style="background:#FEF2F2;border:1px solid #FECACA;border-radius:8px;
                padding:14px 16px;margin-bottom:20px">
      <span style="color:{color};font-weight:700;font-size:14px">
        ⚠ {severity}: Suspicious activity detected on your account
      </span>
    </div>
    <p style="color:#374151;font-size:14px;line-height:1.6;margin:0 0 16px">
      TokenShield detected unusual behaviour on your NeoVault account.
      Your session has been flagged and may be automatically revoked.
    </p>
    {_detail_table([
        ("Time", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")),
        ("IP Address", session.ip_address or "Unknown"),
        ("Device", (session.user_agent or "Unknown")[:60]),
        ("Anomaly Score", f"{anomaly_score:.1%} (threshold: 50%)"),
        ("Action Taken", "Session flagged · Monitoring active"),
    ])}
    <p style="color:#374151;font-size:13px;line-height:1.6">
      If this was you, no action is needed. If not, immediately revoke suspicious
      sessions from your security dashboard.
    </p>"""

    return _send(
        subject=f"[{severity}] Suspicious login detected — NeoVault",
        recipient=user.email,
        html_body=_base_template(
            "Suspicious Login Detected",
            body,
            cta_text="Review Active Sessions",
            cta_url="http://localhost:5000/security"
        )
    )


def send_session_revoked_alert(user, session, reason: str = "Security incident") -> bool:
    """
    Notify user that one of their sessions was revoked (by ML or admin).
    """
    body = f"""
    <p style="color:#374151;font-size:14px;line-height:1.6;margin:0 0 16px">
      A session on your NeoVault account was automatically revoked by TokenShield's
      security system.
    </p>
    {_detail_table([
        ("Revoked At", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")),
        ("Session IP", session.ip_address or "Unknown"),
        ("Device", (session.user_agent or "Unknown")[:60]),
        ("Reason", reason),
    ])}
    <p style="color:#374151;font-size:13px;line-height:1.6">
      If this was your legitimate session, please sign in again. If you did not
      initiate this action, your account may be under attack — we recommend
      changing your password and enabling 2FA immediately.
    </p>"""

    return _send(
        subject="Your session was revoked — NeoVault Security Alert",
        recipient=user.email,
        html_body=_base_template(
            "Session Revoked",
            body,
            cta_text="Sign In & Review Security",
            cta_url="http://localhost:5000/login"
        )
    )


def send_new_device_login_alert(user, session) -> bool:
    """
    Alert user of a login from a new IP or device they haven't used before.
    """
    body = f"""
    <p style="color:#374151;font-size:14px;line-height:1.6;margin:0 0 16px">
      Your NeoVault account was just accessed from a new location or device.
    </p>
    {_detail_table([
        ("Time", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")),
        ("IP Address", session.ip_address or "Unknown"),
        ("Device / Browser", (session.user_agent or "Unknown")[:80]),
    ])}
    <p style="color:#374151;font-size:13px;line-height:1.6">
      If this was you, you can safely ignore this message. If you don't recognise
      this sign-in, revoke the session immediately from your security dashboard.
    </p>"""

    return _send(
        subject="New sign-in to your NeoVault account",
        recipient=user.email,
        html_body=_base_template(
            "New Device Sign-In",
            body,
            cta_text="Review Sessions",
            cta_url="http://localhost:5000/security"
        )
    )


def send_2fa_required_alert(user, triggering_session) -> bool:
    """
    Inform user that 2FA is now required because of a security incident.
    """
    body = f"""
    <div style="background:#FFF7ED;border:1px solid #FED7AA;border-radius:8px;
                padding:14px 16px;margin-bottom:20px">
      <span style="color:#C2410C;font-weight:700;font-size:14px">
        🔐 Two-Factor Authentication now required
      </span>
    </div>
    <p style="color:#374151;font-size:14px;line-height:1.6;margin:0 0 16px">
      Due to suspicious activity on your account, TokenShield has enabled mandatory
      2FA verification for all future logins. You will need to enter a verification
      code each time you sign in.
    </p>
    {_detail_table([
        ("Triggered At", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")),
        ("Triggering IP", triggering_session.ip_address or "Unknown"),
        ("Anomaly Score", f"{triggering_session.anomaly_score:.1%}"),
    ])}
    <p style="color:#374151;font-size:13px;line-height:1.6">
      Set up Google Authenticator from your account security settings to use
      time-based one-time passwords (TOTP) for the strongest protection.
    </p>"""

    return _send(
        subject="Action required: 2FA now enabled on your NeoVault account",
        recipient=user.email,
        html_body=_base_template(
            "2FA Verification Required",
            body,
            cta_text="Set Up Google Authenticator",
            cta_url="http://localhost:5000/security"
        )
    )


def send_totp_enabled_confirmation(user) -> bool:
    """Confirmation email when user successfully enables Google Authenticator."""
    body = f"""
    <div style="background:#F0FDF4;border:1px solid #BBF7D0;border-radius:8px;
                padding:14px 16px;margin-bottom:20px">
      <span style="color:#059669;font-weight:700;font-size:14px">
        ✓ Google Authenticator successfully enabled
      </span>
    </div>
    <p style="color:#374151;font-size:14px;line-height:1.6;margin:0 0 16px">
      Your NeoVault account is now protected with two-factor authentication.
      Every sign-in will require your 6-digit authenticator code.
    </p>
    {_detail_table([
        ("Enabled At", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")),
        ("Method", "TOTP — Google Authenticator / Authy"),
        ("Status", "Active ✓"),
    ])}
    <p style="color:#374151;font-size:13px;line-height:1.6">
      <strong>Important:</strong> Store your backup codes in a safe place. If you
      lose access to your authenticator app, you will need them to recover your account.
    </p>"""

    return _send(
        subject="2FA enabled on your NeoVault account ✓",
        recipient=user.email,
        html_body=_base_template("Two-Factor Authentication Enabled", body)
    )
