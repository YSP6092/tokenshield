# TokenShield — Complete Setup Guide
## After the Phase 1+2+3 Fixes

---

## ✅ What Was Fixed

### Bug 1 — `timedelta` NameError in `auth.py`
**Root cause:** `from datetime import timedelta` was at the bottom of the file (line 331),
but `timedelta` was used on line ~87 inside `login()`.  
**Fix:** Moved to top: `from datetime import datetime, timedelta`

### Bug 2 — `BehaviorLog` indentation in `models.py`
**Root cause:** Fields `time_gap`, `endpoint`, `request_method`, `fingerprint_data` and
`to_dict()` were at module level (0 indentation), not inside the class body.
SQLAlchemy silently ignored them — those columns were never created.  
**Fix:** All fields and methods now correctly indented inside the `BehaviorLog` class.

### Bug 3 — Blueprint missing `url_prefix`
**Root cause:** `auth_bp = Blueprint("auth", __name__)` had no prefix.
Frontend called `/api/auth/login` but route was mounted at `/login` → 404.  
**Fix:** `auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")`

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set up environment
cp .env.example .env    # edit with your values

# 3. Initialize database
python setup_database.py

# 4. Run
python run.py
# → http://localhost:5000
```

---

## 🔐 Phase 2: Google Authenticator (TOTP)

### Install packages
```bash
pip install pyotp "qrcode[pil]"
```

### How it works
1. User calls `POST /api/auth/totp/setup` → gets QR code image
2. User scans with Google Authenticator / Authy
3. User calls `POST /api/auth/totp/confirm` with first 6-digit code
4. All future logins require the TOTP code

### API Flow
```
POST /api/auth/totp/setup          → { qr_code, secret, provisioning_uri }
POST /api/auth/totp/confirm        → { code: "123456" }
POST /api/auth/totp/disable        → { code: "123456" }
```

### New User model fields (auto-migrated via db.create_all)
- `totp_secret` — base32 secret stored per user
- `totp_enabled` — boolean flag

---

## 📧 Phase 2: Email Security Alerts

### Install
```bash
pip install Flask-Mail
```

### Configure `.env`
```
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your@gmail.com
MAIL_PASSWORD=your-app-password    # Google App Password, not account password
MAIL_DEFAULT_SENDER=no-reply@neovault.com
```

### Emails sent automatically on
| Event | Function |
|-------|----------|
| Suspicious session detected | `send_suspicious_login_alert()` |
| Session auto-revoked by ML | `send_session_revoked_alert()` |
| Login from new device/IP | `send_new_device_login_alert()` |
| 2FA now required | `send_2fa_required_alert()` |
| TOTP successfully enabled | `send_totp_enabled_confirmation()` |

### Call from your routes
```python
from app.email_service import send_suspicious_login_alert
send_suspicious_login_alert(user, session, anomaly_score=0.85)
```

> **Dev mode:** If `MAIL_USERNAME` is not set, emails are logged to console instead of sent.

---

## 🔵 Phase 2: Google Sign-In Button

The login page now has a **Continue with Google** button. To activate it:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project → Enable **Google Identity** API
3. Create OAuth 2.0 credentials → Web Application
4. Add `http://localhost:5000` to authorized origins
5. Copy the **Client ID** and replace in `login.html`:
   ```javascript
   client_id: 'YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com'
   ```
6. Add backend route to verify the Google JWT:

```python
# In auth.py — add this route
from google.oauth2 import id_token
from google.auth.transport import requests as grequests

@auth_bp.route("/google/verify", methods=["POST"])
def google_verify():
    data = request.get_json()
    credential = data.get("credential")
    try:
        idinfo = id_token.verify_oauth2_token(
            credential,
            grequests.Request(),
            "YOUR_GOOGLE_CLIENT_ID"
        )
        email = idinfo["email"]
        name = idinfo.get("name", email.split("@")[0])

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(username=name, email=email)
            user.set_password(os.urandom(32).hex())  # random password
            db.session.add(user)
            db.session.commit()

        return _create_session_response(user)
    except ValueError:
        return jsonify({"success": False, "message": "Invalid Google token"}), 401
```

---

## 🤖 Phase 3: ML Model Training

```bash
# Train on synthetic data (no DB needed)
python scripts/train_ml_model.py --synthetic --save

# Train on real behavioral data from DB
python scripts/train_ml_model.py --save

# Custom contamination rate
python scripts/train_ml_model.py --synthetic --save --contamination 0.08
```

The script outputs:
- `ml/model.pkl` — trained Isolation Forest pipeline (scaler + model)
- `ml/model_metadata.json` — training info and feature list
- Classification report with precision/recall for normal vs anomalous sessions

### Features used by the model
| Feature | Description |
|---------|-------------|
| `time_gap_mean/std/min/max` | Timing between requests |
| `requests_per_minute` | Request rate |
| `unique_endpoints` | Number of distinct endpoints visited |
| `post_ratio / get_ratio` | HTTP method distribution |
| `transaction_count` | Number of banking transactions |
| `avg/max_transaction_amount` | Transaction amounts |
| `session_age_minutes` | How long the session has been active |
| `ip_change` | Whether IP changed mid-session |
| `user_agent_change` | Whether UA changed mid-session |

---

## 🧪 Postman Collection

Import `TokenShield_Postman_Collection.json` into Postman.

**Quick start:**
1. Set `baseUrl` = `http://localhost:5000`
2. Run **Register** → **Login** (token auto-saved to `{{token}}`)
3. All other requests use `{{token}}` automatically

---

## 📁 Project Structure

```
tokenshield/
├── app/
│   ├── __init__.py          ✅ Fixed blueprint registration + email init
│   ├── auth.py              ✅ Fixed timedelta, url_prefix, TOTP routes, auto-revocation
│   ├── models.py            ✅ Fixed BehaviorLog indentation + TOTP fields on User
│   ├── email_service.py     ✅ NEW — security alert emails (5 email types)
│   ├── banking_routes.py
│   ├── security_routes.py
│   ├── dashboard_routes.py
│   ├── routes.py
│   └── utils.py
├── frontend/
│   ├── login.html           ✅ Google Sign-In button + improved TOTP overlay
│   ├── dashboard.html
│   ├── security_dashboard_user.html
│   └── ...
├── scripts/
│   ├── train_ml_model.py    ✅ NEW — full ML training with synthetic data gen
│   └── init_db.py
├── requirements.txt         ✅ Updated with pyotp, qrcode, Flask-Mail, google-auth
├── TokenShield_Postman_Collection.json  ✅ NEW — full API test suite
└── SETUP_GUIDE.md           ✅ This file
```
