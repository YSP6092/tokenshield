"""
Migration: Add Google OAuth columns to users table
Run once:  python scripts/migrate_google_oauth.py
Safe to re-run — skips columns that already exist.
"""
import sqlite3
import os

# Support both sqlite:///path and plain path
_raw = os.getenv("DATABASE_URL", "sqlite:///tokenshield.db")
DB_PATH = _raw.replace("sqlite:///", "").replace("sqlite://", "")


COLUMNS = [
    ("google_id",     "VARCHAR(128)"),          # unique index added below
    ("avatar_url",    "VARCHAR(512)"),
    ("auth_provider", "VARCHAR(32) DEFAULT 'local'"),
    ("requires_2fa",  "BOOLEAN DEFAULT 0"),      # used by revoke_and_lock
]

def migrate():
    if not os.path.exists(DB_PATH):
        print(f"  ✗ Database not found at: {DB_PATH}")
        print("    Start the app first so SQLAlchemy creates the tables.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # ── users table ──────────────────────────────────────────────────────────
    cur.execute("PRAGMA table_info(users)")
    existing_users = {row[1] for row in cur.fetchall()}

    added = []
    for col_name, col_def in COLUMNS:
        if col_name not in existing_users:
            cur.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
            added.append(col_name)
            print(f"  + users.{col_name}")
        else:
            print(f"  ✓ users.{col_name} already exists")

    # Unique index on google_id (nullable — only for OAuth users)
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id
        ON users (google_id)
        WHERE google_id IS NOT NULL
    """)

    # ── sessions table: make sure revoked_at and revoked_reason exist ────────
    cur.execute("PRAGMA table_info(sessions)")
    existing_sessions = {row[1] for row in cur.fetchall()}

    session_cols = [
        ("revoked_at",     "DATETIME"),
        ("revoked_reason", "VARCHAR(256)"),
    ]
    for col_name, col_def in session_cols:
        if col_name not in existing_sessions:
            cur.execute(f"ALTER TABLE sessions ADD COLUMN {col_name} {col_def}")
            added.append(f"sessions.{col_name}")
            print(f"  + sessions.{col_name}")
        else:
            print(f"  ✓ sessions.{col_name} already exists")

    conn.commit()
    conn.close()

    if added:
        print(f"\nMigration complete. Added columns: {', '.join(added)}")
    else:
        print("\nNothing to do — database already up to date.")


# ── Google OAuth env-var checker ─────────────────────────────────────────────
def check_google_oauth():
    """
    Called at app startup to warn about missing Google OAuth config.
    Returns True if Google OAuth is properly configured, False otherwise.
    The app should disable the Google login button when this returns False
    instead of crashing or showing "not configured on this server".
    """
    client_id     = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()

    if not client_id or not client_secret:
        print("  ⚠  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET not set.")
        print("     Google OAuth will be disabled until these are configured.")
        print("     To enable: set both env vars and restart the server.")
        return False

    if client_id == "your-google-client-id" or client_secret == "your-google-client-secret":
        print("  ⚠  Google OAuth env vars contain placeholder values.")
        print("     Google OAuth will be disabled.")
        return False

    print("  ✓ Google OAuth configured.")
    return True


if __name__ == "__main__":
    migrate()
    print()
    check_google_oauth()