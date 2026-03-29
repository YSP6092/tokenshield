"""
Migration: Add Google OAuth columns to users table
Run once:  python scripts/migrate_google_oauth.py
Safe to re-run — skips columns that already exist.
"""
import sqlite3
import os

DB_PATH = os.getenv("DATABASE_URL", "sqlite:///tokenshield.db").replace("sqlite:///", "")

COLUMNS = [
    ("google_id",     "VARCHAR(128) UNIQUE"),
    ("avatar_url",    "VARCHAR(512)"),
    ("auth_provider", "VARCHAR(32) DEFAULT 'local'"),
]

def migrate():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("PRAGMA table_info(users)")
    existing = {row[1] for row in cur.fetchall()}

    added = []
    for col_name, col_def in COLUMNS:
        if col_name not in existing:
            cur.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
            added.append(col_name)
            print(f"  + Added column: {col_name}")
        else:
            print(f"  ✓ Already exists: {col_name}")

    # Create index on google_id for fast lookup
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_google_id ON users (google_id)
    """)

    conn.commit()
    conn.close()

    if added:
        print(f"\nMigration complete. Added: {', '.join(added)}")
    else:
        print("\nNothing to do — database already up to date.")

if __name__ == "__main__":
    migrate()