"""
Database Migration: Add metadata field to BehaviorLog
Run this to add the metadata column without losing existing data
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db

def migrate():
    """Add metadata column to behavior_logs table"""
    app = create_app()
    
    with app.app_context():
        print("=" * 70)
        print("🔧 Database Migration: Adding metadata to BehaviorLog")
        print("=" * 70)
        print()
        
        try:
            # Check if column already exists
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('behavior_logs')]
            
            if 'metadata' in columns:
                print("✅ metadata column already exists")
                return
            
            print("📝 Adding metadata column...")
            
            # Add column using raw SQL
            db.engine.execute(
                'ALTER TABLE behavior_logs ADD COLUMN metadata TEXT'
            )
            
            print("✅ Successfully added metadata column")
            print()
            print("=" * 70)
            print("Migration complete!")
            print("=" * 70)
            
        except Exception as e:
            print(f"❌ Migration failed: {e}")
            print()
            print("This might mean:")
            print("1. The column already exists")
            print("2. Database is locked")
            print("3. You need to recreate the database")
            print()
            print("To recreate database (⚠️ DELETES ALL DATA):")
            print("  python setup_database.py --fresh")

if __name__ == '__main__':
    migrate()