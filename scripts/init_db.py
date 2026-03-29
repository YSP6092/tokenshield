"""
TokenShield Database Initialization Script
Sets up the database and creates initial admin user
"""

import sys
import os

# Add parent directory to path
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, parent_dir)

from app import create_app, db
from app.models import User, Session, BehaviorLog, IncidentLog


def init_database():
    """Initialize database with tables"""
    app = create_app()
    
    with app.app_context():
        print("🔨 Creating database tables...")
        
        # Drop all tables (fresh start)
        db.drop_all()
        print("   ✓ Dropped existing tables")
        
        # Create all tables
        db.create_all()
        print("   ✓ Created all tables")
        
        # Verify tables were created
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"   ✓ Tables created: {', '.join(tables)}")
        
        print("\n✅ Database initialized successfully!")
        print("\n" + "="*60)


def create_admin_user():
    """Create initial admin user"""
    app = create_app()
    
    with app.app_context():
        # Check if admin already exists
        admin = User.query.filter_by(username='admin').first()
        
        if admin:
            print("⚠️  Admin user already exists")
            return
        
        print("\n👤 Creating admin user...")
        print("   Username: admin")
        print("   Email: admin@tokenshield.local")
        print("   Password: admin123 (CHANGE THIS IN PRODUCTION!)")
        
        # Create admin user
        admin = User(
            username='admin',
            email='admin@tokenshield.local',
            is_admin=True
        )
        admin.set_password('admin123')
        
        db.session.add(admin)
        db.session.commit()
        
        print("   ✓ Admin user created successfully")
        print("\n⚠️  IMPORTANT: Change the default password after first login!")


def create_demo_user():
    """Create demo user for testing"""
    app = create_app()
    
    with app.app_context():
        # Check if demo user already exists
        demo = User.query.filter_by(username='demo').first()
        
        if demo:
            print("⚠️  Demo user already exists")
            return
        
        print("\n👤 Creating demo user...")
        print("   Username: demo")
        print("   Email: demo@tokenshield.local")
        print("   Password: demo123")
        
        # Create demo user
        demo = User(
            username='demo',
            email='demo@tokenshield.local',
            is_admin=False
        )
        demo.set_password('demo123')
        
        db.session.add(demo)
        db.session.commit()
        
        print("   ✓ Demo user created successfully")


if __name__ == '__main__':
    print("="*60)
    print("🛡️  TokenShield Database Initialization")
    print("="*60)
    
    try:
        # Initialize database
        init_database()
        
        # Create admin user
        create_admin_user()
        
        # Create demo user
        create_demo_user()
        
        print("\n" + "="*60)
        print("✅ Setup completed successfully!")
        print("="*60)
        print("\n📝 Next steps:")
        print("   1. Run: python run.py")
        print("   2. Open: http://localhost:5000")
        print("   3. Login with admin/admin123 or demo/demo123")
        print("\n⚠️  Remember to change default passwords in production!")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ Error during initialization: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)