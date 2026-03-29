#!/usr/bin/env python3
"""
TokenShield - Complete Setup and Fix Script
Handles all installation and compatibility issues
"""

import os
import sys
import subprocess
import shutil

def print_header(text):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)

def run_command(cmd, description):
    """Run a command and return success status"""
    print(f"\n🔄 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, 
                              capture_output=True, text=True)
        print(f"✅ {description} - Success")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} - Failed")
        print(f"   Error: {e.stderr}")
        return False

def check_python_version():
    """Check Python version"""
    version = sys.version_info
    print(f"\n🐍 Python Version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print("❌ Python 3.9+ required!")
        return False
    
    if version.minor >= 13:
        print("⚠️  Python 3.13 detected - Using compatible package versions")
    
    return True

def check_files():
    """Check if all required files exist"""
    print_header("Checking File Structure")
    
    required_files = {
        'app/__init__.py': 'App initialization',
        'app/models.py': 'Database models',
        'app/auth.py': 'Authentication',
        'app/routes.py': 'API routes',
        'app/utils.py': 'Utilities',
        'requirements.txt': 'Dependencies',
        'run.py': 'Startup script'
    }
    
    all_good = True
    for file, desc in required_files.items():
        if os.path.exists(file):
            print(f"✅ {file:25} ({desc})")
        else:
            print(f"❌ {file:25} ({desc}) - MISSING!")
            all_good = False
    
    return all_good

def create_venv():
    """Create virtual environment"""
    print_header("Virtual Environment Setup")
    
    if os.path.exists('venv'):
        response = input("\n⚠️  venv already exists. Delete and recreate? (yes/no): ")
        if response.lower() == 'yes':
            print("🗑️  Removing old venv...")
            shutil.rmtree('venv')
        else:
            print("✅ Using existing venv")
            return True
    
    return run_command(f"{sys.executable} -m venv venv", "Creating virtual environment")

def get_pip_cmd():
    """Get the correct pip command for the venv"""
    if os.name == 'nt':  # Windows
        return 'venv\\Scripts\\pip'
    else:  # Mac/Linux
        return './venv/bin/pip'

def get_python_cmd():
    """Get the correct python command for the venv"""
    if os.name == 'nt':  # Windows
        return 'venv\\Scripts\\python'
    else:  # Mac/Linux
        return './venv/bin/python'

def install_dependencies():
    """Install Python packages"""
    print_header("Installing Dependencies")
    
    pip_cmd = get_pip_cmd()
    
    # Upgrade pip first
    run_command(f"{pip_cmd} install --upgrade pip", "Upgrading pip")
    
    # Install specific compatible versions
    print("\n📦 Installing packages with compatible versions...")
    
    packages = [
        "Flask==3.0.0",
        "Flask-CORS==4.0.0",
        "SQLAlchemy==2.0.23",  # Compatible with Python 3.13
        "Flask-SQLAlchemy==3.0.5",
        "PyJWT==2.8.0",
        "bcrypt==4.1.2",
        "Werkzeug==3.0.1",
        "python-dotenv==1.0.0",
        "requests==2.31.0"
    ]
    
    for package in packages:
        if not run_command(f"{pip_cmd} install {package}", f"Installing {package.split('==')[0]}"):
            return False
    
    return True

def initialize_database():
    """Initialize the database"""
    print_header("Database Initialization")
    
    python_cmd = get_python_cmd()
    
    if os.path.exists('scripts/init_db.py'):
        return run_command(f"{python_cmd} scripts/init_db.py", "Initializing database")
    else:
        print("⚠️  scripts/init_db.py not found - skipping database initialization")
        print("   You can initialize later with: python scripts/init_db.py")
        return True

def main():
    print_header("🛡️  TokenShield - Complete Setup")
    
    # Check current directory
    if not os.path.exists('app'):
        print("\n❌ Error: Not in token-shield directory!")
        print("   Please run this script from the token-shield folder")
        print(f"   Current directory: {os.getcwd()}")
        sys.exit(1)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check files
    if not check_files():
        print("\n❌ Missing required files!")
        print("\n💡 Solutions:")
        print("   1. Make sure you have all files from the download")
        print("   2. Check if you're in the correct directory")
        print("   3. Re-download the project if files are missing")
        
        response = input("\n❓ Continue anyway? (yes/no): ")
        if response.lower() != 'yes':
            sys.exit(1)
    
    # Create virtual environment
    if not create_venv():
        print("\n❌ Failed to create virtual environment")
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Failed to install dependencies")
        print("\n💡 Try manually:")
        print(f"   {get_pip_cmd()} install -r requirements.txt")
        sys.exit(1)
    
    # Initialize database
    initialize_database()
    
    # Final instructions
    print_header("✅ Setup Complete!")
    
    print("\n📝 Next Steps:")
    print("\n1. Activate virtual environment:")
    if os.name == 'nt':
        print("   venv\\Scripts\\activate")
    else:
        print("   source venv/bin/activate")
    
    print("\n2. Start the server:")
    print(f"   {get_python_cmd()} run.py")
    print("   OR")
    print("   python run.py  (after activating venv)")
    
    print("\n3. Open browser:")
    print("   http://localhost:5000")
    
    print("\n4. Login with:")
    print("   Admin: admin / admin123")
    print("   User:  demo / demo123")
    
    print("\n" + "=" * 70)
    
    # Option to start server now
    response = input("\n❓ Start server now? (yes/no): ")
    if response.lower() == 'yes':
        print("\n🚀 Starting TokenShield...")
        os.system(f"{get_python_cmd()} run.py")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)