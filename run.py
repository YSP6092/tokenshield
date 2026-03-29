"""
TokenShield Application Entry Point
Initializes and runs the Flask application
"""

import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app

# Create Flask application
app = create_app()

if __name__ == '__main__':
    # Get configuration from environment (with 5001 as default)
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5001))  # ✅ Changed default to 5001
    debug = os.getenv('DEBUG', 'True').lower() == 'true'  # ✅ Changed to True for development
    
    print("=" * 60)
    print("🛡️  TokenShield - AI-Powered Session Security")
    print("=" * 60)
    print(f"🚀 Starting server on http://{host}:{port}")
    print(f"🔧 Debug mode: {debug}")
    print(f"📊 Environment: {os.getenv('FLASK_ENV', 'development')}")
    print("=" * 60)
    print(f"\n✅ Open in browser: http://localhost:{port}\n")  # ✅ Added helpful message
    print("=" * 60)
    
    # Run the application
    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )