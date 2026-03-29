"""
TokenShield Application Factory
Initializes Flask app with all extensions and configurations
"""

from flask import Flask
from dotenv import load_dotenv
load_dotenv()
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import timedelta

# Initialize extensions
db = SQLAlchemy()

def create_app(config_name=None):
    """
    Application factory pattern
    Creates and configures the Flask application
    """
    # Create Flask app with proper static file configuration
    app = Flask(__name__,
                static_folder='../frontend',
                static_url_path='/static')
    
    # Load configuration directly
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///tokenshield.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
    app.config['JWT_ALGORITHM'] = 'HS256'
    app.config['JWT_EXPIRATION_DELTA'] = timedelta(hours=24)
    app.config['BCRYPT_LOG_ROUNDS'] = 12
    app.config['MAX_LOGIN_ATTEMPTS'] = 5
    app.config['SESSION_TIMEOUT_MINUTES'] = 30
    app.config['CORS_ORIGINS'] = ['http://localhost:3000', 'http://localhost:5000', 'http://localhost:5001', 'http://127.0.0.1:5000', 'http://127.0.0.1:5001']
    app.config['MODEL_PATH'] = 'ml/model.pkl'
    app.config['ANOMALY_THRESHOLD_SUSPICIOUS'] = 0.50
    app.config['ANOMALY_THRESHOLD_CRITICAL'] = 0.70
    app.config['CONTAMINATION_RATE'] = 0.05
    app.config['API_RATE_LIMIT'] = 100
    app.config['ADMIN_REFRESH_INTERVAL'] = 5
    app.config['MAX_INCIDENT_LOGS'] = 1000
    
    # Initialize extensions
    db.init_app(app)
    CORS(app, origins=app.config['CORS_ORIGINS'], supports_credentials=True)

    # Email service (graceful no-op if Flask-Mail not configured)
    try:
        from app.email_service import init_mail
        init_mail(app)
    except Exception:
        pass
    
    with app.app_context():
        from app.routes import main_bp
        from app.auth import auth_bp
        from app.banking_routes import banking_bp
        from app.dashboard_routes import dashboard_bp
        from app.security_routes import security_bp
        from app import dashboard_routes  # FIXED: missing import

        app.register_blueprint(main_bp)
        app.register_blueprint(auth_bp)          # prefix /api/auth built into blueprint
        app.register_blueprint(banking_bp)
        app.register_blueprint(security_bp)

        # Register dashboard blueprints
        dashboard_routes.register_dashboard_blueprints(app)
        
        # Create database tables
        db.create_all()
        
        print("✅ Database initialized successfully")
        print("✅ All blueprints registered successfully")
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return {"error": "Resource not found"}, 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return {"error": "Internal server error"}, 500
    
    return app