"""
TokenShield Application Factory
Initializes Flask app with all extensions and configurations
"""

from flask import Flask
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
    # Create Flask app
    app = Flask(__name__,
                static_folder='../frontend',
                static_url_path='')
    
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
    app.config['CORS_ORIGINS'] = ['http://localhost:3000', 'http://localhost:5000', 'http://127.0.0.1:5000']
    app.config['MODEL_PATH'] = 'ml/model.pkl'
    app.config['ANOMALY_THRESHOLD_SUSPICIOUS'] = 0.50
    app.config['ANOMALY_THRESHOLD_CRITICAL'] = 0.70
    app.config['CONTAMINATION_RATE'] = 0.05
    app.config['API_RATE_LIMIT'] = 100
    app.config['ADMIN_REFRESH_INTERVAL'] = 5
    app.config['MAX_INCIDENT_LOGS'] = 1000
    
    # Initialize extensions
    db.init_app(app)
    CORS(app, origins=app.config['CORS_ORIGINS'])
    
    # Register blueprints
    with app.app_context():
        # Import routes inside app context to avoid circular imports
        from . import routes
        
        
        # Register blueprints
        app.register_blueprint(routes.main_bp)
        app.register_blueprint(auth.auth_bp)
        
        # Create database tables
        db.create_all()
        
        print("✅ Database initialized successfully")
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return {"error": "Resource not found"}, 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return {"error": "Internal server error"}, 500
    
    return app