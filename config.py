"""
TokenShield Configuration Module
Manages application settings and environment variables
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

class Config:
    """Base configuration class"""
    
    # Application Settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///tokenshield.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = DEBUG
    
    # JWT Configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
    JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
    JWT_EXPIRATION_DELTA = timedelta(hours=int(os.getenv('JWT_EXPIRATION_HOURS', 24)))
    
    # Security Settings
    BCRYPT_LOG_ROUNDS = int(os.getenv('BCRYPT_LOG_ROUNDS', 12))
    MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
    SESSION_TIMEOUT_MINUTES = int(os.getenv('SESSION_TIMEOUT_MINUTES', 30))
    
    # CORS Configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://localhost:5000').split(',')
    
    # ML Model Configuration
    MODEL_PATH = os.getenv('MODEL_PATH', 'ml/model.pkl')
    ANOMALY_THRESHOLD_SUSPICIOUS = float(os.getenv('ANOMALY_THRESHOLD_SUSPICIOUS', 0.50))
    ANOMALY_THRESHOLD_CRITICAL = float(os.getenv('ANOMALY_THRESHOLD_CRITICAL', 0.70))
    CONTAMINATION_RATE = float(os.getenv('CONTAMINATION_RATE', 0.05))
    
    # Google OAuth
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', '')

    # API Configuration
    API_RATE_LIMIT = int(os.getenv('API_RATE_LIMIT', 100))
    
    # Dashboard Configuration
    ADMIN_REFRESH_INTERVAL = int(os.getenv('ADMIN_REFRESH_INTERVAL', 5))
    MAX_INCIDENT_LOGS = int(os.getenv('MAX_INCIDENT_LOGS', 1000))


class DevelopmentConfig(Config):
    """Development environment configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production environment configuration"""
    DEBUG = False
    TESTING = False
    
    # Override with production values
    SQLALCHEMY_ECHO = False


class TestingConfig(Config):
    """Testing environment configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test_tokenshield.db'
    BCRYPT_LOG_ROUNDS = 4  # Faster for testing


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Get configuration based on environment"""
    env = os.getenv('FLASK_ENV', 'development')
    return config.get(env, config['default'])