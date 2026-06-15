"""
TokenShield Application Factory — FIXED
========================================
Fix: dashboard_routes.register_dashboard_blueprints() was registering
a second Blueprint on url_prefix='/api/admin' that conflicted with
app/routes/admin.py. Removed the duplicate. Only app/routes/admin.py
owns /api/admin now.
"""

from flask import Flask, jsonify
from dotenv import load_dotenv
load_dotenv()
from flask_cors import CORS
from app.extensions import db
import os
from datetime import timedelta


def create_app(config_name=None):
    app = Flask(__name__,
                static_folder='../frontend',
                static_url_path='/static')

    # ── Config ────────────────────────────────────────────────────────────
    app.config['SECRET_KEY']                     = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI']        = os.getenv('DATABASE_URL', 'sqlite:///tokenshield.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY']                 = os.getenv('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
    app.config['JWT_ALGORITHM']                  = 'HS256'
    app.config['JWT_EXPIRATION_DELTA']           = timedelta(hours=24)
    app.config['BCRYPT_LOG_ROUNDS']              = 12
    app.config['MAX_LOGIN_ATTEMPTS']             = 5
    app.config['SESSION_TIMEOUT_MINUTES']        = 30
    app.config['MODEL_PATH']                     = 'ml/model.pkl'
    app.config['ANOMALY_THRESHOLD_SUSPICIOUS']   = 0.50
    app.config['ANOMALY_THRESHOLD_CRITICAL']     = 0.70
    app.config['CONTAMINATION_RATE']             = 0.05
    app.config['API_RATE_LIMIT']                 = 100
    app.config['ADMIN_REFRESH_INTERVAL']         = 5
    app.config['MAX_INCIDENT_LOGS']              = 1000

    # ── CORS ──────────────────────────────────────────────────────────────
    env_origins = os.getenv('CORS_ORIGINS', '')
    if env_origins:
        cors_origins = [o.strip() for o in env_origins.replace('\n', ',').split(',') if o.strip()]
    else:
        cors_origins = [
            'http://localhost',
            'http://localhost:80',
            'http://localhost:3000',
            'http://localhost:5001',
            'http://127.0.0.1',
            'http://127.0.0.1:80',
            'http://127.0.0.1:5001',
            'http://172.20.0.3',
            'http://172.20.0.2:5001',
        ]
    app.config['CORS_ORIGINS'] = cors_origins

    # ── Extensions ────────────────────────────────────────────────────────
    db.init_app(app)
    CORS(app,
         origins=app.config['CORS_ORIGINS'],
         supports_credentials=True,
         allow_headers=["Content-Type", "Authorization"],
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

    # ── Health endpoint ───────────────────────────────────────────────────
    @app.route('/health')
    def health():
        return jsonify({
            "status":  "healthy",
            "service": "TokenShield / NeoVault",
            "version": "3.5"
        }), 200

    # ── Detection middleware ──────────────────────────────────────────────
    from app.middleware.detection import init_detection_middleware
    init_detection_middleware(app)

    # ── Optional services ─────────────────────────────────────────────────
    try:
        from app.email_service import init_mail
        init_mail(app)
    except Exception:
        pass

    with app.app_context():
        # Import all blueprints
        from app.main_routes              import main_bp
        from app.routes.auth              import auth_bp
        from app.banking_routes           import banking_bp
        from app.dashboard_routes         import dashboard_bp          # /api/dashboard only
        from app.security_routes          import security_bp
        from app.routes.attack_simulator  import attack_bp
        from app.google_auth              import google_bp
        from app.routes.admin             import admin_bp              # sole owner of /api/admin
        from app.routes.simulation        import simulation_bp

        app.register_blueprint(main_bp)
        app.register_blueprint(auth_bp)
        app.register_blueprint(banking_bp)
        app.register_blueprint(dashboard_bp)   # /api/dashboard/*
        app.register_blueprint(security_bp)
        app.register_blueprint(attack_bp)
        app.register_blueprint(google_bp)
        app.register_blueprint(admin_bp)       # /api/admin/*  ← only registered once
        app.register_blueprint(simulation_bp)

        # dashboard_routes.register_dashboard_blueprints() is NOT called here
        # because it used to register a duplicate admin_bp — that caused all 500s.
        # dashboard_bp is registered directly above instead.

        db.create_all()

        from simulation.network_controller import start_monitor
        start_monitor()
        print("✅ Resource monitor started")
        print("✅ Database initialized successfully")
        print("✅ All blueprints registered successfully")

    # ── Error handlers ────────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(error):
        return {"error": "Resource not found"}, 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return {"error": "Internal server error"}, 500

    return app