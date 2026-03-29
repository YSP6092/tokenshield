"""
Main Routes - NeoVault + TokenShield
Serves all HTML pages and static files
"""

from flask import Blueprint, send_from_directory, redirect
import os

main_bp = Blueprint('main', __name__)


# ============================================================================
# HTML PAGES
# ============================================================================

@main_bp.route('/')
def index():
    """Serve landing page - Use the professional NeoVault index"""
    return send_from_directory('../frontend', 'neovault_index_pro.html')


@main_bp.route('/login')
def login_page():
    """Serve login page"""
    return send_from_directory('../frontend', 'login.html')


@main_bp.route('/dashboard')
def dashboard():
    """Serve banking dashboard - Use the professional dashboard"""
    return send_from_directory('../frontend', 'neovault_dashboard_pro.html')


@main_bp.route('/security-dashboard')
def security_dashboard():
    """Serve security dashboard for users"""
    return send_from_directory('../frontend', 'security_dashboard_user.html')


@main_bp.route('/admin')
def admin_panel():
    """Serve admin panel"""
    return send_from_directory('../frontend', 'admin.html')


# ============================================================================
# ALTERNATIVE ROUTES (Backwards compatibility)
# ============================================================================

@main_bp.route('/index')
def index_alt():
    """Alternative index route"""
    return send_from_directory('../frontend', 'index.html')


# ============================================================================
# STATIC FILE ROUTES
# ============================================================================

@main_bp.route('/css/<path:filename>')
def serve_css(filename):
    """Serve CSS files from frontend/css/"""
    return send_from_directory('../frontend/css', filename)


@main_bp.route('/js/<path:filename>')
def serve_js(filename):
    """Serve JavaScript files from frontend/js/"""
    return send_from_directory('../frontend/js', filename)


@main_bp.route('/images/<path:filename>')
def serve_images(filename):
    """Serve images if any"""
    return send_from_directory('../frontend/images', filename)


@main_bp.route('/assets/<path:filename>')
def serve_assets(filename):
    """Serve other assets"""
    return send_from_directory('../frontend/assets', filename)


# ============================================================================
# UTILITY ROUTES
# ============================================================================

@main_bp.route('/health')
def health_check():
    """Health check endpoint"""
    return {'status': 'ok', 'service': 'NeoVault + TokenShield'}, 200


@main_bp.route('/favicon.ico')
def favicon():
    """Serve favicon if exists"""
    return send_from_directory('../frontend', 'favicon.ico', mimetype='image/vnd.microsoft.icon')


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@main_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return send_from_directory('../frontend', 'index.html'), 404


# ============================================================================
# ROUTE REFERENCE
# ============================================================================
"""
Available Routes:

PUBLIC PAGES:
- GET  /                    → neovault_index_pro.html (Landing page)
- GET  /login               → login.html (Login/Register)

AUTHENTICATED PAGES:
- GET  /dashboard           → neovault_dashboard_pro.html (Banking dashboard)
- GET  /security-dashboard  → security_dashboard_user.html (User security)
- GET  /admin               → admin.html (Admin panel)

STATIC FILES:
- GET  /css/<file>          → CSS files
- GET  /js/<file>           → JavaScript files
- GET  /images/<file>       → Images
- GET  /assets/<file>       → Other assets

UTILITY:
- GET  /health              → Health check
- GET  /favicon.ico         → Favicon
"""