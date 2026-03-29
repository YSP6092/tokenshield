"""
TokenShield Utility Functions
Helper functions for various operations
"""

import jwt
import hashlib
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
from app import db
from app.models import Session, User


def generate_token(user_id, username):
    """Generate JWT token for user"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + current_app.config['JWT_EXPIRATION_DELTA'],
        'iat': datetime.utcnow()
    }
    
    token = jwt.encode(
        payload,
        current_app.config['JWT_SECRET_KEY'],
        algorithm=current_app.config['JWT_ALGORITHM']
    )
    
    return token


def decode_token(token):
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=[current_app.config['JWT_ALGORITHM']]
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def hash_token(token):
    """Create hash of token for storage"""
    return hashlib.sha256(token.encode()).hexdigest()


def get_client_ip():
    """Get client IP address from request"""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    
    return ip


def get_user_agent():
    """Get user agent from request"""
    return request.headers.get('User-Agent', 'Unknown')


def token_required(f):
    """Decorator for routes that require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({
                'success': False,
                'message': 'Authentication token is missing'
            }), 401
        
        # Decode token
        payload = decode_token(token)
        if not payload:
            return jsonify({
                'success': False,
                'message': 'Invalid or expired token'
            }), 401
        
        # Check if session exists and is active
        token_hash = hash_token(token)
        session = Session.query.filter_by(token=token_hash, is_active=True).first()
        
        if not session:
            return jsonify({
                'success': False,
                'message': 'Session has been revoked or does not exist'
            }), 401
        
        # Update last activity
        session.last_activity = datetime.utcnow()
        db.session.commit()
        
        # Get user
        user = User.query.get(payload['user_id'])
        if not user or not user.is_active:
            return jsonify({
                'success': False,
                'message': 'User account is inactive'
            }), 401
        
        # Pass user and session to route
        return f(current_user=user, current_session=session, *args, **kwargs)
    
    return decorated


def admin_required(f):
    """Decorator for routes that require admin privileges"""
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user = kwargs.get('current_user')
        
        if not current_user or not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'Admin privileges required'
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated