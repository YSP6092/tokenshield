"""
TokenShield Database Models + Alpha Bank Integration
Defines all database tables and relationships
"""

from datetime import datetime
from app import db
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    # Google OAuth
    google_id = db.Column(db.String(128), unique=True, nullable=True, index=True)
    avatar_url = db.Column(db.String(512), nullable=True)
    auth_provider = db.Column(db.String(32), default="local")  # "local" or "google"

    # 2FA / TOTP fields (Google Authenticator)
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    
    # Relationships
    sessions = db.relationship('Session', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    bank_accounts = db.relationship('BankAccount', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat(),
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'auth_provider': self.auth_provider or 'local',
            'avatar_url': self.avatar_url,
        }
    
    def __repr__(self):
        return f'<User {self.username}>'


class Session(db.Model):
    """Session model for tracking user sessions"""
    __tablename__ = 'sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    token = db.Column(db.String(500), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True, index=True)
    is_suspicious = db.Column(db.Boolean, default=False, index=True)
    anomaly_score = db.Column(db.Float, default=0.0)
    revoked_at = db.Column(db.DateTime)
    revoked_reason = db.Column(db.String(255))
    
    # Relationships
    behavior_logs = db.relationship('BehaviorLog', backref='session', lazy='dynamic', cascade='all, delete-orphan')
    incident_logs = db.relationship('IncidentLog', backref='session', lazy='dynamic', cascade='all, delete-orphan')
    transactions = db.relationship('Transaction', backref='session', lazy='dynamic')
    
    def to_dict(self):
        """Convert session to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'created_at': self.created_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'is_active': self.is_active,
            'is_suspicious': self.is_suspicious,
            'anomaly_score': round(self.anomaly_score, 4),
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
            'revoked_reason': self.revoked_reason
        }
    
    def __repr__(self):
        return f'<Session {self.id} - User {self.user_id}>'


class BehaviorLog(db.Model):
    """Behavior log for tracking user actions"""
    __tablename__ = 'behavior_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('sessions.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    action_type = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(500))
    time_gap = db.Column(db.Float)           # FIX: corrected indentation
    endpoint = db.Column(db.String(255))     # FIX: corrected indentation
    request_method = db.Column(db.String(10))  # FIX: corrected indentation
    fingerprint_data = db.Column(db.Text)    # FIX: corrected indentation

    def to_dict(self):                       # FIX: corrected indentation
        """Convert behavior log to dictionary"""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'timestamp': self.timestamp.isoformat(),
            'action_type': self.action_type,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'time_gap': round(self.time_gap, 2) if self.time_gap else None,
            'endpoint': self.endpoint,
            'request_method': self.request_method,
            'fingerprint_data': self.fingerprint_data
        }

    def __repr__(self):
        return f'<BehaviorLog {self.id} - Session {self.session_id}>'


class IncidentLog(db.Model):
    """Incident log for security events"""
    __tablename__ = 'incident_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('sessions.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    incident_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    anomaly_score = db.Column(db.Float, nullable=False)
    action_taken = db.Column(db.String(100))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    def to_dict(self):
        """Convert incident log to dictionary"""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'timestamp': self.timestamp.isoformat(),
            'incident_type': self.incident_type,
            'severity': self.severity,
            'anomaly_score': round(self.anomaly_score, 4),
            'action_taken': self.action_taken,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'resolved': self.resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }
    
    def __repr__(self):
        return f'<IncidentLog {self.id} - {self.incident_type}>'


# ============================================================================
# BANKING MODELS - Alpha Bank Integration
# ============================================================================

class BankAccount(db.Model):
    """Bank account model for Alpha Bank"""
    __tablename__ = 'bank_accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    account_number = db.Column(db.String(20), unique=True, nullable=False, index=True)
    account_type = db.Column(db.String(20), nullable=False)  # checking, savings
    balance = db.Column(db.Numeric(15, 2), default=0.00, nullable=False)
    currency = db.Column(db.String(3), default='USD')
    status = db.Column(db.String(20), default='active')  # active, frozen, closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_transaction = db.Column(db.DateTime)
    
    # Relationships
    transactions_sent = db.relationship('Transaction', 
                                       foreign_keys='Transaction.from_account_id',
                                       backref='sender_account', 
                                       lazy='dynamic')
    transactions_received = db.relationship('Transaction', 
                                           foreign_keys='Transaction.to_account_id',
                                           backref='receiver_account', 
                                           lazy='dynamic')
    cards = db.relationship('Card', backref='account', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convert account to dictionary"""
        return {
            'id': self.id,
            'account_number': self.account_number,
            'account_type': self.account_type,
            'balance': float(self.balance),
            'currency': self.currency,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'last_transaction': self.last_transaction.isoformat() if self.last_transaction else None
        }
    
    def __repr__(self):
        return f'<BankAccount {self.account_number}>'


class Transaction(db.Model):
    """Transaction model for money transfers and bills"""
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    from_account_id = db.Column(db.Integer, db.ForeignKey('bank_accounts.id'), nullable=False, index=True)
    to_account_id = db.Column(db.Integer, db.ForeignKey('bank_accounts.id'), index=True)
    transaction_type = db.Column(db.String(50), nullable=False)  # transfer, bill_payment, deposit, withdrawal
    amount = db.Column(db.Numeric(15, 2), nullable=False)
    currency = db.Column(db.String(3), default='USD')
    description = db.Column(db.String(255))
    reference_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed, blocked
    blocked_reason = db.Column(db.String(255))  # If blocked by TokenShield
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    session_id = db.Column(db.Integer, db.ForeignKey('sessions.id'), index=True)
    ip_address = db.Column(db.String(45))
    
    # For bill payments
    payee_name = db.Column(db.String(100))
    payee_account = db.Column(db.String(50))
    
    def to_dict(self):
        """Convert transaction to dictionary"""
        return {
            'id': self.id,
            'from_account_id': self.from_account_id,
            'to_account_id': self.to_account_id,
            'transaction_type': self.transaction_type,
            'amount': float(self.amount),
            'currency': self.currency,
            'description': self.description,
            'reference_number': self.reference_number,
            'status': self.status,
            'blocked_reason': self.blocked_reason,
            'timestamp': self.timestamp.isoformat(),
            'payee_name': self.payee_name,
            'payee_account': self.payee_account
        }
    
    def __repr__(self):
        return f'<Transaction {self.reference_number}>'


class Card(db.Model):
    """Card model for credit/debit cards"""
    __tablename__ = 'cards'
    
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('bank_accounts.id'), nullable=False, index=True)
    card_number = db.Column(db.String(19), unique=True, nullable=False)  # Masked: **** **** **** 1234
    card_type = db.Column(db.String(20), nullable=False)  # debit, credit
    card_network = db.Column(db.String(20))  # Visa, Mastercard, Amex
    cardholder_name = db.Column(db.String(100), nullable=False)
    expiry_date = db.Column(db.String(7))  # MM/YYYY
    cvv_hash = db.Column(db.String(255))  # Hashed CVV
    credit_limit = db.Column(db.Numeric(15, 2))  # For credit cards
    status = db.Column(db.String(20), default='active')  # active, blocked, expired
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convert card to dictionary"""
        return {
            'id': self.id,
            'card_number': self.card_number,
            'card_type': self.card_type,
            'card_network': self.card_network,
            'cardholder_name': self.cardholder_name,
            'expiry_date': self.expiry_date,
            'credit_limit': float(self.credit_limit) if self.credit_limit else None,
            'status': self.status,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Card {self.card_number}>'


# Index definitions for performance optimization
db.Index('idx_session_user_active', Session.user_id, Session.is_active)
db.Index('idx_behavior_session_time', BehaviorLog.session_id, BehaviorLog.timestamp)
db.Index('idx_incident_severity_time', IncidentLog.severity, IncidentLog.timestamp)
db.Index('idx_account_user', BankAccount.user_id, BankAccount.status)
db.Index('idx_transaction_account_time', Transaction.from_account_id, Transaction.timestamp)
db.Index('idx_card_account', Card.account_id, Card.status)