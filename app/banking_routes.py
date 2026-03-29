"""
NeoVault Banking Routes
API endpoints for banking operations with TokenShield integration
UPDATED - Compatible with BehaviorLog model
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
from sqlalchemy import desc, or_
from decimal import Decimal
import secrets
from app import db
from app.models import User, Session, BankAccount, Transaction, Card, BehaviorLog, IncidentLog
from app.utils import token_required, get_client_ip

# Create banking blueprint
banking_bp = Blueprint('banking', __name__, url_prefix='/api/banking')


# ============================================================================
# ACCOUNT MANAGEMENT
# ============================================================================

@banking_bp.route('/accounts', methods=['GET'])
@token_required
def get_user_accounts(current_user, current_session):
    """Get all bank accounts for current user"""
    try:
        accounts = BankAccount.query.filter_by(
            user_id=current_user.id
        ).order_by(desc(BankAccount.created_at)).all()
        
        # Log behavior
        log_banking_behavior(current_session.id, 'view_accounts', '/api/banking/accounts')
        
        db.session.commit()  # Commit the behavior log
        
        return jsonify({
            'success': True,
            'accounts': [account.to_dict() for account in accounts]
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Get accounts error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch accounts'
        }), 500


@banking_bp.route('/accounts/<string:account_number>', methods=['GET'])
@token_required
def get_account_details(current_user, current_session, account_number):
    """Get specific account details"""
    try:
        account = BankAccount.query.filter_by(
            account_number=account_number,
            user_id=current_user.id
        ).first()
        
        if not account:
            return jsonify({
                'success': False,
                'message': 'Account not found'
            }), 404
        
        # Log behavior
        log_banking_behavior(current_session.id, 'view_account_details', f'/api/banking/accounts/{account_number}')
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'account': account.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Get account details error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch account details'
        }), 500


@banking_bp.route('/accounts/create', methods=['POST'])
@token_required
def create_account(current_user, current_session):
    """Create a new bank account"""
    try:
        data = request.get_json()
        account_type = data.get('account_type', 'checking')
        initial_balance = Decimal(str(data.get('initial_balance', 0)))
        
        if account_type not in ['checking', 'savings']:
            return jsonify({
                'success': False,
                'message': 'Invalid account type'
            }), 400
        
        # Generate unique account number
        account_number = generate_account_number()
        
        # Create account
        account = BankAccount(
            user_id=current_user.id,
            account_number=account_number,
            account_type=account_type,
            balance=initial_balance,
            currency='USD',
            status='active'
        )
        
        db.session.add(account)
        
        # Log behavior
        log_banking_behavior(current_session.id, 'create_account', '/api/banking/accounts/create')
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Account created successfully',
            'account': account.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Create account error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to create account'
        }), 500


# ============================================================================
# TRANSACTIONS
# ============================================================================

@banking_bp.route('/transactions', methods=['GET'])
@token_required
def get_user_transactions(current_user, current_session):
    """Get transaction history for user's accounts"""
    try:
        limit = request.args.get('limit', 50, type=int)
        account_number = request.args.get('account_number')
        
        # Get user's account IDs
        account_ids = [acc.id for acc in BankAccount.query.filter_by(user_id=current_user.id).all()]
        
        # Build query
        query = Transaction.query.filter(
            or_(
                Transaction.from_account_id.in_(account_ids),
                Transaction.to_account_id.in_(account_ids)
            )
        )
        
        # Filter by specific account if provided
        if account_number:
            account = BankAccount.query.filter_by(
                account_number=account_number,
                user_id=current_user.id
            ).first()
            if account:
                query = query.filter(
                    or_(
                        Transaction.from_account_id == account.id,
                        Transaction.to_account_id == account.id
                    )
                )
        
        transactions = query.order_by(desc(Transaction.timestamp)).limit(limit).all()
        
        # Log behavior
        log_banking_behavior(current_session.id, 'view_transactions', '/api/banking/transactions')
        
        db.session.commit()
        
        # Enrich transaction data
        transactions_data = []
        for trans in transactions:
            trans_dict = trans.to_dict()
            
            # Add account info
            if trans.from_account_id:
                from_acc = BankAccount.query.get(trans.from_account_id)
                trans_dict['from_account_number'] = from_acc.account_number if from_acc else None
            
            if trans.to_account_id:
                to_acc = BankAccount.query.get(trans.to_account_id)
                trans_dict['to_account_number'] = to_acc.account_number if to_acc else None
            
            transactions_data.append(trans_dict)
        
        return jsonify({
            'success': True,
            'transactions': transactions_data,
            'total': len(transactions_data)
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Get transactions error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch transactions'
        }), 500


@banking_bp.route('/transfer', methods=['POST'])
@token_required
def transfer_money(current_user, current_session):
    """
    Transfer money between accounts
    🛡️ CRITICAL: This is protected by TokenShield - suspicious sessions will be blocked
    """
    try:
        data = request.get_json()
        
        from_account_number = data.get('from_account')
        to_account_number = data.get('to_account')
        amount = Decimal(str(data.get('amount')))
        description = data.get('description', 'Money Transfer')
        
        # Validation
        if not from_account_number or not to_account_number or amount <= 0:
            return jsonify({
                'success': False,
                'message': 'Invalid transfer details'
            }), 400
        
        # 🛡️ SECURITY CHECK: Check session anomaly score
        # Default threshold is 0.50 (50%)
        threshold = getattr(current_app.config, 'ANOMALY_THRESHOLD_SUSPICIOUS', 0.50)
        
        if current_session.anomaly_score >= threshold:
            # Log security incident
            incident = IncidentLog(
                session_id=current_session.id,
                incident_type='suspicious_transaction_blocked',
                severity='high',
                anomaly_score=current_session.anomaly_score,
                action_taken='transaction_blocked',
                details=f'Transfer blocked: ${amount} from {from_account_number} to {to_account_number}',
                ip_address=get_client_ip(),
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(incident)
            db.session.commit()
            
            current_app.logger.warning(
                f"🚨 TRANSACTION BLOCKED - User: {current_user.username}, "
                f"Score: {current_session.anomaly_score:.2%}, "
                f"Amount: ${amount}"
            )
            
            return jsonify({
                'success': False,
                'message': 'Transaction blocked for security reasons. Please contact support.',
                'security_alert': True,
                'anomaly_score': current_session.anomaly_score,
                'reason': 'high_risk_session'
            }), 403
        
        # Get accounts
        from_account = BankAccount.query.filter_by(
            account_number=from_account_number,
            user_id=current_user.id,
            status='active'
        ).first()
        
        to_account = BankAccount.query.filter_by(
            account_number=to_account_number,
            status='active'
        ).first()
        
        if not from_account:
            return jsonify({
                'success': False,
                'message': 'Source account not found or inactive'
            }), 404
        
        if not to_account:
            return jsonify({
                'success': False,
                'message': 'Destination account not found or inactive'
            }), 404
        
        # Check sufficient balance
        if from_account.balance < amount:
            return jsonify({
                'success': False,
                'message': 'Insufficient balance'
            }), 400
        
        # Generate reference number
        reference = generate_reference_number()
        
        # Create transaction
        transaction = Transaction(
            from_account_id=from_account.id,
            to_account_id=to_account.id,
            transaction_type='transfer',
            amount=amount,
            currency='USD',
            description=description,
            reference_number=reference,
            status='completed',
            session_id=current_session.id,
            ip_address=get_client_ip()
        )
        
        # Update balances
        from_account.balance -= amount
        from_account.last_transaction = datetime.utcnow()
        
        to_account.balance += amount
        to_account.last_transaction = datetime.utcnow()
        
        db.session.add(transaction)
        
        # Log behavior
        log_banking_behavior(
            current_session.id, 
            'money_transfer', 
            '/api/banking/transfer'
        )
        
        db.session.commit()
        
        current_app.logger.info(
            f"✅ TRANSFER SUCCESS - User: {current_user.username}, "
            f"Amount: ${amount}, Ref: {reference}"
        )
        
        return jsonify({
            'success': True,
            'message': 'Transfer completed successfully',
            'transaction': transaction.to_dict(),
            'new_balance': float(from_account.balance),
            'reference': reference
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Transfer error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Transfer failed. Please try again.'
        }), 500


@banking_bp.route('/pay-bill', methods=['POST'])
@token_required
def pay_bill(current_user, current_session):
    """
    Pay bills from account
    🛡️ CRITICAL: Protected by TokenShield
    """
    try:
        data = request.get_json()
        
        from_account_number = data.get('from_account')
        payee_name = data.get('payee_name')
        payee_account = data.get('payee_account', '')
        amount = Decimal(str(data.get('amount')))
        description = data.get('description', f'Bill Payment - {payee_name}')
        
        # Validation
        if not from_account_number or not payee_name or amount <= 0:
            return jsonify({
                'success': False,
                'message': 'Invalid payment details'
            }), 400
        
        # 🛡️ SECURITY CHECK
        threshold = getattr(current_app.config, 'ANOMALY_THRESHOLD_SUSPICIOUS', 0.50)
        
        if current_session.anomaly_score >= threshold:
            incident = IncidentLog(
                session_id=current_session.id,
                incident_type='suspicious_bill_payment_blocked',
                severity='high',
                anomaly_score=current_session.anomaly_score,
                action_taken='payment_blocked',
                details=f'Bill payment blocked: ${amount} to {payee_name}',
                ip_address=get_client_ip(),
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(incident)
            db.session.commit()
            
            current_app.logger.warning(
                f"🚨 BILL PAYMENT BLOCKED - User: {current_user.username}, "
                f"Score: {current_session.anomaly_score:.2%}, "
                f"Amount: ${amount}, Payee: {payee_name}"
            )
            
            return jsonify({
                'success': False,
                'message': 'Payment blocked for security reasons. Please contact support.',
                'security_alert': True,
                'anomaly_score': current_session.anomaly_score
            }), 403
        
        # Get account
        account = BankAccount.query.filter_by(
            account_number=from_account_number,
            user_id=current_user.id,
            status='active'
        ).first()
        
        if not account:
            return jsonify({
                'success': False,
                'message': 'Account not found or inactive'
            }), 404
        
        # Check balance
        if account.balance < amount:
            return jsonify({
                'success': False,
                'message': 'Insufficient balance'
            }), 400
        
        # Generate reference
        reference = generate_reference_number()
        
        # Create transaction
        transaction = Transaction(
            from_account_id=account.id,
            transaction_type='bill_payment',
            amount=amount,
            currency='USD',
            description=description,
            reference_number=reference,
            status='completed',
            payee_name=payee_name,
            payee_account=payee_account,
            session_id=current_session.id,
            ip_address=get_client_ip()
        )
        
        # Update balance
        account.balance -= amount
        account.last_transaction = datetime.utcnow()
        
        db.session.add(transaction)
        
        # Log behavior
        log_banking_behavior(
            current_session.id,
            'bill_payment',
            '/api/banking/pay-bill'
        )
        
        db.session.commit()
        
        current_app.logger.info(
            f"✅ BILL PAYMENT SUCCESS - User: {current_user.username}, "
            f"Amount: ${amount}, Payee: {payee_name}, Ref: {reference}"
        )
        
        return jsonify({
            'success': True,
            'message': 'Bill paid successfully',
            'transaction': transaction.to_dict(),
            'new_balance': float(account.balance),
            'reference': reference
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Bill payment error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Payment failed. Please try again.'
        }), 500


@banking_bp.route('/deposit', methods=['POST'])
@token_required
def deposit_money(current_user, current_session):
    """Deposit money into account"""
    try:
        data = request.get_json()
        
        to_account_number = data.get('to_account')
        amount = Decimal(str(data.get('amount')))
        description = data.get('description', 'Cash Deposit')
        
        if not to_account_number or amount <= 0:
            return jsonify({
                'success': False,
                'message': 'Invalid deposit details'
            }), 400
        
        # Get account
        account = BankAccount.query.filter_by(
            account_number=to_account_number,
            user_id=current_user.id,
            status='active'
        ).first()
        
        if not account:
            return jsonify({
                'success': False,
                'message': 'Account not found or inactive'
            }), 404
        
        # Generate reference
        reference = generate_reference_number()
        
        # Create transaction
        transaction = Transaction(
            from_account_id=account.id,  # Use same account as source for deposits
            to_account_id=account.id,
            transaction_type='deposit',
            amount=amount,
            currency='USD',
            description=description,
            reference_number=reference,
            status='completed',
            session_id=current_session.id,
            ip_address=get_client_ip()
        )
        
        # Update balance
        account.balance += amount
        account.last_transaction = datetime.utcnow()
        
        db.session.add(transaction)
        
        # Log behavior
        log_banking_behavior(
            current_session.id,
            'deposit',
            '/api/banking/deposit'
        )
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Deposit completed successfully',
            'transaction': transaction.to_dict(),
            'new_balance': float(account.balance),
            'reference': reference
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Deposit error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Deposit failed. Please try again.'
        }), 500


# ============================================================================
# CARDS MANAGEMENT
# ============================================================================

@banking_bp.route('/cards', methods=['GET'])
@token_required
def get_user_cards(current_user, current_session):
    """Get all cards for user's accounts"""
    try:
        # Get user's account IDs
        account_ids = [acc.id for acc in BankAccount.query.filter_by(user_id=current_user.id).all()]
        
        cards = Card.query.filter(Card.account_id.in_(account_ids)).all()
        
        # Log behavior
        log_banking_behavior(current_session.id, 'view_cards', '/api/banking/cards')
        
        db.session.commit()
        
        # Enrich card data with account info
        cards_data = []
        for card in cards:
            card_dict = card.to_dict()
            account = BankAccount.query.get(card.account_id)
            card_dict['account_number'] = account.account_number if account else None
            card_dict['account_type'] = account.account_type if account else None
            cards_data.append(card_dict)
        
        return jsonify({
            'success': True,
            'cards': cards_data
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Get cards error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch cards'
        }), 500


@banking_bp.route('/cards/<int:card_id>/block', methods=['POST'])
@token_required
def block_card(current_user, current_session, card_id):
    """Block a card"""
    try:
        # Get user's account IDs
        account_ids = [acc.id for acc in BankAccount.query.filter_by(user_id=current_user.id).all()]
        
        card = Card.query.filter(
            Card.id == card_id,
            Card.account_id.in_(account_ids)
        ).first()
        
        if not card:
            return jsonify({
                'success': False,
                'message': 'Card not found'
            }), 404
        
        card.status = 'blocked'
        
        # Log behavior
        log_banking_behavior(
            current_session.id, 
            'block_card', 
            f'/api/banking/cards/{card_id}/block'
        )
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Card blocked successfully',
            'card': card.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Block card error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to block card'
        }), 500


@banking_bp.route('/cards/<int:card_id>/unblock', methods=['POST'])
@token_required
def unblock_card(current_user, current_session, card_id):
    """Unblock a card"""
    try:
        # Get user's account IDs
        account_ids = [acc.id for acc in BankAccount.query.filter_by(user_id=current_user.id).all()]
        
        card = Card.query.filter(
            Card.id == card_id,
            Card.account_id.in_(account_ids)
        ).first()
        
        if not card:
            return jsonify({
                'success': False,
                'message': 'Card not found'
            }), 404
        
        card.status = 'active'
        
        # Log behavior
        log_banking_behavior(
            current_session.id,
            'unblock_card',
            f'/api/banking/cards/{card_id}/unblock'
        )
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Card unblocked successfully',
            'card': card.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Unblock card error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to unblock card'
        }), 500


# ============================================================================
# DASHBOARD STATS
# ============================================================================

@banking_bp.route('/dashboard/summary', methods=['GET'])
@token_required
def get_dashboard_summary(current_user, current_session):
    """Get banking dashboard summary"""
    try:
        # Get all accounts
        accounts = BankAccount.query.filter_by(user_id=current_user.id).all()
        
        # Calculate total balance
        total_balance = sum(acc.balance for acc in accounts)
        
        # Get recent transactions (last 10)
        account_ids = [acc.id for acc in accounts]
        recent_transactions = Transaction.query.filter(
            or_(
                Transaction.from_account_id.in_(account_ids),
                Transaction.to_account_id.in_(account_ids)
            )
        ).order_by(desc(Transaction.timestamp)).limit(10).all()
        
        # Get cards count
        cards_count = Card.query.filter(Card.account_id.in_(account_ids)).count()
        active_cards = Card.query.filter(
            Card.account_id.in_(account_ids),
            Card.status == 'active'
        ).count()
        
        # Calculate monthly spending (last 30 days)
        from datetime import timedelta
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        monthly_spending = db.session.query(
            db.func.sum(Transaction.amount)
        ).filter(
            Transaction.from_account_id.in_(account_ids),
            Transaction.timestamp >= thirty_days_ago,
            Transaction.transaction_type.in_(['transfer', 'bill_payment'])
        ).scalar() or Decimal('0')
        
        # Log behavior
        log_banking_behavior(current_session.id, 'view_dashboard', '/api/banking/dashboard/summary')
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'summary': {
                'total_balance': float(total_balance),
                'accounts_count': len(accounts),
                'cards_count': cards_count,
                'active_cards_count': active_cards,
                'recent_transactions_count': len(recent_transactions),
                'monthly_spending': float(monthly_spending),
                'accounts': [acc.to_dict() for acc in accounts],
                'recent_transactions': [trans.to_dict() for trans in recent_transactions]
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Dashboard summary error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch dashboard summary'
        }), 500


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def generate_account_number():
    """Generate unique account number"""
    while True:
        # Format: NVXXXXXX (NV = NeoVault)
        account_number = f"NV{secrets.randbelow(100000000):08d}"
        existing = BankAccount.query.filter_by(account_number=account_number).first()
        if not existing:
            return account_number


def generate_reference_number():
    """Generate unique transaction reference"""
    while True:
        # Format: TXN-TIMESTAMP-RANDOM
        ref = f"TXN{datetime.utcnow().strftime('%Y%m%d%H%M%S')}{secrets.randbelow(10000):04d}"
        existing = Transaction.query.filter_by(reference_number=ref).first()
        if not existing:
            return ref


def log_banking_behavior(session_id, action_type, endpoint):
    """
    Log banking activity for TokenShield monitoring
    Uses BehaviorLog model from your models.py
    """
    try:
        # Get the last behavior log for this session to calculate time gap
        last_behavior = BehaviorLog.query.filter_by(
            session_id=session_id
        ).order_by(desc(BehaviorLog.timestamp)).first()
        
        time_gap = None
        if last_behavior:
            time_gap = (datetime.utcnow() - last_behavior.timestamp).total_seconds()
        
        behavior = BehaviorLog(
            session_id=session_id,
            action_type=action_type,
            ip_address=get_client_ip(),
            user_agent=request.headers.get('User-Agent'),
            endpoint=endpoint,
            request_method=request.method,
            time_gap=time_gap
        )
        db.session.add(behavior)
        # Don't commit here - let the main route handle the commit
    except Exception as e:
        current_app.logger.error(f"Behavior logging error: {str(e)}")