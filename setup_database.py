"""
NeoVault + TokenShield Setup Script
Initializes database, creates tables, and loads demo data
"""

from app import create_app, db
from app.models import User, BankAccount, Transaction, Card, Session
from decimal import Decimal
from datetime import datetime, timedelta
import random

def setup_database():
    """Initialize database and create all tables"""
    app = create_app()
    
    with app.app_context():
        print("🗄️  Creating database tables...")
        db.create_all()
        print("✅ All tables created successfully!\n")
        
        # Check if demo data already exists
        existing_user = User.query.filter_by(username='demo').first()
        if existing_user:
            print("⚠️  Demo data already exists. Skipping...")
            return
        
        print("📊 Creating demo data...\n")
        create_demo_data()
        
        print("\n✅ Setup complete!")
        print("\n" + "="*60)
        print("🎉 NeoVault + TokenShield is ready!")
        print("="*60)
        print("\n📝 Demo Accounts:")
        print("   Regular User:")
        print("   - Username: demo")
        print("   - Password: demo123")
        print("   - Has: 2 bank accounts, 1 card")
        print("\n   Admin User:")
        print("   - Username: admin")
        print("   - Password: admin123")
        print("   - Has: Full admin access")
        print("\n🌐 Access URLs:")
        print("   - Landing Page: http://localhost:5000/")
        print("   - Login: http://localhost:5000/login")
        print("   - Banking Dashboard: http://localhost:5000/dashboard")
        print("   - Security Dashboard: http://localhost:5000/security-dashboard")
        print("   - Admin Panel: http://localhost:5000/admin")
        print("="*60 + "\n")


def create_demo_data():
    """Create demo users and banking data"""
    
    # 1. Create Admin User
    print("👤 Creating admin user...")
    admin = User(
        username='admin',
        email='admin@neovault.com',
        is_admin=True,
        is_active=True
    )
    admin.set_password('admin123')
    db.session.add(admin)
    
    # 2. Create Demo User
    print("👤 Creating demo user...")
    demo = User(
        username='demo',
        email='demo@neovault.com',
        is_admin=False,
        is_active=True
    )
    demo.set_password('demo123')
    db.session.add(demo)
    
    # 3. Create Additional Test Users
    print("👤 Creating additional test users...")
    users = []
    for i in range(1, 4):
        user = User(
            username=f'user{i}',
            email=f'user{i}@neovault.com',
            is_admin=False,
            is_active=True
        )
        user.set_password('test123')
        users.append(user)
        db.session.add(user)
    
    db.session.commit()
    print("✅ Users created")
    
    # 4. Create Bank Accounts for Demo User
    print("🏦 Creating bank accounts...")
    
    checking = BankAccount(
        user_id=demo.id,
        account_number='NV12345678',
        account_type='checking',
        balance=Decimal('5420.50'),
        currency='USD',
        status='active'
    )
    db.session.add(checking)
    
    savings = BankAccount(
        user_id=demo.id,
        account_number='NV87654321',
        account_type='savings',
        balance=Decimal('18750.00'),
        currency='USD',
        status='active'
    )
    db.session.add(savings)
    
    # Admin accounts
    admin_checking = BankAccount(
        user_id=admin.id,
        account_number='NV11111111',
        account_type='checking',
        balance=Decimal('10000.00'),
        currency='USD',
        status='active'
    )
    db.session.add(admin_checking)
    
    # Test user accounts
    for i, user in enumerate(users):
        account = BankAccount(
            user_id=user.id,
            account_number=f'NV{20000000 + i}',
            account_type='checking',
            balance=Decimal(str(random.randint(1000, 50000))),
            currency='USD',
            status='active'
        )
        db.session.add(account)
    
    db.session.commit()
    print("✅ Bank accounts created")
    
    # 5. Create Sample Transactions
    print("💸 Creating sample transactions...")
    
    transactions_data = [
        {
            'from_account': checking,
            'description': 'Grocery Store',
            'amount': Decimal('87.50'),
            'type': 'bill_payment',
            'days_ago': 1
        },
        {
            'from_account': checking,
            'description': 'Electric Bill',
            'amount': Decimal('125.00'),
            'type': 'bill_payment',
            'days_ago': 3
        },
        {
            'from_account': savings,
            'to_account': checking,
            'description': 'Transfer to Checking',
            'amount': Decimal('500.00'),
            'type': 'transfer',
            'days_ago': 5
        },
        {
            'from_account': checking,
            'description': 'Netflix Subscription',
            'amount': Decimal('15.99'),
            'type': 'bill_payment',
            'days_ago': 7
        },
        {
            'from_account': checking,
            'description': 'Amazon Purchase',
            'amount': Decimal('234.99'),
            'type': 'bill_payment',
            'days_ago': 10
        },
        {
            'from_account': savings,
            'description': 'Salary Deposit',
            'amount': Decimal('3500.00'),
            'type': 'deposit',
            'days_ago': 15
        },
    ]
    
    for trans_data in transactions_data:
        ref_num = f"TXN{datetime.utcnow().strftime('%Y%m%d')}{random.randint(1000, 9999)}"
        timestamp = datetime.utcnow() - timedelta(days=trans_data['days_ago'])
        
        transaction = Transaction(
            from_account_id=trans_data['from_account'].id,
            to_account_id=trans_data.get('to_account').id if trans_data.get('to_account') else None,
            transaction_type=trans_data['type'],
            amount=trans_data['amount'],
            currency='USD',
            description=trans_data['description'],
            reference_number=ref_num,
            status='completed',
            timestamp=timestamp,
            ip_address='127.0.0.1'
        )
        db.session.add(transaction)
        
        # Update account balances based on transaction type
        if trans_data['type'] in ['bill_payment', 'withdrawal']:
            trans_data['from_account'].balance -= trans_data['amount']
            trans_data['from_account'].last_transaction = timestamp
        elif trans_data['type'] == 'deposit':
            trans_data['from_account'].balance += trans_data['amount']
            trans_data['from_account'].last_transaction = timestamp
        elif trans_data['type'] == 'transfer' and trans_data.get('to_account'):
            trans_data['from_account'].balance -= trans_data['amount']
            trans_data['to_account'].balance += trans_data['amount']
            trans_data['from_account'].last_transaction = timestamp
            trans_data['to_account'].last_transaction = timestamp
    
    db.session.commit()
    print("✅ Sample transactions created")
    
    # 6. Create Cards
    print("💳 Creating cards...")
    
    debit_card = Card(
        account_id=checking.id,
        card_number='**** **** **** 1234',
        card_type='debit',
        card_network='Visa',
        cardholder_name=demo.username.upper(),
        expiry_date='12/2028',
        status='active'
    )
    db.session.add(debit_card)
    
    credit_card = Card(
        account_id=savings.id,
        card_number='**** **** **** 5678',
        card_type='credit',
        card_network='Mastercard',
        cardholder_name=demo.username.upper(),
        expiry_date='06/2027',
        credit_limit=Decimal('5000.00'),
        status='active'
    )
    db.session.add(credit_card)
    
    db.session.commit()
    print("✅ Cards created")
    
    print("\n✅ Demo data creation complete!")


def reset_database():
    """⚠️ WARNING: Drops all tables and recreates them"""
    app = create_app()
    
    with app.app_context():
        print("⚠️  WARNING: This will delete ALL data!")
        confirm = input("Type 'RESET' to confirm: ")
        
        if confirm == 'RESET':
            print("🗑️  Dropping all tables...")
            db.drop_all()
            print("✅ Tables dropped")
            
            print("🗄️  Recreating tables...")
            db.create_all()
            print("✅ Tables created")
            
            print("📊 Creating demo data...")
            create_demo_data()
            
            print("\n✅ Database reset complete!")
        else:
            print("❌ Reset cancelled")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--reset':
        reset_database()
    else:
        setup_database()