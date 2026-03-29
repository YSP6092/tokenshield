"""
🔥 TOKENSHIELD - REAL-TIME SYNCHRONIZED ATTACK SIMULATION
Everything happens live across all interfaces simultaneously

WHAT HAPPENS:
1. Hacker logs in from Moscow → Admin sees "Unknown Login" alert
2. AI calculates risk score in real-time → Metrics update live
3. Risk reaches 85% → Admin sees RED ALERT
4. User banking page shows "SECURITY ALERT - LOGGING OUT"
5. Session auto-revoked → Both logged out
6. User tries to login → 2FA required
7. Admin sees all actions in real-time

USAGE:
    python scripts/attack_simulation_live.py
    
    Then watch:
    - Banking page: http://localhost:5001/dashboard
    - Admin panel: http://localhost:5001/admin
    - Security dashboard: http://localhost:5001/security-dashboard
"""

import sys
import time
import json
from datetime import datetime, timedelta
from app import db, create_app
from app.models import User, Session, BehaviorLog, IncidentLog
import random

app = create_app()

# Attack scenarios with realistic data
ATTACK_SCENARIOS = {
    'moscow': {
        'location': 'Moscow, Russia',
        'ip': '185.220.101.42',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/96.0.4664.45',
        'time': '03:47 AM',
        'timezone': 'MSK (UTC+3)'
    },
    'beijing': {
        'location': 'Beijing, China',
        'ip': '202.112.51.89',
        'user_agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) Firefox/91.0',
        'time': '02:15 AM',
        'timezone': 'CST (UTC+8)'
    },
    'lagos': {
        'location': 'Lagos, Nigeria',
        'ip': '197.210.55.23',
        'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36',
        'time': '04:32 AM',
        'timezone': 'WAT (UTC+1)'
    }
}

def print_header(text, char="="):
    """Print formatted header"""
    print("\n" + char * 100)
    print(f"  {text}")
    print(char * 100 + "\n")

def print_step(step_num, title, details=None):
    """Print simulation step"""
    print(f"\n{'─' * 100}")
    print(f"STEP {step_num}: {title}")
    print(f"{'─' * 100}")
    if details:
        for detail in details:
            print(f"   {detail}")
    time.sleep(1.5)

def create_attacker_session(user_id, scenario):
    """Create fake attacker session - returns session ID"""
    with app.app_context():
        # Create attacker session
        attacker_session = Session(
            user_id=user_id,
            token='ATTACKER_SESSION_' + str(int(time.time())),
            ip_address=scenario['ip'],
            user_agent=scenario['user_agent'],
            is_active=True,
            is_suspicious=True,
            anomaly_score=0.25  # Starts suspicious
        )
        db.session.add(attacker_session)
        db.session.commit()
        
        session_id = attacker_session.id
        
    return session_id

def simulate_suspicious_behavior(session_id, scenario):
    """Generate suspicious behavior logs - returns final anomaly score"""
    with app.app_context():
        session = Session.query.get(session_id)
        
        suspicious_actions = [
            {'action': 'rapid_page_navigation', 'weight': 0.15, 'desc': '🚨 Rapid page navigation detected'},
            {'action': 'unusual_access_pattern', 'weight': 0.12, 'desc': '⚠️  Accessing pages in unusual order'},
            {'action': 'failed_transaction_attempt', 'weight': 0.18, 'desc': '💰 Multiple transaction attempts'},
            {'action': 'account_enumeration', 'weight': 0.10, 'desc': '👁️  Checking multiple accounts'},
            {'action': 'large_transfer_attempt', 'weight': 0.20, 'desc': '💸 Attempted large transfer ($5,000)'},
        ]
        
        cumulative_score = session.anomaly_score
        
        print("\n🎯 AI BEHAVIOR ANALYSIS IN PROGRESS...")
        print("─" * 100)
        
        for i, action in enumerate(suspicious_actions, 1):
            time.sleep(2)  # Increased to 2 seconds so dashboards can update
            
            # Log behavior
            log = BehaviorLog(
                session_id=session.id,
                action_type=action['action'],
                ip_address=session.ip_address,
                user_agent=session.user_agent,
                endpoint='/banking/dashboard',
                request_method='POST'
            )
            db.session.add(log)
            
            # Increment anomaly score
            cumulative_score += action['weight']
            session.anomaly_score = min(cumulative_score, 0.95)
            
            # Update flags
            if session.anomaly_score >= 0.50:
                session.is_suspicious = True
            
            db.session.commit()
            
            # Display
            bar = "█" * int(session.anomaly_score * 50)
            status = "🟢 SAFE" if session.anomaly_score < 0.3 else "🟡 SUSPICIOUS" if session.anomaly_score < 0.7 else "🔴 CRITICAL"
            
            print(f"   [{i}/5] {action['desc']}")
            print(f"        Risk Score: {session.anomaly_score * 100:.1f}% {bar} {status}")
            print(f"        📊 Check your dashboards NOW - they should update in real-time!")
            
            # Extra pause at critical thresholds
            if session.anomaly_score >= 0.5 and session.anomaly_score < 0.6:
                print(f"        ⏸️  Pausing 3 seconds - WATCH BANKING DASHBOARD for orange notification...")
                time.sleep(3)
            elif session.anomaly_score >= 0.7 and session.anomaly_score < 0.75:
                print(f"        ⏸️  Pausing 3 seconds - WATCH BANKING DASHBOARD for RED banner...")
                time.sleep(3)
        
        print("─" * 100)
        final_score = session.anomaly_score
        
    return final_score

def log_security_incident(session_id, scenario):
    """Log detailed security incident - returns incident ID"""
    with app.app_context():
        session = Session.query.get(session_id)
        
        incident = IncidentLog(
            session_id=session.id,
            incident_type='account_takeover_attempt',
            severity='critical',
            anomaly_score=session.anomaly_score,
            action_taken='session_revoked_auto_logout_2fa_required',
            details=json.dumps({
                'attack_type': 'Account Takeover',
                'origin': scenario['location'],
                'ip_address': scenario['ip'],
                'time': scenario['time'],
                'timezone': scenario['timezone'],
                'device': 'Unknown Windows PC',
                'browser': 'Chrome 96',
                'risk_factors': [
                    'Unusual geographic location',
                    'Login at suspicious hour (3:47 AM)',
                    'New device fingerprint',
                    'Rapid unusual actions',
                    'Large transfer attempt',
                    'Failed authentication patterns'
                ],
                'actions_taken': [
                    'Transaction blocked',
                    'Session immediately revoked',
                    'User logged out automatically',
                    '2FA verification required',
                    'Admin alerted',
                    'Security monitoring increased'
                ],
                'financial_impact': '$0 (Protected)',
                'response_time': '<2 seconds'
            }),
            ip_address=scenario['ip'],
            user_agent=scenario['user_agent']
        )
        db.session.add(incident)
        db.session.commit()
        
        incident_id = incident.id
        
    return incident_id

def revoke_all_sessions(user):
    """Revoke all user sessions"""
    with app.app_context():
        user = User.query.get(user.id)
        sessions = Session.query.filter_by(user_id=user.id, is_active=True).all()
        
        for session in sessions:
            session.is_active = False
            session.revoked_at = datetime.utcnow()
            session.revoked_reason = 'Security incident - suspicious activity detected'
        
        db.session.commit()
        return len(sessions)

def display_live_dashboard_view(session, user, scenario):
    """Show what admin sees on dashboard"""
    print("\n" + "=" * 100)
    print("📺 ADMIN DASHBOARD VIEW (Real-time)")
    print("=" * 100)
    
    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🚨 SECURITY ALERT - SUSPICIOUS SESSION DETECTED                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

👤 USER ACCOUNT
   Username: {user.username}
   Account ID: {user.id}
   Status: ⚠️  UNDER ATTACK

🌍 SUSPICIOUS LOGIN DETECTED
   Location: {scenario['location']}
   IP Address: {scenario['ip']}
   Time: {scenario['time']} {scenario['timezone']}
   Device: Unknown Windows PC (Chrome 96)
   
📊 THREAT METRICS
   Risk Score: {session.anomaly_score * 100:.1f}% {"🔴 CRITICAL" if session.anomaly_score >= 0.7 else "🟡 SUSPICIOUS"}
   Session ID: {session.id}
   Status: {"🔴 ACTIVE THREAT" if session.is_active else "✅ NEUTRALIZED"}
   
🎯 AI ANALYSIS
   ✓ Geographic anomaly detected
   ✓ Unusual time pattern
   ✓ Device fingerprint mismatch
   ✓ Behavioral anomaly confirmed
   ✓ High-risk transaction attempted
   
⚡ AUTOMATED ACTIONS TAKEN
   ✓ Transaction blocked immediately
   ✓ Session revoked automatically
   ✓ User logged out (all devices)
   ✓ 2FA authentication required
   ✓ Security team notified
   ✓ Audit trail logged
   
💰 FINANCIAL PROTECTION
   Amount Attempted: $5,000.00
   Amount Lost: $0.00 ✅
   Protection Rate: 100%
""")
    print("=" * 100)

def display_user_banking_view():
    """Show what user sees on banking page"""
    print("\n" + "=" * 100)
    print("💻 USER BANKING PAGE VIEW (Real-time)")
    print("=" * 100)
    
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🛡️  ALPHA BANK - SECURITY ALERT                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

⚠️  UNUSUAL ACTIVITY DETECTED

We detected unusual activity on your account and have taken steps to protect you.

📍 Detected Activity:
   • Login from Moscow, Russia (3:47 AM)
   • Unrecognized device
   • Attempted large transfer ($5,000)

🛡️  Protection Measures:
   ✓ Suspicious transaction blocked
   ✓ Account temporarily secured
   ✓ All sessions logged out
   
🔐 Next Steps:
   1. You will be redirected to login page
   2. Enter your username and password
   3. Complete 2-Factor Authentication
   4. Review recent activity
   
⏱️  Logging out in 3 seconds...
   
[████████████████████████████████████] 100%

✅ You are now logged out for your security.

""")
    print("=" * 100)

def run_full_simulation():
    """Complete synchronized attack simulation"""
    
    print_header("🔥 TOKENSHIELD LIVE ATTACK SIMULATION", "═")
    
    print("""
This simulation demonstrates real-time threat detection and response across:
  • Banking Website (User interface)
  • Admin Dashboard (Security operations)
  • AI Engine (Threat detection)
  
Everything happens SIMULTANEOUSLY across all interfaces.

🎬 IMPORTANT: OPEN THESE 3 BROWSER WINDOWS NOW:
   1. Security Dashboard: http://localhost:5001/security-dashboard (demo/demo123)
   2. Banking Dashboard:  http://localhost:5001/dashboard (demo/demo123)
   3. Admin Panel:        http://localhost:5001/admin (admin/admin123)

⚡ All dashboards are set to refresh EVERY 1 SECOND for real-time updates!

📺 WHAT TO WATCH FOR:
   Security Dashboard → Threat level will jump 25% → 40% → 55% → 70% → 85%
   Banking Dashboard  → Orange notification at 50%, RED banner at 70%, LOGOUT at 85%
   Admin Panel        → New Moscow session appears, metrics update live
""")
    
    input("✅ Press ENTER after opening all 3 browser windows... ")
    
    # Select scenario
    scenario_name = 'moscow'
    scenario = ATTACK_SCENARIOS[scenario_name]
    
    # Get demo user
    with app.app_context():
        user = User.query.filter_by(username='demo').first()
        if not user:
            print("❌ Demo user not found! Run: python scripts/init_db.py")
            return
        
        user_id = user.id  # Store ID for later use
        
        # Clean up old attacker sessions
        Session.query.filter(Session.token.like('ATTACKER_SESSION%')).delete()
        db.session.commit()
    
    print_header("PHASE 1: ATTACK INITIATED", "─")
    
    print_step(1, "🔓 ATTACKER GAINS UNAUTHORIZED ACCESS", [
        f"• Attacker uses stolen credentials",
        f"• Login from: {scenario['location']}",
        f"• IP: {scenario['ip']}",
        f"• Time: {scenario['time']} {scenario['timezone']}",
        f"• Device: Unknown Windows PC"
    ])
    
    # Create attacker session
    with app.app_context():
        attacker_session_id = create_attacker_session(user_id, scenario)
    
    print("   ✅ Attacker session established")
    print(f"   📊 Initial Risk Score: 25.0% (Elevated)")
    
    print_step(2, "👁️  TOKENSHIELD AI DETECTION ENGINE ACTIVATED", [
        "• Real-time behavior monitoring initiated",
        "• Analyzing access patterns",
        "• Comparing against user baseline",
        "• Geographic location analysis",
        "• Device fingerprinting"
    ])
    
    print_header("PHASE 2: REAL-TIME THREAT ANALYSIS", "─")
    
    # Simulate suspicious behavior
    final_score = simulate_suspicious_behavior(attacker_session_id, scenario)
    
    print_step(3, "🚨 CRITICAL THREAT LEVEL REACHED", [
        f"• Risk Score: {final_score * 100:.1f}% 🔴 CRITICAL",
        "• Multiple risk factors confirmed",
        "• Immediate action required",
        "• Automated response triggered"
    ])
    
    print_header("PHASE 3: AUTOMATED PROTECTION RESPONSE", "─")
    
    print_step(4, "💰 TRANSACTION BLOCK", [
        "• Attempted Transfer: $5,000.00",
        "• Destination: Suspicious offshore account",
        "• ⛔ TRANSACTION DENIED",
        "• Reason: Anomaly score exceeds threshold (50%)",
        "• Amount Protected: $5,000.00 ✅"
    ])
    
    # Log incident
    incident_id = log_security_incident(attacker_session_id, scenario)
    
    print_step(5, "📝 SECURITY INCIDENT LOGGED", [
        f"• Incident ID: {incident_id}",
        "• Type: Account Takeover Attempt",
        "• Severity: CRITICAL",
        "• Status: Neutralized",
        f"• Response Time: <2 seconds",
        "• Audit trail created"
    ])
    
    print_step(6, "⚠️  ALL SESSIONS REVOKED", [
        "• Legitimate user session: Logged out",
        "• Attacker session: Terminated",
        "• All devices disconnected",
        "• Account temporarily locked"
    ])
    
    # Revoke sessions
    with app.app_context():
        user = User.query.get(user_id)
        revoked_count = revoke_all_sessions(user)
    
    print(f"   ✅ {revoked_count} session(s) revoked")
    
    print_header("PHASE 4: USER NOTIFICATION & RE-AUTHENTICATION", "─")
    
    print_step(7, "🔐 2FA AUTHENTICATION REQUIRED", [
        "• User must verify identity",
        "• SMS/Email code sent",
        "• Additional security layer activated",
        "• Account access restricted until verified"
    ])
    
    # Display what each interface shows
    time.sleep(2)
    print_header("LIVE INTERFACE VIEWS", "═")
    
    with app.app_context():
        attacker_session = Session.query.get(attacker_session_id)
        user = User.query.get(user_id)
        
        display_live_dashboard_view(attacker_session, user, scenario)
        time.sleep(2)
        display_user_banking_view()
    
    print_header("SIMULATION COMPLETE", "═")
    
    # Results summary
    print("""
🎯 ATTACK SIMULATION RESULTS

✅ THREAT NEUTRALIZED SUCCESSFULLY

Protection Metrics:
  • Detection Time: <2 seconds
  • Response Time: <2 seconds  
  • Financial Loss: $0.00
  • Success Rate: 100%

Actions Taken:
  ✓ Suspicious login detected
  ✓ Real-time threat analysis
  ✓ Transaction blocked
  ✓ Sessions revoked (attacker + user)
  ✓ User logged out automatically
  ✓ 2FA required for re-authentication
  ✓ Admin notified
  ✓ Incident logged
  ✓ Audit trail created

Impact:
  • Customer Account: Protected ✅
  • Customer Funds: Secure ✅
  • Bank Reputation: Maintained ✅
  • Regulatory Compliance: Met ✅
""")
    
    print_header("NEXT STEPS FOR DEMONSTRATION", "─")
    
    print("""
📋 HOW TO VIEW THE RESULTS:

1️⃣  ADMIN DASHBOARD (Security Operations Center)
   URL: http://localhost:5001/admin
   Login: admin / admin123
   
   What you'll see:
   • Red alert banner at top
   • Suspicious session in "Active Sessions" tab (highlighted)
   • Critical incident in "Incidents" tab
   • Risk score: 85% (RED)
   • All automated actions logged
   • Real-time threat timeline

2️⃣  USER BANKING PAGE (Auto-logged out)
   URL: http://localhost:5001/dashboard
   
   What you'll see:
   • "Session expired due to security reasons"
   • Redirect to login page
   • Security alert message visible

3️⃣  RE-LOGIN WITH 2FA
   URL: http://localhost:5001/login
   Login: demo / demo123
   
   What you'll see:
   • Normal login form
   • After credentials: 2FA modal appears
   • "Enter 6-digit code from your device"
   • Code input field
   • (For demo: any 6-digit code works, e.g., 123456)
   • After 2FA: Access restored

4️⃣  SECURITY DASHBOARD (User's Security Status)
   URL: http://localhost:5001/security-dashboard
   
   What you'll see:
   • Threat level: 85% (RED)
   • "Recent Security Event" notice
   • Incident details
   • Protection measures taken
   • Session history with revoked session

5️⃣  INCIDENT DETAILS (Admin View)
   URL: http://localhost:5001/admin → Incidents tab
   
   What you'll see:
   • Full incident report
   • Timeline of events
   • Risk factors identified
   • Actions taken
   • JSON details with all metadata
""")
    
    print_header("RESET FOR NEXT DEMO", "─")
    
    print("""
To reset and run again:

    python scripts/reset_demo.py

This will:
• Clear all incidents
• Reset threat scores
• Restore normal sessions
• Prepare for next demonstration
""")
    
    print("=" * 100)
    print("✅ Simulation completed successfully!")
    print("=" * 100)
    print()

def main():
    """Main execution"""
    try:
        run_full_simulation()
    except KeyboardInterrupt:
        print("\n\n❌ Simulation interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()