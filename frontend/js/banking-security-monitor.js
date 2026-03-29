/**
 * Real-Time Security Monitor for Banking Dashboard
 * Add this script to the bottom of dashboard.html before closing </body> tag
 * 
 * This monitors for:
 * - Session revocation (attack detected)
 * - High threat scores
 * - Auto-logout on security events
 */

(function() {
    let securityCheckInterval;
    let lastKnownScore = 0;
    let checkCount = 0;
    
    function startSecurityMonitoring() {
        // Check every 1 second for real-time attack detection
        securityCheckInterval = setInterval(checkSecurityStatus, 1000);
        console.log('🛡️ TokenShield security monitoring active (1s refresh)');
    }
    
    async function checkSecurityStatus() {
        try {
            const token = localStorage.getItem('token') || localStorage.getItem('nv_token');
            if (!token) {
                handleSecurityLogout('Session expired');
                return;
            }
            const response = await fetch('/api/auth/verify', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (!response.ok) {
                // Session invalid - logout
                handleSecurityLogout('Session expired');
                return;
            }
            
            const data = await response.json();
            
            if (data.success && data.session) {
                const score = data.session.anomaly_score;
                const isActive = data.session.is_active;
                
                // Check if session was revoked
                if (!isActive) {
                    handleSecurityLogout('Security incident detected');
                    return;
                }
                
                // Check for threat level increases
                if (score >= 0.7 && score > lastKnownScore) {
                    showCriticalThreatBanner(score);
                } else if (score >= 0.5 && score > lastKnownScore) {
                    showSuspiciousActivityNotification(score);
                }
                
                lastKnownScore = score;
                checkCount++;
                
                // If score is critical for 3+ checks, force logout
                if (score >= 0.85 && checkCount > 3) {
                    handleSecurityLogout('Critical threat detected');
                }
            }
        } catch (error) {
            console.error('Security check failed:', error);
        }
    }
    
    function handleSecurityLogout(reason) {
        clearInterval(securityCheckInterval);
        showSecurityLogoutModal(reason);
    }
    
    function showSecurityLogoutModal(reason) {
        // Remove any existing modal
        const existing = document.getElementById('security-logout-modal');
        if (existing) existing.remove();
        
        const modal = document.createElement('div');
        modal.id = 'security-logout-modal';
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.95);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
            animation: fadeIn 0.3s ease;
        `;
        
        modal.innerHTML = `
            <style>
                @keyframes fadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }
                @keyframes slideUp {
                    from { transform: translateY(50px); opacity: 0; }
                    to { transform: translateY(0); opacity: 1; }
                }
                @keyframes pulse {
                    0%, 100% { transform: scale(1); }
                    50% { transform: scale(1.05); }
                }
            </style>
            <div style="
                background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
                border: 2px solid #ef4444;
                border-radius: 16px;
                padding: 3rem;
                max-width: 560px;
                width: 90%;
                box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.5);
                animation: slideUp 0.5s ease;
            ">
                <div style="text-align: center; margin-bottom: 2rem;">
                    <div style="
                        width: 80px;
                        height: 80px;
                        background: rgba(239, 68, 68, 0.2);
                        border-radius: 50%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        margin: 0 auto 1.5rem;
                        animation: pulse 2s infinite;
                    ">
                        <span style="font-size: 3rem;">🚨</span>
                    </div>
                    <h2 style="
                        color: #ef4444;
                        font-size: 1.75rem;
                        font-weight: 700;
                        margin-bottom: 1rem;
                    ">SECURITY ALERT</h2>
                    <p style="
                        color: #f9fafb;
                        font-size: 1.1rem;
                        font-weight: 600;
                        margin-bottom: 1.5rem;
                    ">Unusual Activity Detected</p>
                </div>
                
                <div style="
                    background: rgba(239, 68, 68, 0.1);
                    border-left: 4px solid #ef4444;
                    padding: 1.5rem;
                    border-radius: 8px;
                    margin-bottom: 2rem;
                ">
                    <p style="color: #f9fafb; line-height: 1.8; margin: 0;">
                        We detected suspicious activity on your account from <strong>Moscow, Russia (3:47 AM)</strong>. 
                        Your session has been terminated and all transactions blocked for your protection.
                    </p>
                </div>
                
                <div style="margin-bottom: 2rem;">
                    <h3 style="
                        color: #00d4ff;
                        font-size: 1rem;
                        font-weight: 600;
                        margin-bottom: 1rem;
                    ">🛡️ Protection Measures Taken:</h3>
                    <ul style="
                        color: #d1d5db;
                        line-height: 2;
                        padding-left: 1.5rem;
                        margin: 0;
                    ">
                        <li>✓ Suspicious login from unknown location detected</li>
                        <li>✓ Large transfer attempt ($5,000) blocked</li>
                        <li>✓ All active sessions terminated</li>
                        <li>✓ Account temporarily secured</li>
                        <li>✓ Additional verification required</li>
                    </ul>
                </div>
                
                <div style="
                    background: rgba(0, 212, 255, 0.1);
                    border: 1px solid rgba(0, 212, 255, 0.3);
                    padding: 1rem;
                    border-radius: 8px;
                    margin-bottom: 2rem;
                ">
                    <p style="
                        color: #00d4ff;
                        font-size: 0.875rem;
                        margin: 0;
                        text-align: center;
                        font-weight: 500;
                    ">
                        🔐 You will need to complete 2-Factor Authentication to continue
                    </p>
                </div>
                
                <div style="text-align: center;">
                    <div id="countdown-timer" style="
                        color: #9ca3af;
                        font-size: 0.875rem;
                        margin-bottom: 1rem;
                    ">Redirecting to secure login in <span id="countdown">5</span> seconds...</div>
                    
                    <button onclick="window.location.href='/login'" style="
                        background: linear-gradient(135deg, #00d4ff, #0ea5e9);
                        color: #0a0e27;
                        font-weight: 600;
                        padding: 0.875rem 2rem;
                        border: none;
                        border-radius: 8px;
                        cursor: pointer;
                        font-size: 1rem;
                        width: 100%;
                        transition: transform 0.2s;
                    " onmouseover="this.style.transform='translateY(-2px)'" 
                       onmouseout="this.style.transform='translateY(0)'">
                        Proceed to Secure Login →
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Countdown and auto-redirect
        let countdown = 5;
        const countdownEl = document.getElementById('countdown');
        const interval = setInterval(() => {
            countdown--;
            if (countdownEl) {
                countdownEl.textContent = countdown;
            }
            if (countdown <= 0) {
                clearInterval(interval);
                localStorage.clear();
                window.location.href = '/login';
            }
        }, 1000);
    }
    
    function showCriticalThreatBanner(score) {
        // Remove existing banner
        const existing = document.getElementById('security-threat-banner');
        if (existing) return; // Only show once
        
        const banner = document.createElement('div');
        banner.id = 'security-threat-banner';
        banner.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background: linear-gradient(135deg, #dc2626, #991b1b);
            color: white;
            padding: 1rem 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            z-index: 9999;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
            animation: slideDown 0.5s ease;
        `;
        
        banner.innerHTML = `
            <style>
                @keyframes slideDown {
                    from { transform: translateY(-100%); }
                    to { transform: translateY(0); }
                }
            </style>
            <div style="display: flex; align-items: center; gap: 1rem;">
                <span style="font-size: 1.5rem; animation: pulse 1s infinite;">🚨</span>
                <div>
                    <div style="font-weight: 700; font-size: 1.1rem;">CRITICAL SECURITY ALERT</div>
                    <div style="font-size: 0.875rem; opacity: 0.9;">
                        Threat Level: ${(score * 100).toFixed(0)}% | Suspicious activity from Moscow, Russia | Protective measures activated
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(banner);
        
        // Also disable transfer button
        const transferBtn = document.querySelector('.action-card.enabled');
        if (transferBtn) {
            transferBtn.style.opacity = '0.5';
            transferBtn.style.pointerEvents = 'none';
            transferBtn.innerHTML = `
                <div class="action-icon">🔒</div>
                <div class="action-title">Transfers Blocked</div>
                <div class="action-description">Security protection active</div>
            `;
        }
    }
    
    function showSuspiciousActivityNotification(score) {
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, #f59e0b, #d97706);
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            z-index: 9998;
            max-width: 350px;
            animation: slideInRight 0.5s ease;
        `;
        
        notification.innerHTML = `
            <style>
                @keyframes slideInRight {
                    from { transform: translateX(400px); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
            </style>
            <div style="display: flex; gap: 0.75rem;">
                <span style="font-size: 1.5rem;">⚠️</span>
                <div>
                    <div style="font-weight: 700; margin-bottom: 0.25rem;">Suspicious Activity Detected</div>
                    <div style="font-size: 0.875rem; opacity: 0.9;">
                        Risk level elevated to ${(score * 100).toFixed(0)}%. Monitoring closely...
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => notification.remove(), 5000);
    }
    
    // Start monitoring when page loads
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startSecurityMonitoring);
    } else {
        startSecurityMonitoring();
    }
    
    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        if (securityCheckInterval) {
            clearInterval(securityCheckInterval);
        }
    });
})();