/**
 * TOKENSHIELD API CLIENT
 * Complete API wrapper with 2FA authentication support
 * Professional, production-ready implementation
 */

(function(window) {
    'use strict';

    const API_BASE_URL = window.location.origin;

    /**
     * Main API Client Class
     */
    class TokenShieldAPI {
        constructor() {
            // Some pages use `nv_token`/`nv_user` (older naming), others use `token`/`user`.
            // Support both so admin/security dashboards work after login.
            const storedToken = localStorage.getItem('token') || localStorage.getItem('nv_token');
            const storedUserRaw = localStorage.getItem('user') || localStorage.getItem('nv_user');
            this.token = storedToken;
            this.user = JSON.parse(storedUserRaw || 'null');
        }

        /**
         * Generic request handler
         */
        async request(endpoint, options = {}) {
            const config = {
                method: options.method || 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                }
            };

            if (this.token && !options.skipAuth) {
                config.headers['Authorization'] = `Bearer ${this.token}`;
            }

            if (options.body) {
                config.body = typeof options.body === 'string' 
                    ? options.body 
                    : JSON.stringify(options.body);
            }

            try {
                const response = await fetch(`${API_BASE_URL}${endpoint}`, config);
                const data = await response.json();

                return {
                    success: response.ok,
                    status: response.status,
                    data: data
                };
            } catch (error) {
                console.error('API Request Error:', error);
                return {
                    success: false,
                    error: error.message
                };
            }
        }

        // ====================================================================
        // AUTHENTICATION
        // ====================================================================

        async login(username, password) {
            const result = await this.request('/api/auth/login', {
                method: 'POST',
                skipAuth: true,
                body: { username, password }
            });

            if (result.success && result.data.success) {
                this.token = result.data.token;
                this.user = result.data.user;
                localStorage.setItem('token', this.token);
                localStorage.setItem('user', JSON.stringify(this.user));
                localStorage.setItem('nv_token', this.token);
                localStorage.setItem('nv_user', JSON.stringify(this.user));
            }

            return result;
        }

        async loginWith2FA(username, password, twoFactorCode) {
            const result = await this.request('/api/auth/login-2fa', {
                method: 'POST',
                skipAuth: true,
                body: { username, password, two_factor_code: twoFactorCode }
            });

            if (result.success && result.data.success) {
                this.token = result.data.token;
                this.user = result.data.user;
                localStorage.setItem('token', this.token);
                localStorage.setItem('user', JSON.stringify(this.user));
                localStorage.setItem('nv_token', this.token);
                localStorage.setItem('nv_user', JSON.stringify(this.user));
            }

            return result;
        }

        async register(username, email, password) {
            return await this.request('/api/auth/register', {
                method: 'POST',
                skipAuth: true,
                body: { username, email, password }
            });
        }

        async logout() {
            const result = await this.request('/api/auth/logout', {
                method: 'POST'
            });

            this.token = null;
            this.user = null;
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            localStorage.removeItem('nv_token');
            localStorage.removeItem('nv_user');

            return result;
        }

        getUser() {
            return this.user;
        }

        isAuthenticated() {
            return !!this.token && !!this.user;
        }

        isAdmin() {
            return this.user && this.user.is_admin === true;
        }

        // ====================================================================
        // BANKING
        // ====================================================================

        async getAccounts() {
            return await this.request('/api/banking/accounts');
        }

        async createAccount(accountType, initialBalance = 0) {
            return await this.request('/api/banking/accounts/create', {
                method: 'POST',
                body: {
                    account_type: accountType,
                    initial_balance: initialBalance
                }
            });
        }

        async getTransactions(limit = 50) {
            return await this.request(`/api/banking/transactions?limit=${limit}`);
        }

        async transfer(fromAccount, toAccount, amount, description = 'Transfer') {
            return await this.request('/api/banking/transfer', {
                method: 'POST',
                body: {
                    from_account: fromAccount,
                    to_account: toAccount,
                    amount: amount,
                    description: description
                }
            });
        }

        async getCards() {
            return await this.request('/api/banking/cards');
        }

        // ====================================================================
        // SECURITY
        // ====================================================================

        async getDashboardStats() {
            return await this.request('/api/dashboard/stats');
        }

        async getRecentActivity(limit = 20) {
            return await this.request(`/api/dashboard/recent-activity?limit=${limit}`);
        }

        async getUserSessions() {
            return await this.request('/api/auth/sessions');
        }

        async revokeSession(sessionId) {
            return await this.request(`/api/auth/sessions/${sessionId}/revoke`, {
                method: 'POST'
            });
        }

        // ====================================================================
        // ADMIN
        // ====================================================================

        async getAdminStats() {
            return await this.request('/api/admin/stats');
        }

        async getAdminSessions(activeOnly = true, suspiciousOnly = false) {
            const params = new URLSearchParams({
                active_only: activeOnly.toString(),
                suspicious_only: suspiciousOnly.toString()
            });
            return await this.request(`/api/admin/sessions?${params}`);
        }

        async adminRevokeSession(sessionId, reason = '') {
            return await this.request(`/api/admin/sessions/${sessionId}/revoke`, {
                method: 'POST',
                body: { reason }
            });
        }

        async getIncidents(severity = null, days = 7) {
            const params = new URLSearchParams({ days: days.toString() });
            if (severity) {
                params.append('severity', severity);
            }
            return await this.request(`/api/admin/incidents?${params}`);
        }

        async getUsers() {
            return await this.request('/api/admin/users');
        }
    }

    /**
     * Utility Functions
     */
    const Utils = {
        formatCurrency(amount, currency = 'USD') {
            const num = typeof amount === 'string' ? parseFloat(amount) : amount;
            return new Intl.NumberFormat('en-US', {
                style: 'currency',
                currency: currency,
                minimumFractionDigits: 2,
                maximumFractionDigits: 2
            }).format(num);
        },

        formatDateTime(dateString) {
            const date = new Date(dateString);
            return new Intl.DateTimeFormat('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            }).format(date);
        },

        formatRelativeTime(dateString) {
            const date = new Date(dateString);
            const now = new Date();
            const diffInSeconds = Math.floor((now - date) / 1000);

            if (diffInSeconds < 60) return 'Just now';
            if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
            if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
            if (diffInSeconds < 604800) return `${Math.floor(diffInSeconds / 86400)}d ago`;

            return this.formatDateTime(dateString);
        },

        getSeverityBadge(score) {
            if (score < 0.3) return 'badge-success';
            if (score < 0.5) return 'badge-primary';
            if (score < 0.7) return 'badge-warning';
            return 'badge-danger';
        },

        showToast(message, type = 'success') {
            document.querySelectorAll('.toast').forEach(t => t.remove());

            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.textContent = message;

            document.body.appendChild(toast);

            setTimeout(() => {
                toast.style.animation = 'fadeOut 0.3s ease';
                setTimeout(() => toast.remove(), 300);
            }, 3000);
        },

        confirm(message) {
            return window.confirm(message);
        }
    };

    function requireAuth() {
        const token = localStorage.getItem('token') || localStorage.getItem('nv_token');
        if (!token) {
            window.location.href = '/login';
            return false;
        }
        return true;
    }

    function requireAdmin() {
        const userRaw = localStorage.getItem('user') || localStorage.getItem('nv_user');
        const user = JSON.parse(userRaw || 'null');
        if (!user || !user.is_admin) {
            Utils.showToast('Admin access required', 'error');
            window.location.href = '/dashboard';
            return false;
        }
        return true;
    }

    window.TokenShield = {
        api: new TokenShieldAPI(),
        Utils: Utils,
        requireAuth: requireAuth,
        requireAdmin: requireAdmin
    };

    if (!document.querySelector('style[data-tokenshield-animations]')) {
        const style = document.createElement('style');
        style.setAttribute('data-tokenshield-animations', '');
        style.textContent = `
            @keyframes fadeOut {
                from { opacity: 1; transform: translateX(0); }
                to { opacity: 0; transform: translateX(100px); }
            }
        `;
        document.head.appendChild(style);
    }

})(window);