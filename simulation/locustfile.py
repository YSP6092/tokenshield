"""
TokenShield — Locust Load Test Definition
==========================================
Defines two user classes for Locust:
  - NormalBankingUser  : simulates legitimate account holders browsing NeoVault
  - AttackerUser       : simulates the attacker running rapid malicious requests

Run from the project root:
    locust -f simulation/locustfile.py --host=http://localhost:5001

Then open http://localhost:8089 to start the test from the Locust UI.

Recommended settings for the demonstration:
    Normal users : 3  (spawn rate 1/s)
    Attacker     : 1  (spawn rate 1/s)

Both user classes auto-register and login on startup so no manual setup
is required.  Credentials are generated per-worker to avoid collisions.
"""

import random
import string
import logging

from locust import HttpUser, task, between, events

log = logging.getLogger("locust.tokenshield")


# ─── Helper ───────────────────────────────────────────────────────────────────

def random_suffix(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ─── Normal Banking User ──────────────────────────────────────────────────────

class NormalBankingUser(HttpUser):
    """
    Simulates a legitimate NeoVault customer.
    Performs realistic banking operations with human-like wait times.
    """

    # Wait 3–12 seconds between tasks (realistic human browsing pace)
    wait_time = between(3, 12)

    # Shared across all instances — set on_start
    token    = None
    accounts = []

    def on_start(self):
        """Register + login once when the virtual user spawns."""
        suffix   = random_suffix()
        username = f"user_{suffix}"
        email    = f"{username}@sim.local"
        password = "Sim@12345"

        # Register (ignore 409 if already exists)
        self.client.post("/api/auth/register", json={
            "username": username,
            "email":    email,
            "password": password,
        }, name="/api/auth/register")

        # Login
        r = self.client.post("/api/auth/login", json={
            "username": username,
            "password": password,
        }, name="/api/auth/login")

        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                self.token    = data["token"]
                self.username = username
                self.password = password
                self._ensure_accounts()
                log.info("Normal user %s logged in", username)
        elif r.status_code == 403 and r.json().get("requires_2fa"):
            log.warning("User %s requires 2FA (was attacked). Skipping.", username)
            self.token = None

    def _auth_headers(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _ensure_accounts(self):
        """Create bank accounts if this user has none."""
        r = self.client.get("/api/banking/accounts",
                            headers=self._auth_headers(),
                            name="/api/banking/accounts")
        if r.status_code == 200:
            self.accounts = r.json().get("accounts", [])
        if len(self.accounts) < 2:
            for acct_type in ("checking", "savings"):
                cr = self.client.post(
                    "/api/banking/accounts/create",
                    json={"account_type": acct_type, "initial_balance": 500},
                    headers=self._auth_headers(),
                    name="/api/banking/accounts/create",
                )
                if cr.status_code == 201:
                    self.accounts.append(cr.json().get("account", {}))

    # ── Tasks ─────────────────────────────────────────────────────────────────

    @task(5)
    def view_dashboard(self):
        if not self.token:
            return
        self.client.get("/api/dashboard/stats",
                        headers=self._auth_headers(),
                        name="/api/dashboard/stats")

    @task(5)
    def view_accounts(self):
        if not self.token:
            return
        r = self.client.get("/api/banking/accounts",
                            headers=self._auth_headers(),
                            name="/api/banking/accounts")
        if r.status_code == 200:
            self.accounts = r.json().get("accounts", [])

    @task(4)
    def view_transactions(self):
        if not self.token:
            return
        self.client.get("/api/banking/transactions?limit=10",
                        headers=self._auth_headers(),
                        name="/api/banking/transactions")

    @task(3)
    def make_deposit(self):
        if not self.token or not self.accounts:
            return
        acct   = random.choice(self.accounts)
        amount = round(random.uniform(20, 200), 2)
        self.client.post("/api/banking/deposit", json={
            "to_account":  acct["account_number"],
            "amount":      amount,
            "description": "Salary deposit",
        }, headers=self._auth_headers(), name="/api/banking/deposit")

    @task(2)
    def make_transfer(self):
        if not self.token or len(self.accounts) < 2:
            return
        src, dst = random.sample(self.accounts[:2], 2)
        amount   = round(random.uniform(10, 100), 2)
        self.client.post("/api/banking/transfer", json={
            "from_account": src["account_number"],
            "to_account":   dst["account_number"],
            "amount":       amount,
            "description":  "Routine transfer",
        }, headers=self._auth_headers(), name="/api/banking/transfer")

    @task(1)
    def pay_bill(self):
        if not self.token or not self.accounts:
            return
        acct   = self.accounts[0]
        amount = round(random.uniform(30, 150), 2)
        self.client.post("/api/banking/pay-bill", json={
            "from_account": acct["account_number"],
            "payee_name":   "Electric Co.",
            "amount":       amount,
        }, headers=self._auth_headers(), name="/api/banking/pay-bill")

    @task(2)
    def view_security(self):
        if not self.token:
            return
        self.client.get("/api/dashboard/recent-activity?limit=5",
                        headers=self._auth_headers(),
                        name="/api/dashboard/recent-activity")

    @task(1)
    def view_cards(self):
        if not self.token:
            return
        self.client.get("/api/banking/cards",
                        headers=self._auth_headers(),
                        name="/api/banking/cards")


# ─── Attacker User ────────────────────────────────────────────────────────────

class AttackerUser(HttpUser):
    """
    Simulates the attacker container running escalating attacks.
    Uses the attack simulator endpoints so every action is logged
    and scored by the TokenShield engine.
    """

    # Very short wait — attackers are rapid and automated
    wait_time = between(1, 3)

    # Attacker does NOT use a real account — it hits the attack endpoints directly
    ATTACKER_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45"
        ),
        "Content-Type": "application/json",
    }

    VICTIM_USERNAME = "demo"
    HACKER_PROFILES = ["moscow", "beijing", "lagos", "bucharest", "unknown"]

    stolen_token = None

    def on_start(self):
        """Steal a token before any tasks run."""
        self._steal_token()

    def _steal_token(self):
        loc = random.choice(self.HACKER_PROFILES)
        r = self.client.post("/api/attack/steal-token", json={
            "username": self.VICTIM_USERNAME,
            "location": loc,
        }, headers=self.ATTACKER_HEADERS, name="/api/attack/steal-token")
        if r.status_code == 200:
            self.stolen_token = r.json().get("stolen_token")

    # ── Attack tasks ──────────────────────────────────────────────────────────

    @task(3)
    def brute_force(self):
        attempts = random.randint(10, 30)
        self.client.post("/api/attack/brute-force", json={
            "username": self.VICTIM_USERNAME,
            "attempts": attempts,
            "location": random.choice(self.HACKER_PROFILES),
        }, headers=self.ATTACKER_HEADERS, name="/api/attack/brute-force")

    @task(3)
    def fraudulent_transfer(self):
        if not self.stolen_token:
            self._steal_token()
            return
        amount = random.choice([1000, 2500, 5000, 9999])
        self.client.post("/api/attack/fraudulent-transfer", json={
            "amount":      amount,
            "destination": "offshore-account-XX",
            "location":    random.choice(self.HACKER_PROFILES),
        }, headers={
            **self.ATTACKER_HEADERS,
            "Authorization": f"Bearer {self.stolen_token}",
        }, name="/api/attack/fraudulent-transfer")

    @task(2)
    def sql_injection(self):
        payloads = [
            "' OR '1'='1'; DROP TABLE users; --",
            "'; SELECT * FROM users; --",
            "' UNION SELECT username, password FROM users --",
            "admin'--",
        ]
        self.client.post("/api/attack/sql-injection", json={
            "username": self.VICTIM_USERNAME,
            "payload":  random.choice(payloads),
            "location": "unknown",
        }, headers=self.ATTACKER_HEADERS, name="/api/attack/sql-injection")

    @task(2)
    def phishing(self):
        self.client.post("/api/attack/phishing", json={
            "username": self.VICTIM_USERNAME,
            "location": "beijing",
        }, headers=self.ATTACKER_HEADERS, name="/api/attack/phishing")

    @task(1)
    def credential_stuffing(self):
        self.client.post("/api/attack/credential-stuffing", json={
            "username": self.VICTIM_USERNAME,
            "combos":   random.randint(100, 1000),
            "location": "bucharest",
        }, headers=self.ATTACKER_HEADERS, name="/api/attack/credential-stuffing")

    @task(1)
    def mitm(self):
        self.client.post("/api/attack/mitm", json={
            "username": self.VICTIM_USERNAME,
            "location": random.choice(self.HACKER_PROFILES),
        }, headers=self.ATTACKER_HEADERS, name="/api/attack/mitm")

    @task(1)
    def privilege_escalation(self):
        self.client.post("/api/attack/privilege-escalation", json={
            "username": self.VICTIM_USERNAME,
            "location": "unknown",
        }, headers=self.ATTACKER_HEADERS, name="/api/attack/privilege-escalation")

    @task(1)
    def xss(self):
        self.client.post("/api/attack/xss", json={
            "username": self.VICTIM_USERNAME,
            "payload":  "<script>document.cookie</script>",
            "location": "beijing",
        }, headers=self.ATTACKER_HEADERS, name="/api/attack/xss")


# ─── Event hooks ──────────────────────────────────────────────────────────────

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    log.info("TokenShield Locust test started")
    log.info("Normal users will perform realistic banking operations")
    log.info("Attacker users will execute attack sequences")
    log.info("Watch the Admin Command Center at /admin for real-time detection")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    log.info("TokenShield Locust test stopped")