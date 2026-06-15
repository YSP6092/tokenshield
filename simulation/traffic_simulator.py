"""
TokenShield — Normal User Traffic Simulator
=============================================
Runs inside a Docker container (user1 / user2 / user3) and sends realistic
banking traffic to the Flask server, simulating a legitimate user browsing
their NeoVault account throughout the day.

Usage (inside container, or from terminal for testing):
    python traffic_simulator.py                        # uses defaults
    python traffic_simulator.py --host 172.20.0.2      # custom server IP
    python traffic_simulator.py --username alice        # specific user
    python traffic_simulator.py --cycles 0              # run forever

Environment variables (for Docker Compose):
    SERVER_HOST     IP/hostname of the Flask server   (default: 172.20.0.2)
    SERVER_PORT     Port of the Flask server           (default: 5001)
    SIM_USERNAME    Username to log in with            (default: demo)
    SIM_PASSWORD    Password                           (default: demo123)
    SIM_CYCLES      Number of full action cycles       (default: 0 = forever)
    SIM_MIN_DELAY   Min seconds between actions        (default: 2)
    SIM_MAX_DELAY   Max seconds between actions        (default: 8)

Behaviour:
    Each cycle follows this sequence with randomised delays between steps:
      1.  Register user if not already registered
      2.  Login → receive JWT token
      3.  View dashboard stats
      4.  View accounts list
      5.  Create a bank account (first cycle only)
      6.  Make a small deposit
      7.  Transfer a small amount between own accounts (if 2+ accounts exist)
      8.  View transaction history
      9.  View security dashboard stats
     10.  Logout
     11.  Wait a random "idle" period before the next cycle
"""

import os
import sys
import time
import random
import logging
import argparse
import requests
from datetime import datetime

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("traffic_simulator")

# ─── Configuration ────────────────────────────────────────────────────────────

def get_config(args=None):
    host     = getattr(args, "host",     None) or os.getenv("SERVER_HOST", "172.20.0.2")
    port     = getattr(args, "port",     None) or int(os.getenv("SERVER_PORT", 5001))
    username = getattr(args, "username", None) or os.getenv("SIM_USERNAME", "demo")
    password = getattr(args, "password", None) or os.getenv("SIM_PASSWORD", "demo123")
    email    = getattr(args, "email",    None) or os.getenv("SIM_EMAIL", f"{username}@sim.local")
    cycles   = getattr(args, "cycles",   None)
    if cycles is None:
        cycles = int(os.getenv("SIM_CYCLES", 0))
    min_delay = float(os.getenv("SIM_MIN_DELAY", 2))
    max_delay = float(os.getenv("SIM_MAX_DELAY", 8))

    return {
        "base_url":  f"http://{host}:{port}",
        "username":  username,
        "password":  password,
        "email":     email,
        "cycles":    cycles,       # 0 = run forever
        "min_delay": min_delay,
        "max_delay": max_delay,
    }


# ─── HTTP helpers ─────────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.headers.update({"Content-Type": "application/json"})

REALISTIC_USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.4; rv:109.0) Gecko/20100101 Firefox/114.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
]


def pick_agent():
    return random.choice(REALISTIC_USER_AGENTS)


def get(url, token=None, silent=False):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = SESSION.get(url, headers=headers, timeout=10)
        if not silent:
            log.debug("GET %s → %s", url, r.status_code)
        return r
    except requests.RequestException as exc:
        log.warning("GET %s failed: %s", url, exc)
        return None


def post(url, payload, token=None, silent=False):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = SESSION.post(url, json=payload, headers=headers, timeout=10)
        if not silent:
            log.debug("POST %s → %s", url, r.status_code)
        return r
    except requests.RequestException as exc:
        log.warning("POST %s failed: %s", url, exc)
        return None


def pause(cfg, scale=1.0):
    """Sleep a random human-like duration."""
    t = random.uniform(cfg["min_delay"], cfg["max_delay"]) * scale
    time.sleep(t)


# ─── Actions ──────────────────────────────────────────────────────────────────

def register_user(cfg):
    """Register the user account (idempotent — 409 is fine)."""
    base = cfg["base_url"]
    r = post(f"{base}/api/auth/register", {
        "username": cfg["username"],
        "email":    cfg["email"],
        "password": cfg["password"],
    }, silent=True)
    if r is None:
        return False
    if r.status_code == 201:
        log.info("Registered user: %s", cfg["username"])
    elif r.status_code == 409:
        log.debug("User already exists: %s", cfg["username"])
    else:
        log.warning("Register returned %s: %s", r.status_code, r.text[:100])
    return True


def login(cfg):
    """Log in and return the JWT token, or None on failure."""
    SESSION.headers["User-Agent"] = pick_agent()
    base = cfg["base_url"]
    r = post(f"{base}/api/auth/login", {
        "username": cfg["username"],
        "password": cfg["password"],
    })
    if r is None or not r.ok:
        log.error("Login failed (%s)", getattr(r, "status_code", "no response"))
        return None
    data = r.json()
    if data.get("success"):
        log.info("✅ Logged in as %s", cfg["username"])
        return data["token"]
    # 2FA gate triggered by a prior attack simulation — handle gracefully
    if data.get("requires_2fa"):
        log.warning("2FA required (account was locked by a previous attack). Skipping cycle.")
    else:
        log.warning("Login rejected: %s", data.get("message", "unknown"))
    return None


def logout(base, token):
    r = post(f"{base}/api/auth/logout", {}, token=token, silent=True)
    if r and r.ok:
        log.info("Logged out")


def view_dashboard(base, token):
    r = get(f"{base}/api/dashboard/stats", token=token)
    if r and r.ok:
        d = r.json().get("stats", {})
        score = d.get("current_session", {}).get("anomaly_score", 0)
        log.info("Dashboard | sessions=%s actions=%s score=%.2f",
                 d.get("active_sessions", "?"),
                 d.get("total_actions", "?"),
                 score)


def view_accounts(base, token):
    r = get(f"{base}/api/banking/accounts", token=token)
    if r and r.ok:
        accts = r.json().get("accounts", [])
        log.info("Accounts  | count=%d balances=%s",
                 len(accts),
                 [f"${a['balance']:.2f}" for a in accts[:3]])
        return accts
    return []


def create_account(base, token, account_type="checking"):
    r = post(f"{base}/api/banking/accounts/create", {
        "account_type":    account_type,
        "initial_balance": round(random.uniform(100, 500), 2),
    }, token=token)
    if r and r.ok:
        acct = r.json().get("account", {})
        log.info("Created account | %s #%s $%.2f",
                 account_type, acct.get("account_number", "?"), acct.get("balance", 0))
        return acct
    return {}


def deposit(base, token, account_number, amount=None):
    if amount is None:
        amount = round(random.uniform(50, 300), 2)
    r = post(f"{base}/api/banking/deposit", {
        "to_account":  account_number,
        "amount":      amount,
        "description": "Simulated deposit",
    }, token=token)
    if r and r.ok:
        log.info("Deposit   | $%.2f → %s | new balance $%.2f",
                 amount,
                 account_number,
                 r.json().get("new_balance", 0))
    return r


def transfer(base, token, from_account, to_account, amount=None):
    if amount is None:
        amount = round(random.uniform(10, 100), 2)
    r = post(f"{base}/api/banking/transfer", {
        "from_account": from_account,
        "to_account":   to_account,
        "amount":       amount,
        "description":  "Routine internal transfer",
    }, token=token)
    if r and r.ok:
        data = r.json()
        if data.get("security_alert"):
            log.warning("Transfer BLOCKED by TokenShield (anomaly score too high)")
        else:
            log.info("Transfer  | $%.2f from %s → %s",
                     amount, from_account, to_account)
    return r


def view_transactions(base, token):
    r = get(f"{base}/api/banking/transactions?limit=5", token=token)
    if r and r.ok:
        txns = r.json().get("transactions", [])
        log.info("Transactions | last %d fetched", len(txns))


def view_security(base, token):
    r = get(f"{base}/api/dashboard/recent-activity?limit=5", token=token)
    if r and r.ok:
        acts = r.json().get("activities", [])
        log.info("Security  | last %d activities", len(acts))


def view_cards(base, token):
    r = get(f"{base}/api/banking/cards", token=token)
    if r and r.ok:
        cards = r.json().get("cards", [])
        log.info("Cards     | %d cards on file", len(cards))


# ─── Full cycle ───────────────────────────────────────────────────────────────

def run_cycle(cfg, cycle_num, first_cycle):
    base = cfg["base_url"]
    log.info("─── Cycle %d started ───────────────────────────────", cycle_num)

    # 1. Login
    token = login(cfg)
    if token is None:
        log.warning("Cycle %d aborted — could not log in", cycle_num)
        time.sleep(15)
        return

    pause(cfg)

    # 2. View dashboard
    view_dashboard(base, token)
    pause(cfg)

    # 3. View accounts
    accounts = view_accounts(base, token)
    pause(cfg)

    # 4. First cycle: ensure at least 2 accounts exist
    if first_cycle and len(accounts) < 2:
        if len(accounts) == 0:
            acct = create_account(base, token, "checking")
            if acct.get("account_number"):
                accounts.append(acct)
            pause(cfg, scale=0.5)
        acct2 = create_account(base, token, "savings")
        if acct2.get("account_number"):
            accounts.append(acct2)
        pause(cfg)

    # 5. Deposit into first account
    if accounts:
        deposit(base, token, accounts[0]["account_number"])
        pause(cfg)

    # 6. Transfer between accounts (if 2 or more exist)
    if len(accounts) >= 2:
        # Randomly pick direction
        src, dst = random.sample(accounts[:2], 2)
        transfer(base, token, src["account_number"], dst["account_number"])
        pause(cfg)

    # 7. View transactions
    view_transactions(base, token)
    pause(cfg)

    # 8. Occasionally view cards
    if random.random() < 0.3:
        view_cards(base, token)
        pause(cfg, scale=0.5)

    # 9. View security dashboard
    view_security(base, token)
    pause(cfg, scale=0.5)

    # 10. Logout
    logout(base, token)

    log.info("─── Cycle %d complete ──────────────────────────────", cycle_num)


# ─── Entry point ──────────────────────────────────────────────────────────────

def wait_for_server(base_url, max_wait=120):
    """Poll the health endpoint until the server is up or timeout."""
    log.info("Waiting for server at %s …", base_url)
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"{base_url}/health", timeout=3)
            if r.ok:
                log.info("Server is up ✅")
                return True
        except requests.RequestException:
            pass
        time.sleep(3)
    log.error("Server did not become available within %ds", max_wait)
    return False


def main():
    parser = argparse.ArgumentParser(description="TokenShield normal-user traffic simulator")
    parser.add_argument("--host",     default=None, help="Flask server host/IP")
    parser.add_argument("--port",     default=None, type=int, help="Flask server port")
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--email",    default=None)
    parser.add_argument("--cycles",   default=None, type=int,
                        help="Number of cycles to run (0 = forever)")
    args = parser.parse_args()

    cfg = get_config(args)

    log.info("TokenShield Traffic Simulator starting")
    log.info("Server   : %s", cfg["base_url"])
    log.info("Username : %s", cfg["username"])
    log.info("Cycles   : %s", cfg["cycles"] if cfg["cycles"] > 0 else "∞")
    log.info("Delay    : %.1f – %.1f seconds", cfg["min_delay"], cfg["max_delay"])

    # Wait for the Flask server to be ready
    if not wait_for_server(cfg["base_url"]):
        sys.exit(1)

    # Ensure the user account exists
    register_user(cfg)
    time.sleep(2)

    cycle = 0
    while True:
        cycle += 1
        try:
            run_cycle(cfg, cycle, first_cycle=(cycle == 1))
        except Exception as exc:
            log.error("Cycle %d crashed: %s", cycle, exc, exc_info=True)

        if cfg["cycles"] > 0 and cycle >= cfg["cycles"]:
            log.info("Reached %d cycles — stopping.", cfg["cycles"])
            break

        # Idle pause between cycles (longer than intra-cycle pauses)
        idle = random.uniform(cfg["max_delay"] * 2, cfg["max_delay"] * 5)
        log.info("Idle for %.1f seconds before next cycle …", idle)
        time.sleep(idle)

    log.info("Traffic simulator finished.")


if __name__ == "__main__":
    main()