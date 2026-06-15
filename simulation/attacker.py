"""
TokenShield — Attacker Node Script
=====================================
Runs inside the attacker Docker container (IP 172.20.0.99) and executes a
progressive, escalating sequence of cyber attacks against the NeoVault
banking server via the attack simulator endpoints.

The script is intentionally designed to be demonstrable:
  - Phase 1 (Reconnaissance): slow, probing requests
  - Phase 2 (Active Attack):  escalating attack types
  - Phase 3 (Escalation):     aggressive high-severity attacks
  - Ends when all attacks are complete or the session is revoked

Usage (inside container):
    python attacker.py

    python attacker.py --host 172.20.0.2 --victim demo --location moscow

Environment variables (for Docker Compose):
    SERVER_HOST         Flask server IP         (default: 172.20.0.2)
    SERVER_PORT         Flask server port        (default: 5001)
    ATTACKER_VICTIM     Username to attack       (default: demo)
    ATTACKER_LOCATION   Hacker profile key       (default: moscow)
    ATTACKER_DELAY      Seconds between attacks  (default: 4)
    ATTACKER_LOOP       1 = repeat attacks forever (default: 0)
"""

import os
import sys
import time
import logging
import argparse
import requests

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ATTACKER] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("attacker")

# ─── Config ───────────────────────────────────────────────────────────────────

def get_config(args=None):
    host     = getattr(args, "host",     None) or os.getenv("SERVER_HOST",     "172.20.0.2")
    port     = getattr(args, "port",     None) or int(os.getenv("SERVER_PORT", 5001))
    victim   = getattr(args, "victim",   None) or os.getenv("ATTACKER_VICTIM", "demo")
    location = getattr(args, "location", None) or os.getenv("ATTACKER_LOCATION","moscow")
    delay    = float(os.getenv("ATTACKER_DELAY", 4))
    loop     = os.getenv("ATTACKER_LOOP", "0") == "1"
    return {
        "base_url": f"http://{host}:{port}",
        "victim":   victim,
        "location": location,
        "delay":    delay,
        "loop":     loop,
    }


# ─── HTTP helpers ─────────────────────────────────────────────────────────────

# Use a real-looking but suspicious user agent from a different OS to the victim
ATTACKER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
)

SESSION = requests.Session()
SESSION.headers.update({
    "Content-Type":  "application/json",
    "User-Agent":    ATTACKER_USER_AGENT,
})


def post(url, payload, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = SESSION.post(url, json=payload, headers=headers, timeout=15)
        return r
    except requests.RequestException as exc:
        log.warning("POST %s error: %s", url, exc)
        return None


def get(url, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = SESSION.get(url, headers=headers, timeout=10)
        return r
    except requests.RequestException as exc:
        log.warning("GET %s error: %s", url, exc)
        return None


def wait_for_server(base_url, max_wait=120):
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
    log.error("Server not available after %ds", max_wait)
    return False


def parse_json(r):
    if r is None:
        return {}
    try:
        return r.json()
    except Exception:
        return {}


# ─── Individual Attack Steps ──────────────────────────────────────────────────

def log_separator(title):
    log.info("━" * 55)
    log.info("  %s", title)
    log.info("━" * 55)


def reset_victim(cfg):
    """Reset the victim account so attacks work cleanly each run."""
    base = cfg["base_url"]
    r = post(f"{base}/api/attack/reset-victim", {"username": cfg["victim"]})
    d = parse_json(r)
    if d.get("success"):
        log.info("Victim reset: %s", d.get("message", "ok"))
    else:
        log.warning("Victim reset failed: %s", d)


def step_steal_token(cfg):
    """Phase 1 — Steal the victim's session token."""
    log_separator("STEP 1 — Token Theft / Session Hijack")
    base = cfg["base_url"]
    r = post(f"{base}/api/attack/steal-token", {
        "username": cfg["victim"],
        "location": cfg["location"],
    })
    d = parse_json(r)
    token = d.get("stolen_token")
    hacker = d.get("hacker", {})
    log.info("Stolen token: %s…", str(token)[:40] if token else "FAILED")
    log.info("Attacker IP : %s (%s)", hacker.get("ip", "?"), hacker.get("location", "?"))
    return token


def step_fraudulent_transfer(cfg, token):
    """Phase 1 — Attempt a fraudulent $5,000 transfer."""
    log_separator("STEP 2 — Fraudulent Transfer ($5,000)")
    base = cfg["base_url"]
    r = post(f"{base}/api/attack/fraudulent-transfer", {
        "amount":      5000,
        "destination": "offshore-account-XX",
        "location":    cfg["location"],
    }, token=token)
    d = parse_json(r)
    ts = d.get("tokenshield", {})
    transfer = d.get("transfer", {})
    log.info("Anomaly score : %.0f%%", (ts.get("anomaly_score", 0) * 100))
    log.info("Transfer      : %s", "BLOCKED" if transfer.get("blocked") else "allowed")
    log.info("Sessions rev. : %d", len(ts.get("sessions_revoked", [])))


def step_brute_force(cfg):
    """Phase 2 — Brute force login attack."""
    log_separator("STEP 3 — Brute Force Login (25 attempts)")
    base = cfg["base_url"]
    r = post(f"{base}/api/attack/brute-force", {
        "username": cfg["victim"],
        "attempts": 25,
        "location": cfg["location"],
    })
    d = parse_json(r)
    log.info("Anomaly score : %.0f%%", (d.get("anomaly_score", 0) * 100))
    log.info("Account locked: %s", d.get("account_locked", False))
    log.info("Threat level  : %s", d.get("threat_level", "?"))


def step_sql_injection(cfg):
    """Phase 2 — SQL injection payload."""
    log_separator("STEP 4 — SQL Injection")
    base = cfg["base_url"]
    payload = "' OR '1'='1'; DROP TABLE users; --"
    r = post(f"{base}/api/attack/sql-injection", {
        "username": cfg["victim"],
        "payload":  payload,
        "location": "unknown",
    })
    d = parse_json(r)
    log.info("WAF triggered : %s", d.get("waf_triggered", False))
    log.info("Blocked       : %s", d.get("blocked", False))
    log.info("Threat level  : %s", d.get("threat_level", "?"))


def step_phishing(cfg):
    """Phase 2 — Phishing credential theft simulation."""
    log_separator("STEP 5 — Phishing Attack")
    base = cfg["base_url"]
    r = post(f"{base}/api/attack/phishing", {
        "username": cfg["victim"],
        "location": "beijing",
    })
    d = parse_json(r)
    log.info("Phishing domain: %s", d.get("phishing_domain", "?"))
    log.info("Threat level   : %s", d.get("threat_level", "?"))


def step_credential_stuffing(cfg):
    """Phase 2 — Credential stuffing from breach dump."""
    log_separator("STEP 6 — Credential Stuffing (500 combos)")
    base = cfg["base_url"]
    r = post(f"{base}/api/attack/credential-stuffing", {
        "username": cfg["victim"],
        "combos":   500,
        "location": "bucharest",
    })
    d = parse_json(r)
    log.info("Combos tried  : %d", d.get("combos_tried", 0))
    log.info("Threat level  : %s", d.get("threat_level", "?"))


def step_mitm(cfg):
    """Phase 3 — Man-in-the-middle attack."""
    log_separator("STEP 7 — Man-in-the-Middle (CRITICAL)")
    base = cfg["base_url"]
    r = post(f"{base}/api/attack/mitm", {
        "username": cfg["victim"],
        "location": cfg["location"],
    })
    d = parse_json(r)
    log.info("SSL stripped  : %s", d.get("ssl_stripped", False))
    log.info("Anomaly score : %.0f%%", (d.get("anomaly_score", 0) * 100))
    log.info("Threat level  : %s", d.get("threat_level", "?"))


def step_privilege_escalation(cfg):
    """Phase 3 — JWT admin privilege escalation."""
    log_separator("STEP 8 — Privilege Escalation (CRITICAL)")
    base = cfg["base_url"]
    r = post(f"{base}/api/attack/privilege-escalation", {
        "username": cfg["victim"],
        "location": "unknown",
    })
    d = parse_json(r)
    log.info("Attempted role: %s", d.get("attempted_role", "?"))
    log.info("Blocked       : %s", d.get("blocked", False))
    log.info("Anomaly score : %.0f%%", (d.get("anomaly_score", 0) * 100))


def step_full_scenario(cfg):
    """Full end-to-end scenario — used as a finale."""
    log_separator("FINAL — Full Attack Scenario (token_theft)")
    base = cfg["base_url"]
    r = post(f"{base}/api/attack/full-scenario", {
        "username":    cfg["victim"],
        "location":    cfg["location"],
        "attack_type": "token_theft",
        "amount":      9999,
    })
    d = parse_json(r)
    log.info("Summary : %s", d.get("summary", "?"))
    victim = d.get("victim", {})
    log.info("Requires 2FA: %s", victim.get("requires_2fa", False))
    log.info("Message     : %s", victim.get("message", "?"))


# ─── Attack sequence ──────────────────────────────────────────────────────────

ATTACK_SEQUENCE = [
    # (delay_multiplier, function, label)
    (1.0, step_steal_token,          "Token Theft"),
    (1.5, step_fraudulent_transfer,  "Fraudulent Transfer"),
    (1.0, step_brute_force,          "Brute Force"),
    (0.8, step_sql_injection,        "SQL Injection"),
    (0.8, step_phishing,             "Phishing"),
    (0.8, step_credential_stuffing,  "Credential Stuffing"),
    (0.5, step_mitm,                 "Man-in-the-Middle"),
    (0.5, step_privilege_escalation, "Privilege Escalation"),
    (0.5, step_full_scenario,        "Full Scenario"),
]


def run_attack_sequence(cfg):
    """Execute all 9 attack steps with pacing delays between each."""
    log.info("")
    log.info("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    log.info("  TokenShield Attack Sequence STARTING")
    log.info("  Target  : %s @ %s", cfg["victim"], cfg["base_url"])
    log.info("  Profile : %s", cfg["location"])
    log.info("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    log.info("")

    # Reset victim account before starting
    reset_victim(cfg)
    time.sleep(2)

    stolen_token = None

    for delay_mult, func, label in ATTACK_SEQUENCE:
        try:
            if func == step_steal_token:
                stolen_token = func(cfg)
            elif func == step_fraudulent_transfer:
                func(cfg, stolen_token)
            else:
                func(cfg)
        except Exception as exc:
            log.error("Attack step '%s' failed: %s", label, exc, exc_info=True)

        wait = cfg["delay"] * delay_mult
        log.info("  … pausing %.1fs before next step …", wait)
        time.sleep(wait)

    log.info("")
    log.info("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    log.info("  Attack sequence COMPLETE")
    log.info("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓")
    log.info("")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="TokenShield attacker node")
    parser.add_argument("--host",     default=None)
    parser.add_argument("--port",     default=None, type=int)
    parser.add_argument("--victim",   default=None, help="Target username")
    parser.add_argument("--location", default=None, help="Hacker profile key")
    parser.add_argument("--delay",    default=None, type=float,
                        help="Seconds between attacks")
    parser.add_argument("--loop",     action="store_true",
                        help="Repeat the attack sequence indefinitely")
    args = parser.parse_args()

    cfg = get_config(args)
    if getattr(args, "loop", False):
        cfg["loop"] = True
    if getattr(args, "delay", None):
        cfg["delay"] = args.delay

    log.info("TokenShield Attacker starting")
    log.info("Server  : %s", cfg["base_url"])
    log.info("Victim  : %s", cfg["victim"])
    log.info("Profile : %s", cfg["location"])

    if not wait_for_server(cfg["base_url"]):
        sys.exit(1)

    # Initial wait so normal-user traffic establishes a baseline first
    log.info("Waiting 20 seconds to let normal traffic establish baseline …")
    time.sleep(20)

    run_count = 0
    while True:
        run_count += 1
        log.info("=== Attack run #%d ===", run_count)
        run_attack_sequence(cfg)

        if not cfg["loop"]:
            break

        log.info("Loop mode — waiting 60s before next run …")
        time.sleep(60)

    log.info("Attacker finished.")


if __name__ == "__main__":
    main()