"""
TokenShield — Selenium Browser Node (Phase 2.4)
=================================================
Phase 2.4 adds ZAP proxy support. When ZAP_PROXY_HOST is set,
Chrome routes all traffic through ZAP so ZAP intercepts real
authenticated sessions with valid JWT tokens.

Environment variables:
    SERVER_HOST         Flask server IP         (default: 172.20.0.2)
    SERVER_PORT         Flask server port       (default: 5001)
    SIM_USERNAME        Username                (default: dave)
    SIM_PASSWORD        Password                (default: dave1234)
    SIM_EMAIL           Email                   (default: dave@sim.local)
    SIM_CYCLES          Number of cycles        (default: 0 = forever)
    SIM_MIN_DELAY       Min seconds             (default: 2)
    SIM_MAX_DELAY       Max seconds             (default: 6)
    SELENIUM_HOST       Selenium Grid host      (default: localhost)
    SELENIUM_PORT       Selenium Grid port      (default: 4444)
    ZAP_PROXY_HOST      ZAP proxy IP            (default: 172.20.0.98)
    ZAP_PROXY_PORT      ZAP proxy port          (default: 8091)
    ZAP_PROXY_ENABLED   Set to "false" to skip  (default: true)
"""

import os
import sys
import time
import random
import logging
import requests

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import (
    TimeoutException, NoSuchElementException, WebDriverException
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SELENIUM] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("selenium_browser")


def get_config():
    host        = os.getenv("SERVER_HOST",      "172.20.0.2")
    port        = os.getenv("SERVER_PORT",      "5001")
    username    = os.getenv("SIM_USERNAME",     "dave")
    password    = os.getenv("SIM_PASSWORD",     "dave1234")
    email       = os.getenv("SIM_EMAIL",        "dave@sim.local")
    cycles      = int(os.getenv("SIM_CYCLES",   "0"))
    min_d       = float(os.getenv("SIM_MIN_DELAY", "2"))
    max_d       = float(os.getenv("SIM_MAX_DELAY", "6"))
    sel_host    = os.getenv("SELENIUM_HOST",    "localhost")
    sel_port    = os.getenv("SELENIUM_PORT",    "4444")
    zap_host    = os.getenv("ZAP_PROXY_HOST",   "172.20.0.98")
    zap_port    = os.getenv("ZAP_PROXY_PORT",   "8091")
    zap_enabled = os.getenv("ZAP_PROXY_ENABLED","true").lower() != "false"
    return {
        "base_url":   f"http://{host}:{port}",
        "username":   username,
        "password":   password,
        "email":      email,
        "cycles":     cycles,
        "min_delay":  min_d,
        "max_delay":  max_d,
        "grid_url":   f"http://{sel_host}:{sel_port}/wd/hub",
        "zap_proxy":  f"{zap_host}:{zap_port}" if zap_enabled else None,
        "zap_host":   zap_host,
        "zap_port":   int(zap_port),
        "zap_enabled":zap_enabled,
    }


def human_pause(cfg, scale=1.0):
    time.sleep(random.uniform(cfg["min_delay"], cfg["max_delay"]) * scale)


def human_type(element, text, delay=0.08):
    element.clear()
    for char in text:
        element.send_keys(char)
        time.sleep(random.uniform(delay * 0.5, delay * 1.5))


def wait_for_server(base_url, max_wait=180):
    log.info("Waiting for Flask at %s/health ...", base_url)
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"{base_url}/health", timeout=3)
            if r.ok:
                log.info("Flask is up ✅")
                return True
        except requests.RequestException:
            pass
        time.sleep(5)
    return False


def wait_for_selenium(grid_url, max_wait=120):
    log.info("Waiting for Selenium Grid at %s ...", grid_url)
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"{grid_url}/status", timeout=3)
            if r.ok and r.json().get("value", {}).get("ready"):
                log.info("Selenium Grid ready ✅")
                return True
        except requests.RequestException:
            pass
        time.sleep(5)
    return False


def wait_for_zap_proxy(cfg, max_wait=120):
    if not cfg["zap_enabled"]:
        return True
    zap_api = f"http://{cfg['zap_host']}:{cfg['zap_port']}"
    log.info("Waiting for ZAP proxy at %s ...", zap_api)
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        try:
            r = requests.get(
                f"{zap_api}/JSON/core/view/version/?apikey=tokenshield-zap-2025",
                timeout=3,
            )
            if r.ok:
                log.info("ZAP proxy ready ✅ (v%s)", r.json().get("version","?"))
                return True
        except requests.RequestException:
            pass
        time.sleep(5)
    log.warning("ZAP proxy not ready — continuing without proxy")
    return False


def register_user_api(cfg):
    try:
        r = requests.post(
            f"{cfg['base_url']}/api/auth/register",
            json={"username": cfg["username"], "email": cfg["email"], "password": cfg["password"]},
            timeout=10,
        )
        if r.status_code == 201:
            log.info("Registered user: %s", cfg["username"])
        elif r.status_code == 409:
            log.info("User already exists: %s", cfg["username"])
    except Exception as exc:
        log.warning("Register failed: %s", exc)


def create_driver(cfg):
    """
    Create Chrome WebDriver. Phase 2.4: routes traffic through ZAP proxy
    so ZAP intercepts real authenticated sessions with valid JWT tokens.
    """
    chrome_options = Options()
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--window-size=1366,768")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option("useAutomationExtension", False)
    chrome_options.add_argument(
        "user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    if cfg["zap_enabled"] and cfg["zap_proxy"]:
        chrome_options.add_argument(f"--proxy-server={cfg['zap_proxy']}")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--allow-insecure-localhost")
        log.info("🔍 ZAP proxy ENABLED — Chrome → %s → Flask", cfg["zap_proxy"])
    else:
        log.info("ZAP proxy disabled — direct connection")

    driver = webdriver.Remote(command_executor=cfg["grid_url"], options=chrome_options)
    driver.execute_script(
        "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
    )
    driver.set_page_load_timeout(30)
    driver.implicitly_wait(5)
    return driver


def zap_trigger_active_scan(cfg, target_url):
    """Tell ZAP daemon to actively scan a URL Selenium just visited."""
    if not cfg["zap_enabled"]:
        return
    try:
        r = requests.get(
            f"http://{cfg['zap_host']}:{cfg['zap_port']}/JSON/ascan/action/scan/",
            params={"apikey": "tokenshield-zap-2025", "url": target_url, "recurse": "true"},
            timeout=5,
        )
        if r.ok:
            log.info("   ZAP scan triggered (id=%s) → %s", r.json().get("scan","?"), target_url)
    except Exception as exc:
        log.debug("ZAP scan trigger (non-fatal): %s", exc)


def zap_get_alert_count(cfg):
    if not cfg["zap_enabled"]:
        return 0
    try:
        r = requests.get(
            f"http://{cfg['zap_host']}:{cfg['zap_port']}/JSON/alert/view/numberofAlerts/",
            params={"apikey": "tokenshield-zap-2025"},
            timeout=5,
        )
        if r.ok:
            return int(r.json().get("numberOfAlerts", 0))
    except Exception:
        pass
    return 0


def action_login(driver, cfg, wait):
    log.info("→ Login")
    driver.get(f"{cfg['base_url']}/login")
    human_pause(cfg, scale=0.5)
    try:
        field = wait.until(EC.presence_of_element_located((By.ID, "username")))
        human_type(field, cfg["username"])
        human_pause(cfg, scale=0.3)
        pw = driver.find_element(By.ID, "password")
        human_type(pw, cfg["password"])
        human_pause(cfg, scale=0.3)
        pw.send_keys(Keys.RETURN)
        time.sleep(2)
        token = driver.execute_script(
            "return localStorage.getItem('token') || localStorage.getItem('jwt') || '';"
        )
        log.info("✅ Logged in as %s", cfg["username"])
        return token
    except TimeoutException:
        log.warning("Login page fields not found — API fallback")
        return api_login_fallback(driver, cfg)


def api_login_fallback(driver, cfg):
    try:
        r = requests.post(
            f"{cfg['base_url']}/api/auth/login",
            json={"username": cfg["username"], "password": cfg["password"]},
            timeout=10,
        )
        if r.ok and r.json().get("success"):
            token = r.json()["token"]
            driver.get(cfg["base_url"])
            time.sleep(1)
            driver.execute_script(f"localStorage.setItem('token', '{token}');")
            log.info("✅ Token injected via API fallback")
            return token
    except Exception as exc:
        log.warning("API fallback failed: %s", exc)
    return None


def action_view_dashboard(driver, cfg, wait):
    log.info("→ Dashboard")
    driver.get(f"{cfg['base_url']}/dashboard")
    human_pause(cfg, scale=0.8)
    for _ in range(3):
        driver.execute_script("window.scrollBy(0, 200);")
        time.sleep(random.uniform(0.5, 1.2))
    zap_trigger_active_scan(cfg, f"{cfg['base_url']}/dashboard")


def action_view_accounts(driver, cfg, wait):
    log.info("→ Accounts")
    try:
        link = driver.find_element(
            By.XPATH, "//*[contains(text(),'Account') or contains(@href,'account')]"
        )
        link.click()
        human_pause(cfg, scale=0.6)
    except NoSuchElementException:
        driver.get(f"{cfg['base_url']}/dashboard")
        human_pause(cfg, scale=0.5)
    driver.execute_script("window.scrollTo(0, document.body.scrollHeight/2);")
    time.sleep(random.uniform(0.8, 1.5))
    driver.execute_script("window.scrollTo(0, 0);")


def action_view_transactions(driver, cfg, wait):
    log.info("→ Transactions")
    driver.get(f"{cfg['base_url']}/dashboard")
    human_pause(cfg, scale=0.5)
    try:
        link = driver.find_element(
            By.XPATH, "//*[contains(text(),'Transaction') or contains(text(),'History')]"
        )
        link.click()
        human_pause(cfg, scale=0.6)
    except NoSuchElementException:
        pass
    for _ in range(4):
        driver.execute_script("window.scrollBy(0, 150);")
        time.sleep(random.uniform(0.4, 0.9))


def action_view_security(driver, cfg, wait):
    log.info("→ Security dashboard")
    driver.get(f"{cfg['base_url']}/security")
    human_pause(cfg, scale=0.7)
    driver.execute_script("window.scrollTo(0, document.body.scrollHeight/3);")
    time.sleep(random.uniform(1.0, 2.0))
    zap_trigger_active_scan(cfg, f"{cfg['base_url']}/security")


def action_make_api_transfer(cfg, token):
    if not token:
        return
    try:
        r = requests.get(
            f"{cfg['base_url']}/api/banking/accounts",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if not r.ok:
            return
        accounts = r.json().get("accounts", [])
        if len(accounts) < 2:
            return
        amount = round(random.uniform(10, 80), 2)
        r2 = requests.post(
            f"{cfg['base_url']}/api/banking/transfer",
            json={"from_account": accounts[0]["account_number"],
                  "to_account": accounts[1]["account_number"],
                  "amount": amount, "description": "Selenium transfer"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if r2.ok:
            log.info("   Transfer $%.2f ✅", amount)
    except Exception as exc:
        log.warning("Transfer error: %s", exc)


def action_logout(driver, cfg):
    log.info("→ Logout")
    try:
        btn = driver.find_element(
            By.XPATH,
            "//*[contains(text(),'Logout') or contains(text(),'Sign out') or contains(@href,'logout')]"
        )
        btn.click()
        human_pause(cfg, scale=0.5)
    except NoSuchElementException:
        token = driver.execute_script("return localStorage.getItem('token') || '';")
        if token:
            requests.post(f"{cfg['base_url']}/api/auth/logout",
                         headers={"Authorization": f"Bearer {token}"}, timeout=5)
        driver.execute_script("localStorage.clear(); sessionStorage.clear();")


def run_browser_cycle(driver, cfg, cycle_num):
    wait = WebDriverWait(driver, 15)
    log.info("═══ Cycle %d ════════════════════════════════════════", cycle_num)
    try:
        token = action_login(driver, cfg, wait)
        human_pause(cfg)
        action_view_dashboard(driver, cfg, wait)
        human_pause(cfg)
        action_view_accounts(driver, cfg, wait)
        human_pause(cfg)
        action_make_api_transfer(cfg, token)
        human_pause(cfg)
        action_view_transactions(driver, cfg, wait)
        human_pause(cfg)
        if random.random() < 0.5:
            action_view_security(driver, cfg, wait)
            human_pause(cfg)
        action_logout(driver, cfg)
        alerts = zap_get_alert_count(cfg)
        log.info("   ZAP total alerts: %d", alerts)
    except WebDriverException as exc:
        log.error("WebDriver error cycle %d: %s", cycle_num, exc)
    except Exception as exc:
        log.error("Error cycle %d: %s", cycle_num, exc, exc_info=True)
    log.info("═══ Cycle %d complete ══════════════════════════════", cycle_num)


def main():
    cfg = get_config()
    log.info("TokenShield Selenium Browser (Phase 2.4)")
    log.info("Target   : %s", cfg["base_url"])
    log.info("User     : %s", cfg["username"])
    log.info("Grid     : %s", cfg["grid_url"])
    log.info("ZAP proxy: %s", cfg["zap_proxy"] or "DISABLED")
    log.info("VNC      : http://localhost:7900  (password: secret)")

    if not wait_for_server(cfg["base_url"]):
        sys.exit(1)
    if not wait_for_selenium(cfg["grid_url"]):
        sys.exit(1)

    if cfg["zap_enabled"]:
        if not wait_for_zap_proxy(cfg):
            cfg["zap_enabled"] = False
            cfg["zap_proxy"] = None

    register_user_api(cfg)
    time.sleep(2)
    log.info("Waiting 15s for baseline traffic ...")
    time.sleep(15)

    cycle = 0
    while True:
        cycle += 1
        driver = None
        try:
            driver = create_driver(cfg)
            run_browser_cycle(driver, cfg, cycle)
        except Exception as exc:
            log.error("Driver/cycle failed: %s", exc)
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

        if cfg["cycles"] > 0 and cycle >= cfg["cycles"]:
            log.info("Reached %d cycles — stopping.", cfg["cycles"])
            break

        idle = random.uniform(30, 90)
        log.info("Idle %.0fs before next session ...", idle)
        time.sleep(idle)

    log.info("Selenium browser finished.")


if __name__ == "__main__":
    main()