"""
TokenShield — Nginx IP Block Writer  (Step 3.1)
================================================
Writes banned IPs to /etc/nginx/blocked_ips.conf (inside the nginx-proxy
container) so the entrypoint.sh watcher detects the change and signals
Nginx to reload within 5 seconds.

How it works:
  1. Flask mitigation calls block_ip_in_nginx(ip, reason)
  2. This module writes a "deny <ip>;" line to the shared blocklist file
  3. The Nginx entrypoint watcher detects the md5sum change
  4. Nginx reloads — the IP is blocked at the network edge

The blocklist file is on a Docker volume shared between flask-server
and nginx-proxy:
    flask-server  writes to /app/nginx/blocked_ips.conf
    nginx-proxy   reads from /etc/nginx/blocked_ips.conf
    Both containers mount ./nginx → their respective paths.

File format (nginx deny syntax):
    # BLOCKED: 185.220.101.42 | reason: auto_revoked | 2025-01-01T12:00:00
    deny 185.220.101.42;

Thread safety: file writes use a temp-file + atomic rename pattern so
Nginx never reads a partially written file.
"""

import os
import logging
import tempfile
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("tokenshield.nginx_block")

# Path as seen from inside the flask-server container.
# ./nginx/ is mounted into both containers:
#   flask-server : /app/nginx/blocked_ips.conf  (writes here)
#   nginx-proxy  : /etc/nginx/blocked_ips.conf  (reads from here)
BLOCKED_IPS_PATH = os.environ.get(
    "NGINX_BLOCKED_IPS_PATH",
    "/app/nginx/blocked_ips.conf"
)


def _ensure_file() -> bool:
    """Create the blocked_ips.conf file if it doesn't exist."""
    try:
        path = Path(BLOCKED_IPS_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text("# TokenShield — Dynamic IP Blocklist\n"
                            "# Managed automatically — do not edit manually\n")
        return True
    except OSError as exc:
        logger.error("nginx_block: cannot create blocklist file — %s", exc)
        return False


def _read_blocked_ips() -> set:
    """Return set of currently blocked IPs (parsed from deny lines)."""
    try:
        content = Path(BLOCKED_IPS_PATH).read_text()
        blocked = set()
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("deny ") and line.endswith(";"):
                ip = line[5:-1].strip()
                if ip:
                    blocked.add(ip)
        return blocked
    except OSError:
        return set()


def block_ip_in_nginx(ip: str, reason: str = "auto_blocked") -> bool:
    """
    Add an IP to the Nginx blocklist.
    Returns True if the IP was newly added, False if already blocked.

    The Nginx entrypoint watcher detects the file change via md5sum
    and calls 'nginx -s reload' within RELOAD_INTERVAL seconds (default 5).
    """
    if not ip or ip in ("unknown", "127.0.0.1", "::1"):
        return False

    if not _ensure_file():
        return False

    already_blocked = _read_blocked_ips()
    if ip in already_blocked:
        logger.debug("nginx_block: %s already in blocklist", ip)
        return False

    timestamp = datetime.utcnow().isoformat()
    new_line  = (
        f"\n# BLOCKED: {ip} | reason: {reason} | {timestamp}\n"
        f"deny {ip};\n"
    )

    try:
        # Atomic write: write to temp file then rename
        # This prevents Nginx from reading a half-written file
        path = Path(BLOCKED_IPS_PATH)
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=path.parent,
            prefix=".blocked_ips_tmp_",
            delete=False,
            suffix=".conf"
        ) as tmp:
            tmp.write(path.read_text())
            tmp.write(new_line)
            tmp_path = tmp.name

        os.replace(tmp_path, BLOCKED_IPS_PATH)
        logger.warning(
            "nginx_block: BLOCKED %s at network edge (reason=%s)", ip, reason
        )
        return True

    except OSError as exc:
        logger.error("nginx_block: failed to write blocklist — %s", exc)
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        return False


def unblock_ip_in_nginx(ip: str) -> bool:
    """
    Remove an IP from the Nginx blocklist.
    Used when an admin lifts a ban from the dashboard.
    Returns True if the IP was found and removed.
    """
    if not _ensure_file():
        return False

    try:
        path    = Path(BLOCKED_IPS_PATH)
        content = path.read_text()
        lines   = content.splitlines(keepends=True)

        new_lines = []
        removed   = False
        skip_next = False

        for line in lines:
            stripped = line.strip()
            # Skip the comment line that precedes the deny line
            if stripped.startswith(f"# BLOCKED: {ip} |"):
                skip_next = True
                removed   = True
                continue
            if skip_next and stripped == f"deny {ip};":
                skip_next = False
                continue
            # Also catch bare deny lines without a comment
            if stripped == f"deny {ip};":
                removed = True
                continue
            skip_next = False
            new_lines.append(line)

        if not removed:
            return False

        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=path.parent,
            prefix=".blocked_ips_tmp_",
            delete=False,
            suffix=".conf"
        ) as tmp:
            tmp.writelines(new_lines)
            tmp_path = tmp.name

        os.replace(tmp_path, BLOCKED_IPS_PATH)
        logger.info("nginx_block: UNBLOCKED %s", ip)
        return True

    except OSError as exc:
        logger.error("nginx_block: failed to unblock %s — %s", ip, exc)
        return False


def get_blocked_ips() -> list:
    """
    Return a list of dicts with blocked IP details.
    Parses the comment lines to recover reason + timestamp.
    """
    try:
        content = Path(BLOCKED_IPS_PATH).read_text()
    except OSError:
        return []

    results    = []
    pending    = {}

    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("# BLOCKED:"):
            # Parse: # BLOCKED: <ip> | reason: <reason> | <ts>
            try:
                parts  = stripped[len("# BLOCKED:"):].split("|")
                ip     = parts[0].strip()
                reason = parts[1].replace("reason:", "").strip() if len(parts) > 1 else "unknown"
                ts     = parts[2].strip() if len(parts) > 2 else ""
                pending[ip] = {"ip": ip, "reason": reason, "blocked_at": ts}
            except Exception:
                pass
        elif stripped.startswith("deny ") and stripped.endswith(";"):
            ip = stripped[5:-1].strip()
            if ip in pending:
                results.append(pending.pop(ip))
            else:
                results.append({"ip": ip, "reason": "unknown", "blocked_at": ""})

    return results


def is_ip_blocked(ip: str) -> bool:
    """Quick check — is this IP in the Nginx blocklist?"""
    return ip in _read_blocked_ips()


def blocked_ip_count() -> int:
    """Return total number of IPs currently blocked."""
    return len(_read_blocked_ips())


def ensure_blocklist_exists() -> None:
    """
    Called at app startup to guarantee the file exists.
    Nginx will fail to start if the include file is missing.
    """
    _ensure_file()
    logger.info("nginx_block: blocklist file ready at %s", BLOCKED_IPS_PATH)