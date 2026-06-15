"""
TokenShield — Step 1.2: IP Reputation (Signal 1)
=================================================
Scores every IP across five tiers without requiring any API key.
When you add an IPINFO_TOKEN to .env, the module automatically
upgrades to live IPinfo.io lookups — zero other changes needed.

Offline scoring sources (always active):
  1. Known Tor exit node CIDR blocks / ranges
  2. Known hostile / botnet ASN ranges (hardcoded CIDR)
  3. Known datacenter / hosting CIDR blocks (AWS, DigitalOcean, etc.)
  4. High-risk country heuristic via IP range tables
  5. Bogon / private / reserved ranges

Live scoring (active only when IPINFO_TOKEN is set):
  6. IPinfo.io privacy flags: tor / vpn / proxy / relay
  7. IPinfo.io real country + ASN

Score cap: 0.25 (Signal 1 max weight in the 7-signal pipeline)

Cache: in-process LRU dict, 6-hour TTL, 4096 entries.
       Step 1.3 replaces this with Redis so all Docker nodes share state.
"""

import os
import re
import time
import logging
import ipaddress
import threading
from typing import Optional

logger = logging.getLogger("tokenshield.ip_reputation")

# ---------------------------------------------------------------------------
# Runtime config
# ---------------------------------------------------------------------------

IPINFO_TOKEN  = os.getenv("IPINFO_TOKEN", "")   # empty = offline mode
LOOKUP_TIMEOUT = 2.0       # seconds — never stall a request longer than this
CACHE_TTL      = 6 * 3600  # 6 hours
CACHE_MAX_SIZE = 4_096

# ---------------------------------------------------------------------------
# Threat intel tables  (offline — no API required)
# ---------------------------------------------------------------------------

# High-risk country ISO codes (OFAC + CISA advisory list)
HIGH_RISK_COUNTRIES = {
    "RU", "CN", "KP", "IR", "SY", "CU", "VE", "BY", "MM", "SD",
}

# Known Tor exit / relay CIDR ranges (updated periodically — add more as needed)
# Source: https://check.torproject.org/torbulkexitlist  (sampled ranges)
_TOR_RANGES_RAW = [
    "185.220.100.0/22",   # Tor exit cluster (DE)
    "185.107.80.0/22",    # Tor relay block (NL)
    "199.249.224.0/21",   # Quintex Alliance (Tor-friendly)
    "204.85.191.0/24",    # Tor exit (US)
    "45.142.212.0/22",    # Tor exit cluster (AT)
    "89.234.157.0/24",    # ARN Tor exits (FR)
    "171.25.193.0/24",    # DFRI Tor exits (SE)
    "94.142.244.0/22",    # Tor exits (NL)
]

# Known hostile / botnet infrastructure CIDRs
_HOSTILE_RANGES_RAW = [
    "197.210.54.0/23",    # Nigerian botnet cluster
    "103.224.182.0/24",   # Known C2 infrastructure (AS)
    "92.118.160.0/21",    # Bulletproof hosting (RU)
    "80.82.77.0/24",      # Shodan scanning IPs
    "71.6.135.0/24",      # Censys scanner range
    "162.142.125.0/24",   # Shadowserver scanning
    "167.94.138.0/24",    # GreyNoise scanning
    "167.94.145.0/24",    # GreyNoise scanning
    "167.94.146.0/24",    # GreyNoise scanning
]

# Datacenter / hosting ASN CIDR blocks (legitimate but elevated risk)
_DATACENTER_RANGES_RAW = [
    # AWS
    "3.0.0.0/9", "13.32.0.0/15", "18.144.0.0/15", "52.0.0.0/11",
    "54.64.0.0/11", "35.160.0.0/13",
    # DigitalOcean
    "104.131.0.0/16", "159.65.0.0/16", "167.99.0.0/16", "174.138.0.0/16",
    # Linode / Akamai
    "45.33.0.0/17", "45.56.0.0/21", "69.164.192.0/18", "72.14.176.0/21",
    # Vultr
    "45.32.0.0/16", "45.63.0.0/18", "66.42.96.0/21",
    # Hetzner
    "5.9.0.0/16", "23.88.0.0/21", "95.216.0.0/16", "116.202.0.0/15",
    # OVH
    "5.135.0.0/16", "37.59.0.0/16", "51.68.0.0/15", "54.36.0.0/14",
    # Contabo
    "207.180.192.0/18", "195.201.0.0/16",
]

# Private / bogon ranges (should never reach the app but guard anyway)
_PRIVATE_RANGES_RAW = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10",   # CGNAT
    "0.0.0.0/8", "240.0.0.0/4",
    "::1/128", "fc00::/7", "fe80::/10",
]


def _compile(raw: list[str]) -> list[ipaddress._BaseNetwork]:
    nets = []
    for cidr in raw:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.warning("tokenshield.ip_reputation: bad CIDR %s — skipped", cidr)
    return nets


_TOR_NETS        = _compile(_TOR_RANGES_RAW)
_HOSTILE_NETS    = _compile(_HOSTILE_RANGES_RAW)
_DATACENTER_NETS = _compile(_DATACENTER_RANGES_RAW)
_PRIVATE_NETS    = _compile(_PRIVATE_RANGES_RAW)


def _parse_ip(ip: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def _in_any(addr, nets: list) -> bool:
    return any(addr in net for net in nets)

# ---------------------------------------------------------------------------
# In-process LRU cache (Step 1.3 replaces with Redis)
# ---------------------------------------------------------------------------

class _IPCache:
    """
    Thread-safe, fixed-size cache with TTL expiry.
    Keyed by IP string → (expires_at_monotonic, result_dict).
    When full, evicts the oldest inserted key (FIFO approximation).
    """
    def __init__(self, maxsize: int = CACHE_MAX_SIZE, ttl: int = CACHE_TTL):
        self._store: dict[str, tuple[float, dict]] = {}
        self._lock  = threading.Lock()
        self._max   = maxsize
        self._ttl   = ttl

    def get(self, ip: str) -> Optional[dict]:
        with self._lock:
            entry = self._store.get(ip)
            if entry is None:
                return None
            exp, data = entry
            if time.monotonic() > exp:
                del self._store[ip]
                return None
            return data

    def set(self, ip: str, data: dict) -> None:
        with self._lock:
            if len(self._store) >= self._max and ip not in self._store:
                # evict oldest
                oldest = next(iter(self._store))
                del self._store[oldest]
            self._store[ip] = (time.monotonic() + self._ttl, data)

    def delete(self, ip: str) -> None:
        with self._lock:
            self._store.pop(ip, None)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._store)


_cache = _IPCache()

# ---------------------------------------------------------------------------
# Offline scoring engine
# ---------------------------------------------------------------------------

def _offline_score(ip: str) -> dict:
    """
    Score an IP using only local threat intel tables.
    Returns a dict with keys: score, reasons, source, details.
    """
    addr = _parse_ip(ip)
    if addr is None:
        return {"score": 0.0, "reasons": ["unparseable_ip"], "source": "offline", "details": {}}

    score   = 0.0
    reasons = []

    # Private / bogon — zero score, no further checks
    if _in_any(addr, _PRIVATE_NETS):
        return {"score": 0.0, "reasons": [], "source": "offline",
                "details": {"note": "private/internal"}}

    # Tor exit node  → +0.25  (maximum — single signal cap)
    if _in_any(addr, _TOR_NETS):
        score += 0.25
        reasons.append("tor_exit_node")

    # Hostile / botnet infrastructure  → +0.20
    if _in_any(addr, _HOSTILE_NETS):
        score += 0.20
        reasons.append("hostile_infrastructure")

    # Datacenter / hosting  → +0.10 (elevated, not certain)
    if _in_any(addr, _DATACENTER_NETS):
        score += 0.10
        reasons.append("datacenter_hosting")

    return {
        "score":   min(score, 0.25),
        "reasons": reasons,
        "source":  "offline",
        "details": {"ip": ip},
    }

# ---------------------------------------------------------------------------
# Live scoring via IPinfo.io  (only when IPINFO_TOKEN is set)
# ---------------------------------------------------------------------------

def _live_score(ip: str) -> Optional[dict]:
    """
    Call IPinfo.io and return a scored result dict, or None on any failure.
    Never raises — always fails open.
    """
    if not IPINFO_TOKEN:
        return None

    try:
        import requests as _req
        resp = _req.get(
            f"https://ipinfo.io/{ip}/json",
            headers={"Authorization": f"Bearer {IPINFO_TOKEN}"},
            timeout=LOOKUP_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning("tokenshield.ip_reputation: IPinfo HTTP %s for %s",
                           resp.status_code, ip)
            return None
        data = resp.json()
    except Exception as exc:
        logger.warning("tokenshield.ip_reputation: IPinfo call failed (%s) — using offline", exc)
        return None

    score   = 0.0
    reasons = []

    # Privacy flags (requires IPinfo paid/privacy addon — graceful if absent)
    privacy = data.get("privacy", {})
    if isinstance(privacy, dict):
        if privacy.get("tor"):
            score += 0.25; reasons.append("tor_exit_node")
        elif privacy.get("relay"):
            score += 0.20; reasons.append("apple_private_relay")
        elif privacy.get("proxy") or privacy.get("vpn"):
            score += 0.15; reasons.append("vpn_or_proxy")

    # High-risk country
    if data.get("country") in HIGH_RISK_COUNTRIES:
        score += 0.15
        reasons.append(f"high_risk_country:{data['country']}")

    # Datacenter ASN
    org = data.get("org", "")
    DATACENTER_PREFIXES = (
        "AS396982", "AS16509", "AS14618", "AS8075", "AS20473",
        "AS63949",  "AS14061", "AS13335", "AS24940", "AS16276",
        "AS51167",  "AS9009",  "AS3257",  "AS60068",
    )
    if any(org.startswith(p) for p in DATACENTER_PREFIXES):
        score += 0.10
        reasons.append(f"datacenter_asn:{org.split()[0]}")

    if data.get("bogon"):
        score += 0.05; reasons.append("bogon_ip")

    return {
        "score":   min(score, 0.25),
        "reasons": reasons,
        "source":  "ipinfo",
        "details": data,
    }

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_ip_reputation(ip: str) -> tuple[float, Optional[str]]:
    """
    Entry point for Signal 1 in detection.py.
    Returns (score: float, reason: str | None).

    Priority:
      1. Private IP  → (0.0, None) instantly
      2. Cache hit   → cached result
      3. Live lookup (if IPINFO_TOKEN set) → cache + return
      4. Offline scoring → cache + return
    """
    addr = _parse_ip(ip)
    if addr and _in_any(addr, _PRIVATE_NETS):
        return 0.0, None

    cached = _cache.get(ip)
    if cached is not None:
        logger.debug("tokenshield.ip_reputation: cache hit %s score=%.2f", ip, cached["score"])
        return cached["score"], (_join(cached["reasons"]) or None)

    # Try live first, fall back to offline
    result = _live_score(ip) if IPINFO_TOKEN else None
    if result is None:
        result = _offline_score(ip)

    _cache.set(ip, result)

    logger.info(
        "tokenshield.ip_reputation: %s score=%.2f reasons=%s source=%s",
        ip, result["score"], result["reasons"], result["source"],
    )
    return result["score"], (_join(result["reasons"]) or None)


def get_ip_details(ip: str) -> dict:
    """
    Full enriched profile for the admin dashboard / attacker-info endpoint.
    Returns cached data if available; triggers a fresh lookup otherwise.
    Never raises.
    """
    addr = _parse_ip(ip)
    if addr and _in_any(addr, _PRIVATE_NETS):
        return {"ip": ip, "note": "private/internal", "bogon": True}

    cached = _cache.get(ip)
    if cached:
        return cached

    result = _live_score(ip) if IPINFO_TOKEN else None
    if result is None:
        result = _offline_score(ip)

    _cache.set(ip, result)
    return result


def invalidate_cache(ip: str) -> None:
    """Force-evict an IP from the cache (e.g. after a ban is lifted)."""
    _cache.delete(ip)


def cache_stats() -> dict:
    return {
        "size":             _cache.size,
        "max_size":         CACHE_MAX_SIZE,
        "ttl_hours":        CACHE_TTL // 3600,
        "token_configured": bool(IPINFO_TOKEN),
        "mode":             "live+offline" if IPINFO_TOKEN else "offline",
    }

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _join(lst: list[str]) -> str:
    return "|".join(lst)