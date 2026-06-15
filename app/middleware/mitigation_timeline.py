"""
TokenShield — Mitigation Timeline Recorder  (Step 3.5)
=======================================================
File: app/middleware/mitigation_timeline.py

Tracks each of the 8 mitigation steps in real-time.
Used by:
  - app/middleware/detection.py  (calls record_step() during auto-mitigation)
  - app/security_routes.py       (SSE stream + REST endpoints)
  - frontend simulation_dashboard.html (timeline panel)

Design:
  - In-memory dict keyed by incident_id → list of step events
  - SSE subscriber queue list for live push to dashboard
  - Thread-safe with a single lock
  - No Redis dependency — timeline lives in process memory
    (lost on restart, which is fine for a demo/simulation)
"""

import threading
import queue
import time
import json
from datetime import datetime, timezone

# ── Constants ─────────────────────────────────────────────────────────────────

STEPS = [
    {"step": 1, "name": "Token Revocation",         "target": "Redis",     "nominal_ms": 0},
    {"step": 2, "name": "IP Block → Redis",          "target": "Redis",     "nominal_ms": 12},
    {"step": 3, "name": "IP Block → Nginx Reload",   "target": "Nginx",     "nominal_ms": 28},
    {"step": 4, "name": "Device Fingerprint Ban",    "target": "Redis",     "nominal_ms": 35},
    {"step": 5, "name": "Account 2FA Lock",          "target": "Database",  "nominal_ms": 45},
    {"step": 6, "name": "Coordinated Attack Check",  "target": "Database",  "nominal_ms": 60},
    {"step": 7, "name": "Email Alert",               "target": "SMTP",      "nominal_ms": 80},
    {"step": 8, "name": "Dashboard SSE Push",        "target": "WebSocket", "nominal_ms": 100},
]

STEP_BY_NUM = {s["step"]: s for s in STEPS}

# ── In-process state ──────────────────────────────────────────────────────────

_lock:    threading.Lock             = threading.Lock()
_store:   dict[str, list]            = {}   # incident_id → [step_event, ...]
_queues:  list[queue.Queue]          = []   # SSE subscriber queues


# ── Core API ──────────────────────────────────────────────────────────────────

def record_step(incident_id: str, step_number: int, status: str,
                actual_ms: float, detail: str = "") -> dict:
    """
    Record one mitigation step completion and push it to all SSE subscribers.

    Call this from detection.py or security_routes.py after each step runs.

    Args:
        incident_id:  str(incident.id) from IncidentLog
        step_number:  1–8
        status:       "ok" | "error" | "skipped"
        actual_ms:    elapsed milliseconds since mitigation started
        detail:       short human-readable note (e.g. "IP 1.2.3.4 → blocklist")

    Returns the event dict that was recorded.
    """
    meta = STEP_BY_NUM.get(step_number, {})
    event = {
        "incident_id": incident_id,
        "step":        step_number,
        "name":        meta.get("name", f"Step {step_number}"),
        "target":      meta.get("target", "—"),
        "nominal_ms":  meta.get("nominal_ms", 0),
        "actual_ms":   round(actual_ms, 1),
        "status":      status,
        "detail":      detail,
        "ts":          datetime.now(timezone.utc).isoformat(),
    }

    with _lock:
        _store.setdefault(incident_id, []).append(event)

        dead = []
        for q in _queues:
            try:
                q.put_nowait(event)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _queues.remove(q)

    return event


def get_timeline(incident_id: str) -> list:
    """Return all recorded steps for one incident."""
    with _lock:
        return list(_store.get(incident_id, []))


def get_all_summaries(limit: int = 50) -> list:
    """
    Return lightweight summary dicts for the most recent incidents,
    newest first, capped at `limit`.
    """
    with _lock:
        items = list(_store.items())

    items.sort(key=lambda kv: kv[1][0]["ts"] if kv[1] else "", reverse=True)
    result = []
    for incident_id, steps in items[:limit]:
        ok    = sum(1 for s in steps if s["status"] == "ok")
        total = len(steps)
        result.append({
            "incident_id": incident_id,
            "steps_done":  total,
            "steps_ok":    ok,
            "total_steps": 8,
            "total_ms":    max((s["actual_ms"] for s in steps), default=0),
            "status":      "complete" if ok == 8 else "partial" if total > 0 else "pending",
            "first_ts":    steps[0]["ts"] if steps else None,
        })
    return result


def subscribe() -> queue.Queue:
    """
    Register a new SSE subscriber.  Returns a Queue that will receive
    step event dicts as they are recorded.  Call unsubscribe() when done.
    """
    q = queue.Queue(maxsize=300)
    with _lock:
        _queues.append(q)
    return q


def unsubscribe(q: queue.Queue) -> None:
    """Remove an SSE subscriber queue."""
    with _lock:
        try:
            _queues.remove(q)
        except ValueError:
            pass


def subscriber_count() -> int:
    with _lock:
        return len(_queues)