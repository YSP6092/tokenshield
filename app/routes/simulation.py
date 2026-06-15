"""
TokenShield Simulation Blueprint  (DEMO-READY FIX)
===================================================
Root cause fixes:
  BUG 1: @admin_token_required decorator stacking was broken.
          Fixed with a single combined decorator.

  BUG 2: /run-attack called run_full_scenario() which doesn't exist
          in attack_simulator.py. Now calls the existing full_scenario
          logic directly via the DB — no HTTP round-trip, no missing function.

  BUG 3: /start-attack, /mitigate, /reset required admin token.
          For the demo dashboard these now accept ANY valid token
          so the simulation buttons work without an admin account.
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
from functools import wraps

from simulation.network_controller import (
    resource_monitor,
    gns3_controller,
    trigger_attack_phase,
    trigger_mitigation_phase,
    reset_simulation,
    PHASE_NORMAL,
    PHASE_UNDER_ATTACK,
    PHASE_POST_MITIGATION,
)
from app.extensions import db

simulation_bp = Blueprint("simulation", __name__, url_prefix="/api/simulation")


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _get_current_user_and_session():
    """
    Extract user + session from Bearer token.
    Returns (user, session) or (None, None).
    """
    from app.models import Session, User
    import hashlib, jwt, os

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None
    token = auth[7:]

    try:
        secret  = os.getenv("JWT_SECRET_KEY", "jwt-secret-change-in-production")
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        user_id = payload.get("user_id")
    except Exception:
        return None, None

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    session    = Session.query.filter_by(token=token_hash, is_active=True).first()
    if not session:
        return None, None

    user = User.query.get(user_id)
    if not user or not user.is_active:
        return None, None

    session.last_activity = datetime.utcnow()
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()

    return user, session


def token_required_sim(f):
    """Require any valid token (user or admin) — used for phase control endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user, session = _get_current_user_and_session()
        if not user:
            return jsonify({"success": False, "message": "Authentication required"}), 401
        return f(*args, current_user=user, current_session=session, **kwargs)
    return decorated


def admin_token_required(f):
    """Require a valid admin token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user, session = _get_current_user_and_session()
        if not user:
            return jsonify({"success": False, "message": "Authentication required"}), 401
        if not user.is_admin:
            return jsonify({"success": False, "message": "Admin privileges required"}), 403
        return f(*args, current_user=user, current_session=session, **kwargs)
    return decorated


# ── Public endpoints (no auth needed for demo visibility) ────────────────────

@simulation_bp.route("/current", methods=["GET"])
def get_current():
    snapshot = resource_monitor.current()
    return jsonify({"success": True, "snapshot": snapshot}), 200


@simulation_bp.route("/history", methods=["GET"])
def get_history():
    try:
        n = min(int(request.args.get("n", 60)), 120)
    except (TypeError, ValueError):
        n = 60
    snapshots = resource_monitor.history(n)
    return jsonify({"success": True, "count": len(snapshots), "snapshots": snapshots}), 200


@simulation_bp.route("/comparison", methods=["GET"])
def get_comparison():
    comparison = resource_monitor.comparison()
    return jsonify({"success": True, "comparison": comparison}), 200


@simulation_bp.route("/topology", methods=["GET"])
def get_topology():
    topology = gns3_controller.get_topology()
    return jsonify({"success": True, "topology": topology}), 200


@simulation_bp.route("/status", methods=["GET"])
def get_status():
    snapshot = resource_monitor.current()
    phase    = snapshot.get("phase", PHASE_NORMAL)
    return jsonify({
        "success": True,
        "status": {
            "phase":            phase,
            "gns3_connected":   gns3_controller.connected,
            "monitor_running":  resource_monitor._running,
            "phase_timestamps": resource_monitor.phase_timestamps(),
            "current_snapshot": snapshot,
        }
    }), 200


# ── Phase control endpoints (any valid token — for demo) ─────────────────────

@simulation_bp.route("/start-attack", methods=["POST"])
@token_required_sim
def start_attack(current_user, current_session):
    data = request.get_json() or {}
    note = data.get("note", "manual")
    trigger_attack_phase()
    return jsonify({
        "success":   True,
        "phase":     PHASE_UNDER_ATTACK,
        "note":      note,
        "timestamp": datetime.utcnow().isoformat(),
        "message":   "Phase set to under_attack.",
    }), 200


@simulation_bp.route("/mitigate", methods=["POST"])
@token_required_sim
def mitigate(current_user, current_session):
    data        = request.get_json() or {}
    node_key    = data.get("node", "attacker")
    gns3_result = trigger_mitigation_phase()
    if node_key != "attacker":
        gns3_result = gns3_controller.isolate_node(node_key)
    return jsonify({
        "success":   True,
        "phase":     PHASE_POST_MITIGATION,
        "gns3":      gns3_result,
        "timestamp": datetime.utcnow().isoformat(),
        "message":   "Mitigation triggered.",
    }), 200


@simulation_bp.route("/reset", methods=["POST"])
@token_required_sim
def reset(current_user, current_session):
    gns3_result = reset_simulation()
    return jsonify({
        "success":   True,
        "phase":     PHASE_NORMAL,
        "gns3":      gns3_result,
        "timestamp": datetime.utcnow().isoformat(),
        "message":   "Simulation reset to normal.",
    }), 200


@simulation_bp.route("/phase", methods=["POST"])
@token_required_sim
def set_phase(current_user, current_session):
    data  = request.get_json() or {}
    phase = data.get("phase", PHASE_NORMAL)
    if phase == PHASE_UNDER_ATTACK:
        trigger_attack_phase()
    elif phase == PHASE_POST_MITIGATION:
        trigger_mitigation_phase()
    else:
        reset_simulation()
    return jsonify({"success": True, "phase": phase,
                    "timestamp": datetime.utcnow().isoformat()}), 200


# ── /run-attack — FIXED: calls attack DB logic directly ──────────────────────

@simulation_bp.route("/run-attack", methods=["POST"])
@token_required_sim
def run_attack(current_user, current_session):
    """
    Flips phase to under_attack AND writes a full attack scenario
    into the DB by calling the attack simulator logic directly.

    FIX: No longer tries to call non-existent run_full_scenario().
    Instead reuses the HACKER_PROFILES + build_details logic that
    already exists in attack_simulator.py via a direct Python call.
    """
    data        = request.get_json() or {}
    username    = data.get("username",    "demo")
    attack_type = data.get("attack_type", "token_theft")
    location    = data.get("location",    "moscow")
    amount      = data.get("amount",      5000)

    # 1. Flip phase
    trigger_attack_phase()

    # 2. Write attack data directly using the simulator's own helpers
    attack_result = {}
    try:
        from app.routes.attack_simulator import (
            HACKER_PROFILES, ATTACK_TYPES, build_details,
            calc_score, threat_level, hacker_dict,
            revoke_and_lock, make_attacker_session, ensure_victim_session,
        )
        from app.models import User, IncidentLog, BehaviorLog

        profile = HACKER_PROFILES.get(location, HACKER_PROFILES["moscow"])
        user    = User.query.filter_by(username=username).first()

        if not user:
            # Create demo user automatically if missing
            from app.models import User as UserModel
            import bcrypt
            pw_hash = bcrypt.hashpw(b"demo123", bcrypt.gensalt()).decode()
            user = UserModel(
                username="demo", email="demo@sim.local",
                password_hash=pw_hash, is_active=True, is_admin=False
            )
            db.session.add(user)
            db.session.flush()

        victim         = ensure_victim_session(user.id)
        sess, stolen   = make_attacker_session(user.id, profile)
        score, factors = calc_score(
            profile["ip"], profile["user_agent"],
            victim.ip_address, victim.user_agent,
            amount, attack_type
        )
        sess.anomaly_score = score
        level   = threat_level(score)
        revoked = revoke_and_lock(user.id, f"simulation_{attack_type}")

        db.session.add(IncidentLog(
            session_id    = sess.id,
            incident_type = attack_type,
            severity      = level,
            anomaly_score = score,
            action_taken  = "run_attack_simulation",
            details       = build_details(profile, attack_type, amount),
            ip_address    = profile["ip"],
            user_agent    = profile["user_agent"],
        ))
        db.session.add(BehaviorLog(
            session_id     = sess.id,
            action_type    = f"simulation_{attack_type}",
            ip_address     = profile["ip"],
            user_agent     = profile["user_agent"],
            endpoint       = "/api/simulation/run-attack",
            request_method = "POST",
        ))
        db.session.commit()

        type_info = ATTACK_TYPES.get(attack_type, {})
        attack_result = {
            "success": True,
            "summary": (
                f"Simulated {type_info.get('label', attack_type)} — "
                f"Score: {int(score * 100)}% ({level.upper()}) — "
                f"{len(revoked)} sessions revoked"
            ),
            "anomaly_score":    score,
            "threat_level":     level,
            "sessions_revoked": revoked,
            "hacker":           hacker_dict(profile),
        }

    except Exception as e:
        # Even if attack data fails, phase is already set — report partial success
        attack_result = {
            "success": False,
            "note":    f"Phase set to under_attack. Attack data error: {str(e)}",
        }

    return jsonify({
        "success":       True,
        "phase":         PHASE_UNDER_ATTACK,
        "attack_result": attack_result,
        "timestamp":     datetime.utcnow().isoformat(),
        "message":       f"Attack '{attack_type}' triggered. Phase = under_attack.",
    }), 200