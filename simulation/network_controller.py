"""
TokenShield Network Controller — Step 3.5 + CPU Spike Fix
==========================================================
FIX: Added simulated CPU/RAM spike during attack phase so the
simulation dashboard charts show a visible difference between
normal traffic and attack traffic.

During under_attack phase, synthetic load is added to snapshots:
  CPU: +40–65% spike with jitter
  RAM: +8–12% spike
  Connections: +80–150 spike
  Network: +200–400 KB/s spike

This makes the Before/During/After comparison table meaningful
for demo purposes without actually stressing the host machine.
"""

import time
import random
import threading
import logging
from collections import deque
from datetime import datetime

import psutil

try:
    import gns3fy
    GNS3FY_AVAILABLE = True
except ImportError:
    GNS3FY_AVAILABLE = False

logger = logging.getLogger(__name__)

PHASE_NORMAL          = "normal"
PHASE_UNDER_ATTACK    = "under_attack"
PHASE_POST_MITIGATION = "post_mitigation"


class ResourceMonitor:
    MAX_HISTORY = 120

    def __init__(self):
        self._lock    = threading.Lock()
        self._history = deque(maxlen=self.MAX_HISTORY)
        self._phase   = PHASE_NORMAL
        self._phase_timestamps = {
            PHASE_NORMAL:          None,
            PHASE_UNDER_ATTACK:    None,
            PHASE_POST_MITIGATION: None,
        }
        self._thread  = None
        self._running = False

        net = psutil.net_io_counters()
        self._prev_net_sent = net.bytes_sent
        self._prev_net_recv = net.bytes_recv
        self._prev_net_time = time.monotonic()

        # Track attack start time for ramping effect
        self._attack_start_time = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._collect_loop,
            name="ResourceMonitor",
            daemon=True,
        )
        self._thread.start()
        logger.info("ResourceMonitor started")

    def stop(self):
        self._running = False

    def set_phase(self, phase: str):
        if phase not in (PHASE_NORMAL, PHASE_UNDER_ATTACK, PHASE_POST_MITIGATION):
            raise ValueError(f"Unknown phase: {phase!r}")
        with self._lock:
            self._phase = phase
            self._phase_timestamps[phase] = datetime.utcnow().isoformat()
            if phase == PHASE_UNDER_ATTACK:
                self._attack_start_time = time.monotonic()
            else:
                self._attack_start_time = None
        logger.info("Phase changed to %s", phase)

    def current(self) -> dict:
        with self._lock:
            if self._history:
                return dict(self._history[-1])
            return {}

    def history(self, n: int = 60) -> list:
        with self._lock:
            items = list(self._history)
        return items[-n:]

    def comparison(self) -> dict:
        with self._lock:
            snapshots = list(self._history)
            timestamps = dict(self._phase_timestamps)

        buckets: dict[str, list] = {
            PHASE_NORMAL:          [],
            PHASE_UNDER_ATTACK:    [],
            PHASE_POST_MITIGATION: [],
        }
        for s in snapshots:
            p = s.get("phase", PHASE_NORMAL)
            if p in buckets:
                buckets[p].append(s)

        result = {}
        for phase, rows in buckets.items():
            if not rows:
                continue
            result[phase] = {
                "cpu":    round(sum(r["cpu_percent"] for r in rows) / len(rows), 2),
                "ram":    round(sum(r["ram_percent"] for r in rows) / len(rows), 2),
                "net_kb": round(
                    sum(r["net_sent_kb"] + r["net_recv_kb"] for r in rows) / len(rows), 2
                ),
                "sample_count": len(rows),
            }
        result["phase_timestamps"] = timestamps
        return result

    def phase_timestamps(self) -> dict:
        with self._lock:
            return dict(self._phase_timestamps)

    def _collect_loop(self):
        while self._running:
            try:
                snapshot = self._take_snapshot()
                with self._lock:
                    self._history.append(snapshot)
            except Exception as exc:
                logger.warning("ResourceMonitor snapshot error: %s", exc)
            time.sleep(1)

    def _take_snapshot(self) -> dict:
        now = time.monotonic()

        cpu = psutil.cpu_percent(interval=None)

        mem = psutil.virtual_memory()
        ram_percent = mem.percent
        ram_used_mb = round(mem.used / 1_048_576, 1)

        net     = psutil.net_io_counters()
        elapsed = max(now - self._prev_net_time, 0.001)
        sent_kb = round((net.bytes_sent - self._prev_net_sent) / elapsed / 1024, 2)
        recv_kb = round((net.bytes_recv - self._prev_net_recv) / elapsed / 1024, 2)
        self._prev_net_sent = net.bytes_sent
        self._prev_net_recv = net.bytes_recv
        self._prev_net_time = now

        try:
            connections = len(psutil.net_connections(kind="inet"))
        except (psutil.AccessDenied, OSError):
            connections = 0

        with self._lock:
            phase = self._phase
            attack_start = self._attack_start_time

        # ── Inject simulated attack load ──────────────────────────────────────
        # Real Docker container CPU stays low (no actual attack computation),
        # so we add a synthetic spike to make the charts meaningful for demo.
        if phase == PHASE_UNDER_ATTACK and attack_start is not None:
            elapsed_attack = now - attack_start

            # Ramp up over first 10 seconds, then sustain with jitter
            ramp = min(elapsed_attack / 10.0, 1.0)

            cpu_spike  = ramp * random.uniform(42, 68)
            ram_spike  = ramp * random.uniform(8, 14)
            net_spike  = ramp * random.uniform(180, 420)
            conn_spike = int(ramp * random.uniform(80, 160))

            cpu         = min(cpu + cpu_spike, 98.0)
            ram_percent = min(ram_percent + ram_spike, 95.0)
            recv_kb     = recv_kb + net_spike
            connections = connections + conn_spike

        elif phase == PHASE_POST_MITIGATION:
            # After mitigation: drop back toward normal but slightly elevated
            cpu         = max(cpu * 0.85, cpu - random.uniform(5, 15))
            recv_kb     = max(recv_kb * 0.9, 0)

        return {
            "timestamp":   datetime.utcnow().isoformat(),
            "cpu_percent": round(cpu, 1),
            "ram_percent": round(ram_percent, 1),
            "ram_used_mb": ram_used_mb,
            "net_sent_kb": round(sent_kb, 2),
            "net_recv_kb": round(recv_kb, 2),
            "connections": connections,
            "phase":       phase,
        }


class GNS3Controller:
    NODE_MAP = {
        "attacker":  "attacker",
        "user1":     "user1",
        "user2":     "user2",
        "user3":     "user3",
        "server":    "flask-server",
    }

    def __init__(self, host=None, port=None, project_name=None):
        import os
        self._host         = host         or os.getenv("GNS3_HOST", "localhost")
        self._port         = int(port     or os.getenv("GNS3_PORT", 3080))
        self._project_name = project_name or os.getenv("GNS3_PROJECT", "TokenShield")
        self._server       = None
        self._project      = None
        self._connected    = False
        self._node_cache   = {}

        if GNS3FY_AVAILABLE:
            self._try_connect()
        else:
            logger.warning("gns3fy not installed — GNS3 integration disabled.")

    def _try_connect(self):
        try:
            self._server  = gns3fy.Gns3Connector(url=f"http://{self._host}:{self._port}")
            self._project = gns3fy.Project(name=self._project_name, connector=self._server)
            self._project.get()
            self._connected = True
        except Exception as exc:
            self._connected = False
            logger.warning("GNS3Controller could not connect: %s", exc)

    def _get_node(self, node_name):
        if not self._connected:
            return None
        if node_name in self._node_cache:
            return self._node_cache[node_name]
        try:
            self._project.get_nodes()
            for node in self._project.nodes:
                if node.name == node_name:
                    self._node_cache[node_name] = node
                    return node
        except Exception as exc:
            logger.error("GNS3 get_node(%s) failed: %s", node_name, exc)
        return None

    @property
    def connected(self):
        return self._connected

    def isolate_node(self, node_key="attacker"):
        node_name = self.NODE_MAP.get(node_key, node_key)
        if not GNS3FY_AVAILABLE or not self._connected:
            return {"success": True, "node": node_name, "action": "isolated", "mode": "stub"}
        node = self._get_node(node_name)
        if node is None:
            return {"success": False, "node": node_name, "error": f"Node '{node_name}' not found"}
        try:
            node.suspend()
            return {"success": True, "node": node_name, "action": "isolated", "mode": "gns3"}
        except Exception as exc:
            return {"success": False, "node": node_name, "error": str(exc)}

    def restore_node(self, node_key="attacker"):
        node_name = self.NODE_MAP.get(node_key, node_key)
        if not GNS3FY_AVAILABLE or not self._connected:
            return {"success": True, "node": node_name, "action": "restored", "mode": "stub"}
        node = self._get_node(node_name)
        if node is None:
            return {"success": False, "node": node_name, "error": f"Node '{node_name}' not found"}
        try:
            node.start()
            return {"success": True, "node": node_name, "action": "restored", "mode": "gns3"}
        except Exception as exc:
            return {"success": False, "node": node_name, "error": str(exc)}

    def get_topology(self):
        if not GNS3FY_AVAILABLE or not self._connected:
            return self._stub_topology()
        try:
            self._project.get_nodes()
            self._project.get_links()
            nodes = [{"id": n.node_id, "name": n.name, "status": n.status,
                      "type": n.node_type, "x": getattr(n,"x",0), "y": getattr(n,"y",0)}
                     for n in self._project.nodes]
            links = [{"id": lk.link_id,
                      "nodes": [nd.get("node_id","") for nd in (lk.nodes or [])]}
                     for lk in self._project.links]
            return {"connected": True, "nodes": nodes, "links": links}
        except Exception as exc:
            return {**self._stub_topology(), "error": str(exc)}

    @staticmethod
    def _stub_topology():
        return {
            "connected": False, "mode": "stub",
            "nodes": [
                {"id":"node-nat",     "name":"NAT Cloud",    "status":"started","type":"cloud",   "x":0,    "y":-200},
                {"id":"node-router",  "name":"Router",       "status":"started","type":"router",  "x":0,    "y":-100},
                {"id":"node-switch",  "name":"Switch",       "status":"started","type":"switch",  "x":0,    "y":0},
                {"id":"node-server",  "name":"flask-server", "status":"started","type":"docker",  "x":-200, "y":120, "ip":"172.20.0.2"},
                {"id":"node-user1",   "name":"user1",        "status":"started","type":"docker",  "x":-100, "y":220, "ip":"172.20.0.10"},
                {"id":"node-user2",   "name":"user2",        "status":"started","type":"docker",  "x":0,    "y":220, "ip":"172.20.0.11"},
                {"id":"node-user3",   "name":"user3",        "status":"started","type":"docker",  "x":100,  "y":220, "ip":"172.20.0.12"},
                {"id":"node-attacker","name":"attacker",     "status":"started","type":"docker",  "x":250,  "y":120, "ip":"172.20.0.99"},
            ],
            "links": [
                {"id":"link-1","nodes":["node-nat",    "node-router"]},
                {"id":"link-2","nodes":["node-router", "node-switch"]},
                {"id":"link-3","nodes":["node-switch", "node-server"]},
                {"id":"link-4","nodes":["node-switch", "node-user1"]},
                {"id":"link-5","nodes":["node-switch", "node-user2"]},
                {"id":"link-6","nodes":["node-switch", "node-user3"]},
                {"id":"link-7","nodes":["node-switch", "node-attacker"]},
            ],
        }


# ── Singletons ────────────────────────────────────────────────────────────────
resource_monitor = ResourceMonitor()
gns3_controller  = GNS3Controller()


def start_monitor():
    resource_monitor.start()

def trigger_attack_phase():
    resource_monitor.set_phase(PHASE_UNDER_ATTACK)

def trigger_mitigation_phase():
    resource_monitor.set_phase(PHASE_POST_MITIGATION)
    result = gns3_controller.isolate_node("attacker")
    logger.info("Mitigation triggered: %s", result)
    return result

def reset_simulation():
    resource_monitor.set_phase(PHASE_NORMAL)
    result = gns3_controller.restore_node("attacker")
    logger.info("Simulation reset: %s", result)
    return result