# TokenShield — Complete Setup & Run Guide

AI-Powered Banking Security with Simulated Network Environment  
NeoVault Digital Banking Platform · Final Year Project

---

## Project Structure

```
your-project/
│
├── app/                          ← Flask application
│   ├── __init__.py               ← create_app() factory  ← PATCH NEEDED
│   ├── extensions.py             ← db = SQLAlchemy()
│   ├── models.py                 ← all database models
│   ├── utils.py                  ← token_required, hash_token, etc.
│   ├── main_routes.py            ← page routes           ← PATCH NEEDED
│   ├── banking_routes.py         ← /api/banking/*
│   ├── security_routes.py        ← /api/security/*
│   ├── dashboard_routes.py       ← /api/dashboard/*
│   ├── email_service.py          ← alert emails
│   ├── google_auth.py            ← Google OAuth
│   └── routes/
│       ├── auth.py               ← /api/auth/*
│       ├── admin.py              ← /api/admin/*
│       ├── attack_simulator.py   ← /api/attack/*
│       └── simulation.py         ← /api/simulation/*    ← NEW (Step 2)
│
├── simulation/                   ← Simulation layer      ← NEW FOLDER
│   ├── __init__.py
│   ├── network_controller.py     ← psutil + GNS3        ← NEW (Step 1)
│   ├── traffic_simulator.py      ← normal user script   ← NEW (Step 5)
│   ├── attacker.py               ← attacker script      ← NEW (Step 6)
│   └── locustfile.py             ← Locust definition    ← NEW (Step 7)
│
├── frontend/                     ← HTML pages
│   ├── simulation_dashboard.html ← NEW dashboard        ← NEW (Step 8)
│   ├── admin.html
│   ├── login.html
│   ├── neovault_dashboard_pro.html
│   ├── security_dashboard_user.html
│   ├── security_engine.html
│   └── js/
│       ├── app.js
│       ├── device-fingerprint.js
│       └── banking-security-monitor.js
│
├── scripts/
│   └── setup_database.py         ← DB init + default users
│
├── Dockerfile                    ← NEW (Step 9)
├── docker-compose.yml            ← NEW (Step 9)
├── requirements.txt
├── run.py
└── .env                          ← create this yourself (see below)
```

---

## Step 1 — Apply the Two Code Patches

### Patch A: `app/__init__.py` (create_app function)

Inside the `with app.app_context():` block, add these lines alongside the
existing blueprint registrations:

```python
# ADD these two lines with the other blueprint imports:
from app.routes.simulation import simulation_bp
app.register_blueprint(simulation_bp)

# ADD these three lines AFTER db.create_all():
from simulation.network_controller import start_monitor
start_monitor()
print("✅ Resource monitor started")
```

Your complete block should look like this:

```python
with app.app_context():
    from app.main_routes import main_bp
    from app.routes.auth import auth_bp
    from app.banking_routes import banking_bp
    from app.dashboard_routes import dashboard_bp
    from app.security_routes import security_bp
    from app.routes.attack_simulator import attack_bp
    from app import dashboard_routes
    from app.google_auth import google_bp
    from app.routes.admin import admin_bp
    from app.routes.simulation import simulation_bp          # ← ADD

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(banking_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(attack_bp)
    app.register_blueprint(google_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(simulation_bp)                    # ← ADD
    dashboard_routes.register_dashboard_blueprints(app)

    db.create_all()

    from simulation.network_controller import start_monitor  # ← ADD
    start_monitor()                                          # ← ADD
    print("✅ Resource monitor started")                    # ← ADD

    print("✅ Database initialized successfully")
    print("✅ All blueprints registered successfully")
```

### Patch B: `app/main_routes.py`

Add this route after the existing `/security-engine` route:

```python
@main_bp.route('/simulation')
def simulation_dashboard():
    """Serve the GNS3 + resource monitoring simulation dashboard"""
    return send_from_directory('../frontend', 'simulation_dashboard.html')
```

---

## Step 2 — Create the `.env` File

Create a file called `.env` in your project root:

```env
SECRET_KEY=tokenshield-secret-change-me
JWT_SECRET_KEY=jwt-secret-change-me
DATABASE_URL=sqlite:///tokenshield.db
FLASK_ENV=development
FLASK_DEBUG=1

# GNS3 (leave as-is if GNS3 is not installed — app works without it)
GNS3_HOST=localhost
GNS3_PORT=3080
GNS3_PROJECT=TokenShield

# Google OAuth (optional — leave blank to disable Google login)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Email alerts (optional)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=
MAIL_PASSWORD=
```

---

## Step 3 — Install Dependencies

```bash
# Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate          # Mac/Linux
# venv\Scripts\activate           # Windows

# Install all packages
pip install -r requirements.txt
```

---

## Step 4 — Initialise the Database

```bash
python scripts/setup_database.py
```

This creates:
- `tokenshield.db` with all tables
- Admin user: `admin` / `admin123`
- Demo user:  `demo`  / `demo123`

---

## METHOD A — Run Without Docker (Simplest for Development)

### Terminal 1: Start Flask

```bash
source venv/bin/activate
python run.py
```

Server starts at http://localhost:5001

### Terminal 2: Start Normal Traffic (Optional)

```bash
source venv/bin/activate
python simulation/traffic_simulator.py --host localhost --username alice
```

Open a second terminal and run another user:

```bash
python simulation/traffic_simulator.py --host localhost --username bob
```

### Terminal 3: Run Attacker (Optional)

```bash
source venv/bin/activate
python simulation/attacker.py --host localhost --victim demo
```

### Terminal 4: Start Locust (Optional)

```bash
source venv/bin/activate
locust -f simulation/locustfile.py --host=http://localhost:5001
```

Open Locust UI at http://localhost:8089  
Set: 3 normal users, 1 attacker, spawn rate 1/s → Start

---

## METHOD B — Run With Docker Compose (Full Simulation)

### Prerequisites
- Docker Desktop installed and running
- `docker --version` works in terminal

### Start Everything

```bash
# Build images and start all 5 containers
docker-compose up --build

# Or run in background:
docker-compose up --build -d
```

This starts:
| Container    | IP           | Role                          |
|--------------|--------------|-------------------------------|
| flask-server | 172.20.0.2   | NeoVault + TokenShield engine |
| user1        | 172.20.0.3   | Normal banking traffic (alice)|
| user2        | 172.20.0.4   | Normal banking traffic (bob)  |
| user3        | 172.20.0.5   | Normal banking traffic (carol)|
| attacker     | 172.20.0.99  | Attack simulation             |

### View Logs

```bash
# All containers
docker-compose logs -f

# Just the Flask server
docker-compose logs -f flask-server

# Just the attacker
docker-compose logs -f attacker
```

### Stop

```bash
docker-compose down          # stop (keeps database)
docker-compose down -v       # stop + wipe database (fresh start)
```

### Reset Between Demos

```bash
docker-compose down -v && docker-compose up --build -d
```

---

## METHOD C — With GNS3 (Full Network Simulation)

### Prerequisites
1. GNS3 for Mac installed: https://gns3.com/software/download
2. Docker Desktop installed
3. GNS3 server running (open GNS3 app)

### GNS3 Setup (one-time, ~2 hours)

1. Open GNS3 → File → New Project → Name: `TokenShield`
2. Add Docker template: Edit → Preferences → Docker → Add
   - Image: `python:3.11-slim`
   - Name: `flask-server`
   - Adapters: 1
3. Repeat for `user1`, `user2`, `user3`, `attacker`
4. Add a NAT cloud node from the toolbar
5. Add an Ethernet switch from the toolbar
6. Drag nodes into the canvas and draw links:
   ```
   NAT Cloud ── Router (optional) ── Switch ── flask-server
                                            ├── user1
                                            ├── user2
                                            ├── user3
                                            └── attacker
   ```
7. Right-click each Docker node → Configure → set the startup command to
   match what docker-compose.yml does for that container
8. Start all nodes

### Enable GNS3 in the App

Uncomment in requirements.txt:
```
gns3fy==0.8.0
```

Then:
```bash
pip install gns3fy
```

The app auto-connects to GNS3 at localhost:3080 on startup. When GNS3 is
connected, the topology badge shows "GNS3 LIVE" and the Mitigate button
actually suspends the attacker container in GNS3.

---

## Dashboard URLs

| Dashboard              | URL                              | Who uses it     |
|------------------------|----------------------------------|-----------------|
| Landing page           | http://localhost:5001            | Everyone        |
| Login / Register       | http://localhost:5001/login      | Everyone        |
| Banking dashboard      | http://localhost:5001/dashboard  | Demo user       |
| Security dashboard     | http://localhost:5001/security-dashboard | Demo user |
| **Simulation dashboard** | **http://localhost:5001/simulation** | **Presenter** |
| Admin command center   | http://localhost:5001/admin      | Admin user      |
| Security engine        | http://localhost:5001/security-engine | Admin    |
| Locust load test UI    | http://localhost:8089            | Locust only     |

---

## Demo Sequence (Presentation)

Follow this exact sequence during the viva:

### Step 0 — Setup (before examiner enters room)
```bash
# Reset everything to clean state
curl -X POST http://localhost:5001/api/attack/reset-engine \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```
Or click **Reset Engine** button on the Admin dashboard.

Have open in separate browser tabs:
1. `localhost:5001/simulation` — Simulation Dashboard (main screen)
2. `localhost:5001/admin` — Admin Command Center
3. `localhost:8089` — Locust (if using)

### Step 1 — Show Normal Traffic (2 minutes)
- Point to the topology SVG — all nodes green, traffic particles flowing
- Point to CPU/RAM charts — flat baseline (10-20% CPU, normal RAM)
- Point to the stat strip — active sessions, zero threats
- Explain what each component is

### Step 2 — Run the Attack (3 minutes)
Click **⚡ Run Attack** on the simulation dashboard (or Locust attacker).

Watch in real time:
- Phase banner turns amber: "⚠ ATTACK IN PROGRESS"
- CPU/RAM charts spike upward
- Admin dashboard: incident cards appear, anomaly score climbs
- Attacker node in topology pulses red
- Security engine shows 85%+ anomaly score

### Step 3 — Trigger Mitigation (1 minute)
Click **🛡 Mitigate** on the simulation dashboard.

Watch in real time:
- Phase banner turns cyan: "✓ THREAT MITIGATED"
- Attacker link turns red dashed, red ✕ appears over node
- CPU/RAM graphs drop back to baseline
- "ISOLATED" label appears on attacker
- Admin: sessions revoked count increments

### Step 4 — Show Comparison Table (1 minute)
Point to the **Before · During · After** table:
- Before: CPU ~15%, RAM ~55%
- During: CPU ~75%, RAM ~68% (Δ +60%)
- After:  CPU ~18%, RAM ~56% (Δ -57%)

This is measurable, verifiable proof of both attack impact and mitigation.

### Step 5 — Answer Guide Questions
See Section 11 of the project documentation for anticipated Q&A.

---

## Troubleshooting

### "Module 'simulation' not found"
Make sure `simulation/__init__.py` exists (empty file). Run from project root,
not from inside the `app/` folder.

### Flask server crashes on start
Check that all blueprint registrations in `create_app()` match the import
paths exactly. The `simulation_bp` import is `from app.routes.simulation`.

### "Demo user not found" during attack
Run `python scripts/setup_database.py` to create the demo user, or register
manually at `localhost:5001/login`.

### GNS3 says "not connected" (stub mode)
This is normal when GNS3 is not installed. The app works fully without GNS3.
The topology shows the stub layout and the Mitigate button logs a stub
response instead of calling the GNS3 API.

### Docker containers can't reach flask-server
The `depends_on: service_healthy` condition waits for the healthcheck to pass.
Flask must be up and `/health` must return 200 before user/attacker containers
start. If Flask is slow, increase `start_period` in Dockerfile HEALTHCHECK.

### Charts not updating
The simulation blueprint polls `/api/simulation/history`. Make sure the
blueprint is registered and `start_monitor()` was called in `create_app()`.
Check browser console for 401 (auth) or 404 (route missing) errors.

### Locust users get 403 (requires_2fa)
A previous attack set `failed_login_attempts = 99` on the demo/alice/bob
accounts. Click **Reset Engine** on the admin dashboard, or call:
```bash
curl -X POST http://localhost:5001/api/attack/reset-engine \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

---

## API Reference — Simulation Endpoints

| Method | Path                           | Auth  | Description                      |
|--------|--------------------------------|-------|----------------------------------|
| GET    | /api/simulation/current        | —     | Latest psutil snapshot           |
| GET    | /api/simulation/history?n=60   | —     | Last N snapshots                 |
| GET    | /api/simulation/comparison     | —     | Per-phase averages               |
| GET    | /api/simulation/topology       | —     | GNS3 topology (or stub)          |
| GET    | /api/simulation/status         | —     | Overall simulation state         |
| POST   | /api/simulation/start-attack   | admin | Phase → under_attack             |
| POST   | /api/simulation/mitigate       | admin | Phase → post_mitigation + GNS3   |
| POST   | /api/simulation/reset          | admin | Phase → normal + GNS3 restore    |
| POST   | /api/simulation/run-attack     | admin | Flip phase + fire attack scenario |

---

*TokenShield Final Year Project — All files complete*