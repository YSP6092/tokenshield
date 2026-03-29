# 🛡️ TokenShield

**AI-Powered Session Hijacking Detection & Automated Mitigation System**

TokenShield is an enterprise-grade security solution that leverages machine learning to detect and prevent session hijacking attacks in real-time. Built with cutting-edge anomaly detection algorithms, it provides automated threat response while maintaining seamless user experience.

---

## 🚀 Key Features

### Core Security
- **Real-Time Threat Detection**: ML-powered anomaly detection using Isolation Forest
- **Automated Response**: Instant session revocation on confirmed threats
- **Behavioral Analysis**: 8-dimensional feature engineering for precision detection
- **JWT Authentication**: Secure token-based session management

### Intelligence & Analytics
- **Adaptive Learning**: Continuous model improvement from behavioral patterns
- **Risk Scoring**: Granular threat classification (Normal/Suspicious/Critical)
- **Forensic Logging**: Comprehensive incident tracking and audit trails
- **Predictive Analytics**: Proactive threat identification

### Administration
- **Live Dashboard**: Real-time monitoring with auto-refresh
- **Visual Analytics**: Interactive charts and threat visualization
- **Manual Controls**: Administrative override and session management
- **Alert System**: Instant notifications on critical events

---

## 🏗️ Architecture

```
┌─────────────────┐
│   Web Client    │
└────────┬────────┘
         │
    ┌────▼────┐
    │  Flask  │
    │   API   │
    └────┬────┘
         │
    ┌────▼──────────────────┐
    │  Authentication       │
    │  & Session Manager    │
    └────┬──────────────────┘
         │
    ┌────▼──────────────────┐
    │  Behavior Logger      │
    │  & Feature Extractor  │
    └────┬──────────────────┘
         │
    ┌────▼──────────────────┐
    │  Isolation Forest     │
    │  Anomaly Detector     │
    └────┬──────────────────┘
         │
    ┌────▼──────────────────┐
    │  Automated Response   │
    │  & Mitigation Engine  │
    └───────────────────────┘
```

---

## 📊 Detection Features

TokenShield analyzes 8 behavioral dimensions:

1. **IP Address Change**: Geographic consistency validation
2. **User-Agent Variation**: Device fingerprint analysis
3. **Action Timing**: Average time between requests
4. **Request Velocity**: Actions per minute calculation
5. **Session Duration**: Total active time tracking
6. **Navigation Patterns**: Unique pages visited
7. **Geographic Deviation**: Location consistency scoring
8. **Temporal Analysis**: Time-of-day behavior encoding

---

## 🛠️ Technology Stack

**Backend**
- Python 3.9+
- Flask (Web Framework)
- SQLAlchemy (ORM)
- PyJWT (Authentication)
- SQLite (Database)

**Machine Learning**
- Scikit-learn (Isolation Forest)
- Pandas (Data Processing)
- NumPy (Numerical Operations)
- Joblib (Model Persistence)

**Frontend**
- HTML5/CSS3
- Vanilla JavaScript
- Chart.js (Visualizations)

---

## 📦 Installation

### Prerequisites
- Python 3.9 or higher
- pip package manager
- Git

### Setup Steps

1. **Clone Repository**
```bash
git clone https://github.com/yourusername/token-shield.git
cd token-shield
```

2. **Create Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure Environment**
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. **Initialize Database**
```bash
python scripts/init_db.py
```

6. **Train ML Model**
```bash
python ml/generate_data.py
python ml/train_model.py
```

7. **Run Application**
```bash
python run.py
```

Access the application at `http://localhost:5000`

---

## 📁 Project Structure

```
token-shield/
│
├── app/
│   ├── __init__.py          # Flask application factory
│   ├── models.py            # Database models
│   ├── routes.py            # API endpoints
│   ├── auth.py              # Authentication logic
│   ├── detection.py         # ML detection engine
│   └── utils.py             # Helper functions
│
├── ml/
│   ├── generate_data.py     # Training data generator
│   ├── train_model.py       # Model training script
│   └── model.pkl            # Trained model
│
├── frontend/
│   ├── index.html           # Login page
│   ├── dashboard.html       # User dashboard
│   ├── admin.html           # Admin panel
│   ├── css/
│   │   └── styles.css       # Styling
│   └── js/
│       └── app.js           # Frontend logic
│
├── scripts/
│   ├── init_db.py           # Database initialization
│   └── attack_simulator.py  # Security testing
│
├── tests/
│   └── test_*.py            # Unit tests
│
├── config/
│   └── config.py            # Configuration classes
│
├── requirements.txt         # Python dependencies
├── .env.example             # Environment template
├── run.py                   # Application entry point
└── README.md                # Documentation
```

---

## 🔒 Security Considerations

- All passwords are hashed using bcrypt
- JWT tokens with configurable expiration
- CORS protection enabled
- SQL injection prevention via ORM
- Rate limiting on authentication endpoints
- Secure session management

---

## 📈 Roadmap

- [ ] Redis integration for session storage
- [ ] Multi-factor authentication
- [ ] Advanced ML models (Random Forest, Neural Networks)
- [ ] Real-time WebSocket notifications
- [ ] Mobile application
- [ ] API rate limiting
- [ ] IP geolocation integration
- [ ] Export functionality for reports

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

---

## 📄 License

This project is licensed under the MIT License - see LICENSE file for details.

---

## 👥 Authors

**Your Name** - Initial Development

---

## 🙏 Acknowledgments

- Scikit-learn team for excellent ML library
- Flask community for robust web framework
- Security researchers for threat intelligence

---

**Built with 🛡️ by security professionals, for security professionals**