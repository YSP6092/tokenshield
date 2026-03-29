"""
TokenShield ML Model Training Script
=====================================
Trains an Isolation Forest anomaly detection model on behavioral data.
Generates synthetic training data if no real data exists yet.

Usage:
    python scripts/train_ml_model.py                   # Train on real DB data
    python scripts/train_ml_model.py --synthetic        # Generate + train on synthetic data
    python scripts/train_ml_model.py --synthetic --save # Save model to ml/model.pkl
"""

import argparse
import os
import sys
import json
import numpy as np
import pandas as pd
import joblib
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report

# Add parent dir to path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

def extract_features(behavior_logs: list[dict]) -> pd.DataFrame:
    """
    Extract ML features from raw behavior log records.
    Each row = one session's behavioral fingerprint.
    """
    features = []
    for log in behavior_logs:
        feature_row = {
            # Timing features
            'time_gap_mean': log.get('time_gap_mean', 0.0),
            'time_gap_std': log.get('time_gap_std', 0.0),
            'time_gap_min': log.get('time_gap_min', 0.0),
            'time_gap_max': log.get('time_gap_max', 0.0),
            # Request patterns
            'requests_per_minute': log.get('requests_per_minute', 0.0),
            'unique_endpoints': log.get('unique_endpoints', 0),
            'post_ratio': log.get('post_ratio', 0.0),
            'get_ratio': log.get('get_ratio', 0.0),
            # Behavioral patterns
            'transaction_count': log.get('transaction_count', 0),
            'avg_transaction_amount': log.get('avg_transaction_amount', 0.0),
            'max_transaction_amount': log.get('max_transaction_amount', 0.0),
            # Session metadata
            'session_age_minutes': log.get('session_age_minutes', 0.0),
            'ip_change': int(log.get('ip_change', False)),
            'user_agent_change': int(log.get('user_agent_change', False)),
        }
        features.append(feature_row)

    return pd.DataFrame(features)


# ============================================================================
# SYNTHETIC DATA GENERATION
# ============================================================================

def generate_synthetic_data(n_normal=2000, n_anomalous=200, seed=42) -> tuple:
    """
    Generate realistic synthetic behavioral data for training.
    Returns (features_df, labels) where labels: 1=normal, -1=anomaly
    """
    rng = np.random.default_rng(seed)

    # === Normal user behavior ===
    normal = []
    for _ in range(n_normal):
        normal.append({
            'time_gap_mean': rng.normal(3.5, 1.2),         # ~3.5s between actions
            'time_gap_std': rng.uniform(0.5, 2.0),
            'time_gap_min': rng.uniform(0.5, 2.0),
            'time_gap_max': rng.uniform(5.0, 15.0),
            'requests_per_minute': rng.normal(8, 3),        # ~8 req/min
            'unique_endpoints': int(rng.integers(3, 12)),
            'post_ratio': rng.uniform(0.1, 0.4),
            'get_ratio': rng.uniform(0.6, 0.9),
            'transaction_count': int(rng.integers(0, 5)),
            'avg_transaction_amount': rng.uniform(50, 500),
            'max_transaction_amount': rng.uniform(100, 1000),
            'session_age_minutes': rng.uniform(5, 60),
            'ip_change': int(rng.random() < 0.02),          # 2% IP change chance
            'user_agent_change': int(rng.random() < 0.01),
        })

    # === Anomalous / attacker behavior ===
    anomalous = []
    for _ in range(n_anomalous):
        attack_type = rng.choice(['rapid_fire', 'session_hijack', 'bulk_transfer'])

        if attack_type == 'rapid_fire':
            anomalous.append({
                'time_gap_mean': rng.uniform(0.05, 0.3),   # Very fast requests
                'time_gap_std': rng.uniform(0.01, 0.05),
                'time_gap_min': rng.uniform(0.01, 0.1),
                'time_gap_max': rng.uniform(0.5, 1.5),
                'requests_per_minute': rng.uniform(60, 300), # Bot-like
                'unique_endpoints': int(rng.integers(1, 3)),
                'post_ratio': rng.uniform(0.8, 1.0),
                'get_ratio': rng.uniform(0.0, 0.2),
                'transaction_count': int(rng.integers(10, 50)),
                'avg_transaction_amount': rng.uniform(1000, 5000),
                'max_transaction_amount': rng.uniform(5000, 20000),
                'session_age_minutes': rng.uniform(0.5, 5),
                'ip_change': int(rng.random() < 0.5),
                'user_agent_change': int(rng.random() < 0.3),
            })
        elif attack_type == 'session_hijack':
            anomalous.append({
                'time_gap_mean': rng.normal(4.0, 0.5),    # Mimics normal timing
                'time_gap_std': rng.uniform(0.1, 0.3),    # But very consistent
                'time_gap_min': rng.uniform(3.0, 4.0),
                'time_gap_max': rng.uniform(4.5, 6.0),
                'requests_per_minute': rng.normal(10, 1),
                'unique_endpoints': int(rng.integers(2, 5)),
                'post_ratio': rng.uniform(0.6, 0.9),
                'get_ratio': rng.uniform(0.1, 0.4),
                'transaction_count': int(rng.integers(3, 10)),
                'avg_transaction_amount': rng.uniform(2000, 9000),
                'max_transaction_amount': rng.uniform(8000, 25000),
                'session_age_minutes': rng.uniform(0.1, 2.0),
                'ip_change': 1,                            # Always changes IP
                'user_agent_change': int(rng.random() < 0.7),
            })
        else:  # bulk_transfer
            anomalous.append({
                'time_gap_mean': rng.uniform(0.5, 2.0),
                'time_gap_std': rng.uniform(0.1, 0.5),
                'time_gap_min': rng.uniform(0.2, 0.8),
                'time_gap_max': rng.uniform(3.0, 8.0),
                'requests_per_minute': rng.uniform(20, 60),
                'unique_endpoints': int(rng.integers(2, 4)),
                'post_ratio': rng.uniform(0.7, 1.0),
                'get_ratio': rng.uniform(0.0, 0.3),
                'transaction_count': int(rng.integers(20, 100)),
                'avg_transaction_amount': rng.uniform(500, 3000),
                'max_transaction_amount': rng.uniform(5000, 50000),
                'session_age_minutes': rng.uniform(1, 10),
                'ip_change': int(rng.random() < 0.2),
                'user_agent_change': int(rng.random() < 0.1),
            })

    all_records = normal + anomalous
    labels = [1] * n_normal + [-1] * n_anomalous

    df = pd.DataFrame(all_records)
    return df, np.array(labels)


# ============================================================================
# LOAD REAL DATA FROM DATABASE
# ============================================================================

def load_real_data_from_db() -> pd.DataFrame:
    """Load and aggregate behavior logs from the real TokenShield database."""
    try:
        from app import create_app, db
        from app.models import BehaviorLog, Session

        app = create_app()
        with app.app_context():
            sessions = Session.query.all()
            records = []

            for session in sessions:
                logs = list(session.behavior_logs.all())
                if not logs:
                    continue

                time_gaps = [l.time_gap for l in logs if l.time_gap is not None]
                methods = [l.request_method for l in logs if l.request_method]
                endpoints = list(set(l.endpoint for l in logs if l.endpoint))

                session_age = (datetime.utcnow() - session.created_at).total_seconds() / 60

                post_count = sum(1 for m in methods if m == 'POST')
                get_count = sum(1 for m in methods if m == 'GET')
                total = len(methods) or 1

                records.append({
                    'session_id': session.id,
                    'time_gap_mean': np.mean(time_gaps) if time_gaps else 0.0,
                    'time_gap_std': np.std(time_gaps) if time_gaps else 0.0,
                    'time_gap_min': min(time_gaps) if time_gaps else 0.0,
                    'time_gap_max': max(time_gaps) if time_gaps else 0.0,
                    'requests_per_minute': (len(logs) / session_age) if session_age > 0 else 0,
                    'unique_endpoints': len(endpoints),
                    'post_ratio': post_count / total,
                    'get_ratio': get_count / total,
                    'transaction_count': session.transactions.count(),
                    'avg_transaction_amount': 0.0,  # extend if needed
                    'max_transaction_amount': 0.0,
                    'session_age_minutes': session_age,
                    'ip_change': 0,
                    'user_agent_change': 0,
                    'is_suspicious': int(session.is_suspicious),
                })

            return pd.DataFrame(records)

    except Exception as e:
        print(f"⚠️  Could not load from DB: {e}")
        return pd.DataFrame()


# ============================================================================
# MODEL TRAINING
# ============================================================================

def train_model(X: pd.DataFrame, contamination: float = 0.05) -> Pipeline:
    """Train Isolation Forest pipeline with StandardScaler."""
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('model', IsolationForest(
            n_estimators=200,
            contamination=contamination,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        ))
    ])
    pipeline.fit(X)
    return pipeline


def evaluate_model(pipeline: Pipeline, X: pd.DataFrame, y: np.ndarray):
    """Print evaluation metrics on labeled synthetic data."""
    preds = pipeline.predict(X)
    print("\n📊 Model Evaluation Report:")
    print(classification_report(y, preds, target_names=['Anomaly (-1)', 'Normal (1)']))

    scores = pipeline.decision_function(X)
    normal_scores = scores[y == 1]
    anomaly_scores = scores[y == -1]

    print(f"   Normal sessions   — avg score: {normal_scores.mean():.4f}")
    print(f"   Anomalous sessions — avg score: {anomaly_scores.mean():.4f}")
    print(f"   Score separation:  {normal_scores.mean() - anomaly_scores.mean():.4f}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='TokenShield ML Model Trainer')
    parser.add_argument('--synthetic', action='store_true', help='Use synthetic data')
    parser.add_argument('--save', action='store_true', help='Save trained model')
    parser.add_argument('--output', default='ml/model.pkl', help='Output model path')
    parser.add_argument('--contamination', type=float, default=0.05,
                        help='Expected anomaly fraction (0.01-0.5)')
    args = parser.parse_args()

    print("🛡️  TokenShield ML Model Training")
    print("=" * 45)

    labels = None

    if args.synthetic:
        print("📦 Generating synthetic behavioral data...")
        X, labels = generate_synthetic_data(n_normal=2000, n_anomalous=200)
        print(f"   ✅ {len(X)} samples generated ({sum(labels==1)} normal, {sum(labels==-1)} anomalous)")
    else:
        print("🗄️  Loading behavioral data from database...")
        df = load_real_data_from_db()

        if df.empty:
            print("   ⚠️  No DB data found. Falling back to synthetic data.")
            X, labels = generate_synthetic_data()
        else:
            feature_cols = [c for c in df.columns if c not in ('session_id', 'is_suspicious')]
            X = df[feature_cols]
            if 'is_suspicious' in df.columns:
                labels = np.where(df['is_suspicious'] == 1, -1, 1)
            print(f"   ✅ Loaded {len(X)} sessions from database")

    print(f"\n🤖 Training Isolation Forest (contamination={args.contamination})...")
    pipeline = train_model(X, contamination=args.contamination)
    print("   ✅ Training complete!")

    if labels is not None:
        evaluate_model(pipeline, X, labels)

    if args.save:
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        metadata = {
            'trained_at': datetime.utcnow().isoformat(),
            'n_samples': len(X),
            'contamination': args.contamination,
            'features': list(X.columns),
        }
        joblib.dump({'pipeline': pipeline, 'metadata': metadata}, args.output)
        print(f"\n💾 Model saved to: {args.output}")

        meta_path = args.output.replace('.pkl', '_metadata.json')
        with open(meta_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"📋 Metadata saved to: {meta_path}")
    else:
        print("\n💡 Use --save to persist the model to disk")

    print("\n✅ Done!")


if __name__ == '__main__':
    main()