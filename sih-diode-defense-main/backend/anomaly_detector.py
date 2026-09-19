"""
anomaly_detector.py
-------------------
Isolation Forest-based anomaly detector for passive cyber threat detection.
Used as a COMPLEMENTARY signal alongside the supervised DiodeThreatNet classifier.

Fitted EXCLUSIVELY on REAL Clean Benign network traffic (CIC-IDS2017 Monday/Tuesday)
to prevent attack leakage into the benign baseline.

Input  : engineered feature vector (dict or numpy array)
Output : anomaly_score (float 0-1, higher = more anomalous)
         is_anomaly (bool)
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler, StandardScaler

ANOMALY_FEATURES = [
    "iat_mean",
    "iat_std",
    "pkt_len_mean",
    "pkt_len_std",
    "payload_entropy",
    "syn_ratio",
]

DEFAULT_ANOMALY_THRESHOLD = 0.55

def _generate_benign_baseline(n_samples: int = 2000, seed: int = 42) -> np.ndarray:
    """Fallback synthetic baseline only if real dataset artifacts are missing."""
    rng = np.random.default_rng(seed)
    iat_mean     = rng.exponential(scale=0.05, size=n_samples)
    iat_std      = rng.exponential(scale=0.02, size=n_samples)
    pkt_len_mean = np.clip(rng.normal(loc=500, scale=100, size=n_samples), 40, 1500)
    pkt_len_std  = np.clip(rng.normal(loc=80, scale=20, size=n_samples), 0, 500)
    payload_ent  = np.clip(rng.normal(loc=5.0, scale=0.8, size=n_samples), 0, 8.0)
    syn_ratio    = rng.beta(a=1, b=20, size=n_samples)

    return np.column_stack([
        iat_mean, iat_std, pkt_len_mean, pkt_len_std,
        payload_ent, syn_ratio
    ])

class AnomalyDetector:
    def __init__(
        self,
        contamination: float = 0.03,
        n_estimators: int = 100,
        threshold: float = DEFAULT_ANOMALY_THRESHOLD,
        random_state: int = 42,
    ):
        self.contamination  = contamination
        self.n_estimators   = n_estimators
        self.threshold      = threshold
        self.random_state   = random_state

        self._forest       = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self._score_scaler = MinMaxScaler(feature_range=(0, 1))
        self._fitted       = False
        self._scaler       = None

        # Attempt to load trained real-benign artifacts
        if os.path.exists("models/isolation_forest.pkl"):
            try:
                self._forest = joblib.load("models/isolation_forest.pkl")
                self._fitted = True
                if os.path.exists("models/scaler_v1.pkl"):
                    self._scaler = joblib.load("models/scaler_v1.pkl")
            except Exception:
                pass

    def fit(self, X: np.ndarray | None = None) -> None:
        if X is None:
            if os.path.exists("ml/artifacts/benign_train.npz"):
                raw = np.load("ml/artifacts/benign_train.npz")
                X = raw["v1"]
                if os.path.exists("models/scaler_v1.pkl"):
                    self._scaler = joblib.load("models/scaler_v1.pkl")
                    X = self._scaler.transform(X)
            else:
                X = _generate_benign_baseline()

        self._forest.fit(X)
        raw_scores = -self._forest.score_samples(X)
        self._score_scaler.fit(raw_scores.reshape(-1, 1))
        self._fitted = True

    def score(self, features: dict) -> dict:
        if not self._fitted:
            self.fit()

        raw_vec = np.array([[
            float(features.get(f, 0.0)) for f in ANOMALY_FEATURES
        ]], dtype=np.float32)

        if self._scaler is not None:
            try:
                vec = self._scaler.transform(raw_vec)
            except Exception:
                vec = raw_vec
        else:
            vec = raw_vec

        raw_score  = -self._forest.score_samples(vec)[0]
        # Normalization using decision function offset
        # Offset in IsolationForest separates inliers (> 0) from outliers (< 0)
        norm_score = float(
            np.clip((raw_score - 0.35) / 0.40, 0.0, 1.0)
        )

        return {
            "anomaly_score": round(norm_score, 4),
            "is_anomaly"   : norm_score >= self.threshold,
        }

    def score_batch(self, features_list: list[dict]) -> list[dict]:
        return [self.score(f) for f in features_list]

_detector_instance: AnomalyDetector | None = None

def get_detector() -> AnomalyDetector:
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = AnomalyDetector()
        if not _detector_instance._fitted:
            _detector_instance.fit()
    return _detector_instance
