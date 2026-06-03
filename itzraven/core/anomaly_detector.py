"""
ML-based Anomaly Detector — identifies unusual patterns in scan data, HTTP responses,
and agent behavior to flag potential false positives or novel vulnerabilities.

Uses scikit-learn for clustering and outlier detection.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from collections import defaultdict

from itzraven.core.logger import get_logger

logger = get_logger()

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    np = None


@dataclass
class AnomalyScore:
    feature: str
    value: float
    z_score: float
    is_anomaly: bool
    threshold: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "feature": self.feature,
            "value": round(self.value, 4),
            "z_score": round(self.z_score, 4),
            "is_anomaly": self.is_anomaly,
            "threshold": self.threshold,
        }


class AnomalyDetector:
    """Detects anomalies in scan metrics and response patterns."""

    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self._response_times: Dict[str, List[float]] = defaultdict(list)
        self._status_codes: Dict[str, List[int]] = defaultdict(list)
        self._response_sizes: Dict[str, List[int]] = defaultdict(list)
        self._isolation_forest: Optional[Any] = None
        self._scaler: Optional[Any] = None
        self._trained = False
        self._z_threshold = 2.5

    def record_response(self, target: str, status_code: int, response_time: float, response_size: int):
        self._response_times[target].append(response_time)
        self._status_codes[target].append(status_code)
        self._response_sizes[target].append(response_size)
        # Keep only last 1000 per target
        if len(self._response_times[target]) > 1000:
            self._response_times[target] = self._response_times[target][-1000:]
            self._status_codes[target] = self._status_codes[target][-1000:]
            self._response_sizes[target] = self._response_sizes[target][-1000:]

    def check_anomaly(self, target: str, status_code: int,
                      response_time: float, response_size: int) -> List[AnomalyScore]:
        scores = []

        times = self._response_times.get(target, [])
        if len(times) > 5:
            mean_t = float(np.mean(times)) if np else 0
            std_t = float(np.std(times)) if np else 0
            if std_t > 0:
                z = (response_time - mean_t) / std_t
                scores.append(AnomalyScore(
                    feature="response_time", value=response_time,
                    z_score=z, is_anomaly=abs(z) > self._z_threshold,
                    threshold=self._z_threshold,
                ))

        sizes = self._response_sizes.get(target, [])
        if len(sizes) > 5:
            mean_s = float(np.mean(sizes)) if np else 0
            std_s = float(np.std(sizes)) if np else 0
            if std_s > 0:
                z = (response_size - mean_s) / std_s
                scores.append(AnomalyScore(
                    feature="response_size", value=response_size,
                    z_score=z, is_anomaly=abs(z) > self._z_threshold,
                    threshold=self._z_threshold,
                ))

        # Check for rare status codes
        codes = self._status_codes.get(target, [])
        if codes and status_code not in (200, 301, 302, 404):
            freq = codes.count(status_code) / len(codes)
            if freq < 0.05:
                scores.append(AnomalyScore(
                    feature="status_code", value=status_code,
                    z_score=freq, is_anomaly=True,
                    threshold=0.05,
                ))

        return scores

    def train_isolation_forest(self, target: str) -> bool:
        if not SKLEARN_AVAILABLE:
            return False
        times = self._response_times.get(target, [])
        sizes = self._response_sizes.get(target, [])
        if len(times) < 10 or len(sizes) < 10:
            return False

        X = np.column_stack([
            np.array(times[-100:]).reshape(-1, 1),
            np.array(sizes[-100:]).reshape(-1, 1),
        ])
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)
        self._isolation_forest = IsolationForest(
            contamination=self.contamination, random_state=42,
        )
        self._isolation_forest.fit(X_scaled)
        self._trained = True
        return True

    def predict_outliers(self, target: str) -> List[int]:
        if not self._trained or not SKLEARN_AVAILABLE:
            return []
        times = self._response_times.get(target, [])
        sizes = self._response_sizes.get(target, [])
        if len(times) < 5 or len(sizes) < 5:
            return []
        X = np.column_stack([
            np.array(times[-50:]).reshape(-1, 1),
            np.array(sizes[-50:]).reshape(-1, 1),
        ])
        X_scaled = self._scaler.transform(X)
        preds = self._isolation_forest.predict(X_scaled)
        return [int(p) for p in preds]

    def get_stats(self, target: str) -> dict:
        times = self._response_times.get(target, [])
        sizes = self._response_sizes.get(target, [])
        return {
            "response_count": len(times),
            "avg_response_time": round(float(np.mean(times)), 3) if np and times else 0,
            "avg_response_size": round(float(np.mean(sizes)), 1) if np and sizes else 0,
            "trained": self._trained,
            "sklearn_available": SKLEARN_AVAILABLE,
        }


_anomaly_detector: Optional[AnomalyDetector] = None


def get_anomaly_detector() -> AnomalyDetector:
    global _anomaly_detector
    if _anomaly_detector is None:
        _anomaly_detector = AnomalyDetector()
    return _anomaly_detector
