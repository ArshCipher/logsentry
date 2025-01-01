 
from sklearn.ensemble import IsolationForest
import numpy as np
import logging

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """Machine learning-based anomaly detection."""
    def __init__(self):
        self.model = IsolationForest(contamination=0.05, random_state=42)

    def extract_features(self, attempts: dict) -> list:
        """Extract features for ML model."""
        data = []
        for user, ip_data in attempts.items():
            for ip, timestamps in ip_data.items():
                for ts in timestamps:
                    features = [ts.hour, ts.weekday(), len(timestamps)]
                    data.append(features)
        return data

    def train(self, attempts: dict):
        """Train anomaly detection model."""
        data = self.extract_features(attempts)
        if not data:
            logger.warning("No data to train model.")
            return
        try:
            self.model.fit(np.array(data))
        except ValueError as e:
            logger.error(f"Model training failed: {e}")

    def detect(self, attempts: dict) -> list:
        """Detect anomalies in login attempts."""
        anomalies = []
        data = self.extract_features(attempts)
        if not data:
            return anomalies
        try:
            predictions = self.model.predict(np.array(data))
            idx = 0
            for user, ip_data in attempts.items():
                for ip, timestamps in ip_data.items():
                    for ts in timestamps:
                        if predictions[idx] == -1:
                            anomalies.append({
                                "user": user,
                                "ip": ip,
                                "type": "anomaly",
                                "attempts": 1,
                                "time_range": f"{ts}"
                            })
                        idx += 1
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
        return anomalies