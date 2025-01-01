 
import pytest
from logsentry.ml import AnomalyDetector
from datetime import datetime

def test_anomaly_detector():
    detector = AnomalyDetector()
    attempts = {
        "root": {
            "192.168.1.1": [datetime.now(), datetime.now()]
        }
    }
    detector.train(attempts)
    anomalies = detector.detect(attempts)
    assert isinstance(anomalies, list)