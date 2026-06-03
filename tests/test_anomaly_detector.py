"""Tests for the ML Anomaly Detector."""

from itzraven.core.anomaly_detector import AnomalyDetector, AnomalyScore


def test_anomaly_score_creation():
    score = AnomalyScore(
        feature="response_time",
        value=5.0,
        z_score=3.5,
        is_anomaly=True,
        threshold=2.5,
    )
    assert score.feature == "response_time"
    assert score.is_anomaly is True
    d = score.to_dict()
    assert d["is_anomaly"] is True


def test_detector_initialization():
    detector = AnomalyDetector(contamination=0.1)
    assert detector.contamination == 0.1
    assert detector._trained is False


def test_record_response():
    detector = AnomalyDetector()
    detector.record_response("https://example.com", 200, 0.5, 1024)
    detector.record_response("https://example.com", 200, 0.6, 2048)
    assert len(detector._response_times["https://example.com"]) == 2


def test_check_anomaly_insufficient_data():
    detector = AnomalyDetector()
    scores = detector.check_anomaly("https://example.com", 200, 0.5, 1024)
    # Not enough data for anomaly detection
    assert len(scores) == 0


def test_check_anomaly_with_data():
    detector = AnomalyDetector()
    target = "https://test.com"
    # Add normal data
    for _ in range(20):
        detector.record_response(target, 200, 0.5, 1024)
    # Check an anomaly
    scores = detector.check_anomaly(target, 500, 10.0, 99999)
    assert len(scores) > 0


def test_detector_stats():
    detector = AnomalyDetector()
    detector.record_response("https://stats.test", 200, 0.3, 512)
    stats = detector.get_stats("https://stats.test")
    assert stats["response_count"] == 1
    assert stats["sklearn_available"] is True or stats["sklearn_available"] is False


def test_anomaly_detector_singleton():
    from itzraven.core.anomaly_detector import get_anomaly_detector
    a1 = get_anomaly_detector()
    a2 = get_anomaly_detector()
    assert a1 is a2
