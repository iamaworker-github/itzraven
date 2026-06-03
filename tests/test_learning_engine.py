"""Tests for Cross-Session Learning Engine."""

from itzraven.core.learning_engine import LearningEngine, TechniqueRecord, ToolRecord


def test_technique_record():
    rec = TechniqueRecord(technique="sqli", target_tech="mysql")
    assert rec.success_rate == 0.0
    assert rec.reliability == 0.0


def test_technique_success_rate():
    rec = TechniqueRecord(technique="xss", target_tech="generic", attempts=10, successes=7)
    assert rec.success_rate == 0.7
    assert rec.reliability == 0.7


def test_technique_with_false_positives():
    rec = TechniqueRecord(technique="nuclei", target_tech="nginx", attempts=5,
                          successes=4, false_positives=2)
    assert rec.success_rate == 0.8
    assert rec.reliability == 0.4


def test_tool_record():
    rec = ToolRecord(tool_name="nuclei", runs=10, findings_found=8, false_positives=3)
    assert rec.tp_rate == 0.5
    d = rec.to_dict()
    assert d["tool_name"] == "nuclei"


def test_learning_engine_record():
    engine = LearningEngine()
    engine.record_technique("sqli", "mysql", success=True, execution_time=30.0)
    engine.record_technique("sqli", "mysql", success=False, execution_time=45.0)
    assert engine.get_technique_reliability("sqli", "mysql") == 0.5


def test_should_skip():
    engine = LearningEngine()
    for _ in range(4):
        engine.record_technique("nuclei-slow", "apache", success=False)
    assert engine.should_skip("nuclei-slow", "apache", min_reliability=0.2)


def test_should_not_skip():
    engine = LearningEngine()
    engine.record_technique("good-tech", "nginx", success=True)
    assert not engine.should_skip("good-tech", "nginx")


def test_best_technique():
    engine = LearningEngine()
    engine.record_technique("t1", "generic", success=True)
    engine.record_technique("t2", "generic", success=False)
    best = engine.get_best_technique("generic")
    assert best is not None
    assert best["technique"] == "t1"


def test_tool_stats():
    engine = LearningEngine()
    engine.record_tool_run("nuclei", findings_count=5, false_positives=1, run_time=120)
    engine.record_tool_run("nuclei", findings_count=3, run_time=90)
    assert engine.get_tool_reliability("nuclei") > 0


def test_persist_and_load(tmp_path):
    import tempfile
    from pathlib import Path
    from itzraven.core.learning_engine import LEARNED_PATTERNS_PATH

    original_path = LEARNED_PATTERNS_PATH
    try:
        import itzraven.core.learning_engine as le
        le.LEARNED_PATTERNS_PATH = tmp_path / "test_patterns.jsonl"

        engine = LearningEngine()
        engine.record_technique("test-tech", "test-target", success=True)
        engine.record_technique("test-tech", "test-target", success=False)
        engine.record_tool_run("test-tool", 5, 1, 30)
        engine.persist()

        engine2 = LearningEngine()
        assert engine2.get_technique_reliability("test-tech", "test-target") == 0.5
    finally:
        le.LEARNED_PATTERNS_PATH = original_path


def test_get_stats():
    engine = LearningEngine()
    engine.record_technique("a", "x", True)
    stats = engine.get_stats()
    assert "techniques_tracked" in stats
    assert "tools_tracked" in stats
