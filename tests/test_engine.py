"""End-to-end tests of the DetectionEngine wiring (capture -> detect -> mitigate)."""

from __future__ import annotations

import yaml

from src.detector import AnomalyDetector, DetectorConfig
from src.engine import DetectionEngine, build_engine_from_config, load_config
from src.mitigator import Mitigator
from tests.conftest import make_event


def _engine(config: DetectorConfig | None = None) -> DetectionEngine:
    return DetectionEngine(
        detector=AnomalyDetector(config or DetectorConfig()),
        mitigator=Mitigator(dry_run=True, block_duration=300.0),
        window_duration=1.0,
        baseline_history=10,
    )


def test_syn_flood_end_to_end_blocks_source_ip():
    config = DetectorConfig(
        max_per_src_pps=10.0,
        max_total_pps=10_000.0,
        syn_ratio_threshold=0.5,
        min_syn_count=5,
    )
    engine = _engine(config)

    for i in range(40):
        engine.on_event(make_event(1000.0 + i * 0.001, "203.0.113.5", syn=True))
    engine.force_flush()

    assert engine.alerts_raised >= 1
    assert engine.mitigator.is_blocked("203.0.113.5")


def test_engine_rotates_windows_and_uses_baseline():
    engine = _engine(DetectorConfig(max_total_pps=10_000.0))

    # First window: 100 pps of benign traffic -> baseline sample recorded.
    for i in range(100):
        engine.on_event(make_event(1000.0 + i * 0.005, "192.168.1.1", ack=True))
    # Crossing the window boundary flushes the first window.
    engine.on_event(make_event(1001.5, "192.168.1.1", ack=True))

    assert engine.baseline.sample_count == 1
    assert engine.baseline.history_size == 10


def test_force_flush_on_empty_engine_is_safe():
    engine = _engine()
    engine.force_flush()  # must not raise
    assert engine.alerts_raised == 0


def test_engine_replays_synthetic_flood_stream():
    """Simulates a sustained UDP flood across several windows."""
    config = DetectorConfig(max_total_pps=500.0, udp_pps_threshold=200.0)
    engine = _engine(config)

    from src.models import Protocol
    for window_index in range(3):
        base = 1000.0 + window_index
        for i in range(400):
            engine.on_event(
                make_event(base + i * 0.001, f"198.51.100.{i % 10}", protocol=Protocol.UDP)
            )
    engine.force_flush()

    assert engine.alerts_raised > 0


def test_syn_flood_alone_blocks_the_dominant_source_ip():
    """The SYN_FLOOD rule must be actionable on its own: with SOURCE_FLOOD and
    VOLUMETRIC_FLOOD thresholds pushed out of reach, the dominant source
    attached to the SYN_FLOOD alert still gets blocked.
    """
    config = DetectorConfig(
        max_per_src_pps=10_000.0,
        max_total_pps=10_000.0,
        min_syn_count=5,
        syn_ratio_threshold=0.5,
    )
    engine = _engine(config)

    for i in range(40):
        engine.on_event(make_event(1000.0 + i * 0.001, "203.0.113.7", syn=True))
    engine.force_flush()

    assert engine.alerts_raised >= 1
    assert engine.mitigator.is_blocked("203.0.113.7")


def test_load_config_reads_project_config_file(project_root):
    config = load_config(str(project_root / "config.yaml"))
    assert "detector" in config
    assert config["mitigator"]["dry_run"] is True

    engine = build_engine_from_config(config)
    assert engine.window_duration == config["engine"]["window_duration_seconds"]
    assert engine.detector.config.max_total_pps == config["detector"]["max_total_pps"]
    assert engine.mitigator.dry_run is True


def test_build_engine_from_empty_config_uses_defaults():
    engine = build_engine_from_config({})
    assert engine.window_duration == 1.0
    assert engine.mitigator.dry_run is True
    assert engine.detector.config.max_total_pps == DetectorConfig().max_total_pps


def test_config_file_is_valid_yaml(project_root):
    with open(project_root / "config.yaml", "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    assert set(data) >= {"detector", "mitigator", "engine"}
