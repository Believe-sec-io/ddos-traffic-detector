"""Tests for the anomaly detector: one test per detection rule."""

from __future__ import annotations

from src.detector import AnomalyDetector, DetectorConfig
from src.models import AlertType
from src.stats import BaselineTracker, TrafficWindow
from tests.conftest import make_event


def _window(events, duration=1.0) -> TrafficWindow:
    window = TrafficWindow(start_time=events[0].timestamp, duration=duration)
    for event in events:
        window.add(event)
    return window


def _types(alerts):
    return {alert.alert_type for alert in alerts}


def test_no_alerts_for_normal_traffic(default_config, normal_packets):
    detector = AnomalyDetector(default_config)
    alerts = detector.evaluate(_window(normal_packets), BaselineTracker())
    assert alerts == []


def test_empty_window_produces_no_alerts(default_config):
    detector = AnomalyDetector(default_config)
    assert detector.evaluate(TrafficWindow(start_time=0.0), BaselineTracker()) == []


def test_detects_syn_flood(default_config, syn_flood_packets):
    detector = AnomalyDetector(default_config)
    alerts = detector.evaluate(_window(syn_flood_packets), BaselineTracker())
    assert AlertType.SYN_FLOOD in _types(alerts)


def test_syn_flood_from_single_dominant_source_carries_src_ip(default_config):
    # 100% of the window comes from one IP -> that IP is attached to the alert.
    packets = [make_event(1000.0 + i * 0.001, "203.0.113.5", syn=True) for i in range(100)]
    detector = AnomalyDetector(default_config)
    alerts = detector.evaluate(_window(packets), BaselineTracker())
    syn_flood = next(a for a in alerts if a.alert_type is AlertType.SYN_FLOOD)
    assert syn_flood.src_ip == "203.0.113.5"


def test_syn_flood_from_many_sources_has_no_src_ip(default_config):
    # 100 SYNs spread evenly across 10 sources -> no single IP to blame.
    packets = [
        make_event(1000.0 + i * 0.001, f"203.0.113.{i % 10}", syn=True)
        for i in range(100)
    ]
    detector = AnomalyDetector(default_config)
    alerts = detector.evaluate(_window(packets), BaselineTracker())
    syn_flood = next(a for a in alerts if a.alert_type is AlertType.SYN_FLOOD)
    assert syn_flood.src_ip is None


def test_syn_ratio_below_threshold_is_ignored(default_config):
    # 200 packets but only 20 SYNs (10% ratio, below the 60% threshold).
    packets = [make_event(1000.0 + i * 0.001, "203.0.113.5", syn=i < 20) for i in range(200)]
    detector = AnomalyDetector(default_config)
    alerts = detector.evaluate(_window(packets), BaselineTracker())
    assert AlertType.SYN_FLOOD not in _types(alerts)


def test_detects_udp_flood(default_config, udp_flood_packets):
    detector = AnomalyDetector(default_config)
    alerts = detector.evaluate(_window(udp_flood_packets), BaselineTracker())
    assert AlertType.UDP_FLOOD in _types(alerts)


def test_detects_icmp_flood(default_config, icmp_flood_packets):
    detector = AnomalyDetector(default_config)
    alerts = detector.evaluate(_window(icmp_flood_packets), BaselineTracker())
    assert AlertType.ICMP_FLOOD in _types(alerts)


def test_detects_volumetric_flood(default_config):
    packets = [
        make_event(1000.0 + i * 0.0005, f"10.1.{i // 250}.{i % 250 % 250}", ack=True)
        for i in range(2000)
    ]
    detector = AnomalyDetector(default_config)
    window = _window(packets)
    alerts = detector.evaluate(window, BaselineTracker())
    assert AlertType.VOLUMETRIC_FLOOD in _types(alerts)
    # The alert carries the observed rate and the configured threshold.
    flood = next(a for a in alerts if a.alert_type is AlertType.VOLUMETRIC_FLOOD)
    assert flood.metric_value == window.pps
    assert flood.threshold == default_config.max_total_pps


def test_detects_source_flood_and_exposes_src_ip(default_config, syn_flood_packets):
    # 100 packets/s from one IP > max_per_src_pps (200) is false here, so use a
    # per-source threshold that triggers on this fixture's rate.
    config = DetectorConfig(max_per_src_pps=50.0)
    detector = AnomalyDetector(config)
    alerts = detector.evaluate(_window(syn_flood_packets), BaselineTracker())
    source_floods = [a for a in alerts if a.alert_type is AlertType.SOURCE_FLOOD]
    assert source_floods
    assert source_floods[0].src_ip == "203.0.113.5"


def test_detects_distributed_flood(default_config, distributed_flood_packets):
    detector = AnomalyDetector(default_config)
    alerts = detector.evaluate(_window(distributed_flood_packets), BaselineTracker())
    assert AlertType.DISTRIBUTED_FLOOD in _types(alerts)
    distributed = next(a for a in alerts if a.alert_type is AlertType.DISTRIBUTED_FLOOD)
    # No single culprit IP for a distributed attack.
    assert distributed.src_ip is None


def test_detects_adaptive_anomaly_spike(default_config):
    baseline = BaselineTracker(history_size=5)
    for _ in range(5):
        baseline.update(100.0)

    # 400 pps: below static thresholds but far above the 100 pps baseline.
    packets = [
        make_event(1000.0 + i * 0.001, f"192.168.1.{10 + (i % 50)}", ack=True)
        for i in range(400)
    ]
    detector = AnomalyDetector(default_config)
    alerts = detector.evaluate(_window(packets), baseline)
    assert AlertType.ANOMALY_SPIKE in _types(alerts)
    assert AlertType.VOLUMETRIC_FLOOD not in _types(alerts)


def test_adaptive_check_skipped_when_baseline_not_ready(default_config):
    packets = [
        make_event(1000.0 + i * 0.001, f"192.168.1.{10 + (i % 50)}", ack=True)
        for i in range(400)
    ]
    detector = AnomalyDetector(default_config)
    alerts = detector.evaluate(_window(packets), BaselineTracker(history_size=60))
    assert AlertType.ANOMALY_SPIKE not in _types(alerts)


def test_dominant_source_ratio_configurable():
    # With a permissive ratio, even a 20% dominant source is attached.
    config = DetectorConfig(dominant_source_ratio=0.2, min_syn_count=10, syn_ratio_threshold=0.5)
    packets = [
        make_event(1000.0 + i * 0.001, "203.0.113.5" if i < 20 else f"198.51.100.{i % 8}", syn=True)
        for i in range(100)
    ]
    detector = AnomalyDetector(config)
    alerts = detector.evaluate(_window(packets), BaselineTracker())
    syn_flood = next(a for a in alerts if a.alert_type is AlertType.SYN_FLOOD)
    assert syn_flood.src_ip == "203.0.113.5"


def test_config_from_dict_ignores_unknown_keys():
    config = DetectorConfig.from_dict({
        "max_total_pps": 500,
        "unknown_setting": "ignored",
        "engine": {"window_duration_seconds": 2},
    })
    assert config.max_total_pps == 500
    assert config.max_per_src_pps == DetectorConfig().max_per_src_pps
