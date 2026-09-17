"""Tests for the traffic aggregation primitives (TrafficWindow, BaselineTracker)."""

from __future__ import annotations

import pytest

from src.models import Protocol
from src.stats import BaselineTracker, TrafficWindow
from tests.conftest import make_event


def _window_from(events, duration=1.0):
    window = TrafficWindow(start_time=events[0].timestamp, duration=duration)
    for event in events:
        window.add(event)
    return window


class TestTrafficWindow:
    def test_counts_and_rates(self, syn_flood_packets):
        window = _window_from(syn_flood_packets)
        assert window.total_packets == 100
        assert window.pps == pytest.approx(100.0)
        assert window.total_bytes == 100 * 60
        assert window.bps == pytest.approx(100 * 60 * 8)

    def test_syn_ratio_only_counts_bare_syn(self, syn_flood_packets):
        window = _window_from(syn_flood_packets)
        assert window.syn_count == 100
        assert window.syn_ratio == pytest.approx(1.0)

        mixed = _window_from([
            make_event(1000.0, "203.0.113.5", syn=True, ack=False),
            make_event(1000.1, "203.0.113.5", syn=True, ack=True),  # SYN-ACK, not counted
            make_event(1000.2, "203.0.113.5", syn=False, ack=True),
            make_event(1000.3, "203.0.113.5", syn=False, ack=True),
        ])
        assert mixed.syn_count == 1
        assert mixed.syn_ratio == pytest.approx(0.25)

    def test_top_talkers_and_max_source_pps(self, distributed_flood_packets):
        window = _window_from(distributed_flood_packets)
        assert len(window.unique_src_ips) == 50
        top = window.top_talkers(3)
        assert len(top) == 3
        assert all(count == 20 for _, count in top)

        src_ip, src_pps = window.max_source_pps()
        assert src_ip is not None
        assert src_pps == pytest.approx(20.0)

    def test_max_source_pps_empty_window(self):
        window = TrafficWindow(start_time=0.0, duration=1.0)
        assert window.max_source_pps() == (None, 0.0)
        assert window.syn_ratio == 0.0
        assert window.pps == 0.0

    def test_proto_pps(self, udp_flood_packets):
        window = _window_from(udp_flood_packets)
        assert window.proto_pps(Protocol.UDP) == pytest.approx(600.0)
        assert window.proto_pps(Protocol.TCP) == 0.0

    def test_contains_respects_half_open_interval(self):
        window = TrafficWindow(start_time=1000.0, duration=1.0)
        assert window.contains(1000.0)
        assert window.contains(1000.999)
        assert not window.contains(1001.0)


class TestBaselineTracker:
    def test_rejects_invalid_history_size(self):
        with pytest.raises(ValueError):
            BaselineTracker(history_size=0)

    def test_not_ready_until_enough_samples(self):
        tracker = BaselineTracker(history_size=20)
        tracker.update(100.0)
        assert not tracker.is_ready
        for _ in range(4):
            tracker.update(100.0)
        assert tracker.is_ready

    def test_mean_and_stdev(self):
        tracker = BaselineTracker(history_size=5)
        for _ in range(5):
            tracker.update(100.0)
        assert tracker.mean == pytest.approx(100.0)
        assert tracker.stdev == pytest.approx(0.0)
        assert tracker.upper_bound(k=3.0) == pytest.approx(100.0)

        tracker.update(200.0)  # rolling window drops the oldest 100.0
        assert tracker.mean == pytest.approx(120.0)
        assert tracker.stdev == pytest.approx(40.0)
        assert tracker.upper_bound(k=3.0) == pytest.approx(240.0)

    def test_history_is_bounded(self):
        tracker = BaselineTracker(history_size=10)
        for i in range(100):
            tracker.update(float(i))
        assert tracker.sample_count == 10
