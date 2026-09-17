"""Ties capture, windowing, detection and mitigation together."""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, Optional

import yaml

from .detector import AnomalyDetector, DetectorConfig
from .mitigator import Mitigator
from .models import PacketEvent
from .stats import BaselineTracker, TrafficWindow

logger = logging.getLogger("ddos_detector.engine")


class DetectionEngine:
    """Consumes a stream of :class:`PacketEvent`, buckets them into
    fixed-size :class:`TrafficWindow` slices, evaluates each closed window
    with the :class:`AnomalyDetector`, and forwards any alerts to the
    :class:`Mitigator`.
    """

    def __init__(
        self,
        detector: AnomalyDetector,
        mitigator: Mitigator,
        window_duration: float = 1.0,
        baseline_history: int = 60,
    ):
        self.detector = detector
        self.mitigator = mitigator
        self.window_duration = window_duration
        self.baseline = BaselineTracker(history_size=baseline_history)
        self._current_window: Optional[TrafficWindow] = None
        self._lock = threading.Lock()
        self.alerts_raised = 0

    def on_event(self, event: PacketEvent) -> None:
        """Feed a single packet event into the engine."""
        with self._lock:
            if self._current_window is None:
                self._current_window = TrafficWindow(
                    start_time=event.timestamp, duration=self.window_duration
                )
            elif not self._current_window.contains(event.timestamp):
                self._flush_window(next_start=event.timestamp)
            self._current_window.add(event)

    def _flush_window(self, next_start: float) -> None:
        window = self._current_window
        if window is not None and window.total_packets > 0:
            alerts = self.detector.evaluate(window, self.baseline)
            for alert in alerts:
                self.alerts_raised += 1
                logger.warning(
                    "ALERT[%s/%s] %s", alert.alert_type.value, alert.severity.value, alert.message
                )
                self.mitigator.handle_alert(alert)
            self.baseline.update(window.pps)
            self.mitigator.unblock_expired()
        self._current_window = TrafficWindow(start_time=next_start, duration=self.window_duration)

    def force_flush(self) -> None:
        """Flush and evaluate whatever window is currently open.

        Should be called when capture stops (e.g. Ctrl+C, or end of pcap
        replay) so the last partial window is not silently dropped.
        """
        with self._lock:
            if self._current_window is not None:
                self._flush_window(next_start=self._current_window.start_time + self.window_duration)


def load_config(path: str) -> Dict[str, Any]:
    """Load a YAML config file into a plain dict."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def build_engine_from_config(config: Dict[str, Any]) -> DetectionEngine:
    """Construct a fully-wired :class:`DetectionEngine` from a config dict
    (as produced by :func:`load_config`).
    """
    detector_cfg = DetectorConfig.from_dict(config.get("detector", {}))
    mitigator_cfg = config.get("mitigator", {}) or {}
    mitigator = Mitigator(
        dry_run=mitigator_cfg.get("dry_run", True),
        block_duration=mitigator_cfg.get("block_duration_seconds", 300.0),
    )
    detector = AnomalyDetector(detector_cfg)
    engine_cfg = config.get("engine", {}) or {}
    return DetectionEngine(
        detector=detector,
        mitigator=mitigator,
        window_duration=engine_cfg.get("window_duration_seconds", 1.0),
        baseline_history=engine_cfg.get("baseline_history", 60),
    )
