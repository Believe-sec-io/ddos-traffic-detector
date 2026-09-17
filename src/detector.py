"""Heuristic anomaly detection over aggregated traffic windows."""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, Dict, List, Optional

from .models import Alert, AlertType, Protocol, Severity
from .stats import BaselineTracker, TrafficWindow


@dataclass
class DetectorConfig:
    """Configurable thresholds for the anomaly detector.

    All thresholds have sane defaults for a small/medium server, but should
    be tuned to the baseline traffic of the network being protected.
    """

    max_total_pps: float = 1000.0
    max_per_src_pps: float = 200.0
    syn_ratio_threshold: float = 0.6
    min_syn_count: int = 50
    unique_ip_threshold: int = 30
    udp_pps_threshold: float = 500.0
    icmp_pps_threshold: float = 300.0
    adaptive_k: float = 3.0
    dominant_source_ratio: float = 0.5

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectorConfig":
        """Build a config from a plain dict, ignoring unknown keys (e.g. from
        a YAML file that also carries unrelated sections).
        """
        valid_keys = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in (data or {}).items() if k in valid_keys}
        return cls(**filtered)


class AnomalyDetector:
    """Evaluates a :class:`TrafficWindow` against static thresholds and an
    adaptive baseline, producing zero or more :class:`Alert` objects.
    """

    def __init__(self, config: DetectorConfig):
        self.config = config

    def evaluate(self, window: TrafficWindow, baseline: BaselineTracker) -> List[Alert]:
        alerts: List[Alert] = []
        ts = window.start_time

        if window.total_packets == 0:
            return alerts

        alerts.extend(self._check_volumetric(window, ts))
        alerts.extend(self._check_syn_flood(window, ts))
        alerts.extend(self._check_protocol_floods(window, ts))
        alerts.extend(self._check_source_flood(window, ts))
        alerts.extend(self._check_distributed(window, ts))
        alerts.extend(self._check_adaptive(window, ts, baseline))
        return alerts

    def _check_volumetric(self, window: TrafficWindow, ts: float) -> List[Alert]:
        """Global flood: raw packet rate too high overall."""
        cfg = self.config
        if window.pps <= cfg.max_total_pps:
            return []
        return [Alert(
            timestamp=ts,
            alert_type=AlertType.VOLUMETRIC_FLOOD,
            severity=Severity.CRITICAL,
            message=(
                f"Total traffic {window.pps:.1f} pps exceeds threshold "
                f"{cfg.max_total_pps:.1f} pps"
            ),
            metric_value=window.pps,
            threshold=cfg.max_total_pps,
        )]

    def _check_syn_flood(self, window: TrafficWindow, ts: float) -> List[Alert]:
        """SYN flood: high ratio of bare SYNs (half-open connection abuse).

        When a single source is responsible for the bulk of the traffic
        (>= ``dominant_source_ratio`` of the window), its IP is attached to
        the alert so the mitigator can block it directly.
        """
        cfg = self.config
        if window.syn_count < cfg.min_syn_count or window.syn_ratio <= cfg.syn_ratio_threshold:
            return []
        return [Alert(
            timestamp=ts,
            alert_type=AlertType.SYN_FLOOD,
            severity=Severity.HIGH,
            message=(
                f"SYN ratio {window.syn_ratio:.1%} exceeds threshold "
                f"{cfg.syn_ratio_threshold:.1%} ({window.syn_count} SYNs)"
            ),
            metric_value=window.syn_ratio,
            threshold=cfg.syn_ratio_threshold,
            src_ip=self._dominant_source(window),
        )]

    def _dominant_source(self, window: TrafficWindow) -> Optional[str]:
        """Return the busiest source IP when it accounts for at least
        ``dominant_source_ratio`` of the window's packets, otherwise ``None``
        (i.e. the attack is spread across many sources).
        """
        src_ip, src_pps = window.max_source_pps()
        if src_ip is None or window.pps <= 0:
            return None
        if (src_pps / window.pps) >= self.config.dominant_source_ratio:
            return src_ip
        return None

    def _check_protocol_floods(self, window: TrafficWindow, ts: float) -> List[Alert]:
        """UDP and ICMP floods (including reflection/amplification traffic)."""
        cfg = self.config
        alerts: List[Alert] = []

        udp_pps = window.proto_pps(Protocol.UDP)
        if udp_pps > cfg.udp_pps_threshold:
            alerts.append(Alert(
                timestamp=ts,
                alert_type=AlertType.UDP_FLOOD,
                severity=Severity.HIGH,
                message=(
                    f"UDP traffic {udp_pps:.1f} pps exceeds threshold "
                    f"{cfg.udp_pps_threshold:.1f} pps"
                ),
                metric_value=udp_pps,
                threshold=cfg.udp_pps_threshold,
            ))

        icmp_pps = window.proto_pps(Protocol.ICMP)
        if icmp_pps > cfg.icmp_pps_threshold:
            alerts.append(Alert(
                timestamp=ts,
                alert_type=AlertType.ICMP_FLOOD,
                severity=Severity.MEDIUM,
                message=(
                    f"ICMP traffic {icmp_pps:.1f} pps exceeds threshold "
                    f"{cfg.icmp_pps_threshold:.1f} pps"
                ),
                metric_value=icmp_pps,
                threshold=cfg.icmp_pps_threshold,
            ))

        return alerts

    def _check_source_flood(self, window: TrafficWindow, ts: float) -> List[Alert]:
        """Single-source flood: one IP dominates traffic (easy to block)."""
        cfg = self.config
        src_ip, src_pps = window.max_source_pps()
        if src_ip is None or src_pps <= cfg.max_per_src_pps:
            return []
        return [Alert(
            timestamp=ts,
            alert_type=AlertType.SOURCE_FLOOD,
            severity=Severity.HIGH,
            message=(
                f"Source {src_ip} sending {src_pps:.1f} pps exceeds threshold "
                f"{cfg.max_per_src_pps:.1f} pps"
            ),
            metric_value=src_pps,
            threshold=cfg.max_per_src_pps,
            src_ip=src_ip,
        )]

    def _check_distributed(self, window: TrafficWindow, ts: float) -> List[Alert]:
        """Distributed flood: many unique sources jointly pushing volume up
        (classic DDoS signature, no single IP to block).
        """
        cfg = self.config
        unique_ips = len(window.unique_src_ips)
        if unique_ips <= cfg.unique_ip_threshold or window.pps <= cfg.max_total_pps * 0.5:
            return []
        return [Alert(
            timestamp=ts,
            alert_type=AlertType.DISTRIBUTED_FLOOD,
            severity=Severity.CRITICAL,
            message=(
                f"{unique_ips} unique sources exceed threshold "
                f"{cfg.unique_ip_threshold} with {window.pps:.1f} pps total"
            ),
            metric_value=float(unique_ips),
            threshold=float(cfg.unique_ip_threshold),
        )]

    def _check_adaptive(
        self, window: TrafficWindow, ts: float, baseline: BaselineTracker
    ) -> List[Alert]:
        """Adaptive baseline anomaly: catches attacks that stay below the
        static thresholds but are well above this network's normal behaviour.
        """
        cfg = self.config
        if not baseline.is_ready:
            return []
        upper = baseline.upper_bound(cfg.adaptive_k)
        if upper <= 0 or window.pps <= upper:
            return []
        return [Alert(
            timestamp=ts,
            alert_type=AlertType.ANOMALY_SPIKE,
            severity=Severity.MEDIUM,
            message=(
                f"Traffic {window.pps:.1f} pps deviates from baseline "
                f"(mean={baseline.mean:.1f}, upper_bound={upper:.1f})"
            ),
            metric_value=window.pps,
            threshold=upper,
        )]
