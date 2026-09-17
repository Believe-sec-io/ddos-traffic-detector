"""Traffic aggregation primitives: sliding windows and adaptive baselines."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import Deque, Optional, Tuple

from .models import PacketEvent, Protocol


@dataclass
class TrafficWindow:
    """Aggregates all :class:`PacketEvent` objects that fall within a fixed
    time slice ``[start_time, start_time + duration)``.
    """

    start_time: float
    duration: float = 1.0
    total_packets: int = 0
    total_bytes: int = 0
    syn_count: int = 0
    proto_counts: Counter = field(default_factory=Counter)
    per_src_packets: Counter = field(default_factory=Counter)
    unique_src_ips: set = field(default_factory=set)

    def add(self, event: PacketEvent) -> None:
        """Fold a packet event into this window's running counters."""
        self.total_packets += 1
        self.total_bytes += event.size
        self.proto_counts[event.protocol] += 1
        self.per_src_packets[event.src_ip] += 1
        self.unique_src_ips.add(event.src_ip)
        if event.syn and not event.ack:
            self.syn_count += 1

    def contains(self, timestamp: float) -> bool:
        """Return True if ``timestamp`` belongs to this window's time slice."""
        return self.start_time <= timestamp < self.start_time + self.duration

    @property
    def pps(self) -> float:
        """Packets per second observed in this window."""
        return self.total_packets / self.duration if self.duration else 0.0

    @property
    def bps(self) -> float:
        """Bits per second observed in this window."""
        return (self.total_bytes * 8) / self.duration if self.duration else 0.0

    @property
    def syn_ratio(self) -> float:
        """Fraction of packets that were bare SYNs (SYN without ACK)."""
        if self.total_packets == 0:
            return 0.0
        return self.syn_count / self.total_packets

    def top_talkers(self, n: int = 5):
        """Return the ``n`` source IPs with the most packets in this window."""
        return self.per_src_packets.most_common(n)

    def max_source_pps(self) -> Tuple[Optional[str], float]:
        """Return ``(src_ip, pps)`` for the single busiest source IP."""
        if not self.per_src_packets:
            return None, 0.0
        src, count = self.per_src_packets.most_common(1)[0]
        return src, count / self.duration if self.duration else 0.0

    def proto_pps(self, protocol: Protocol) -> float:
        """Packets per second for a specific protocol in this window."""
        count = self.proto_counts.get(protocol, 0)
        return count / self.duration if self.duration else 0.0


class BaselineTracker:
    """Maintains a rolling history of recent window ``pps`` values so the
    detector can flag statistically abnormal spikes (mean + k*stdev), on top
    of static thresholds.
    """

    def __init__(self, history_size: int = 60):
        if history_size < 1:
            raise ValueError("history_size must be >= 1")
        self.history_size = history_size
        self._history: Deque[float] = deque(maxlen=history_size)

    def update(self, pps: float) -> None:
        """Record a new observed pps sample into the rolling history."""
        self._history.append(pps)

    @property
    def sample_count(self) -> int:
        return len(self._history)

    @property
    def is_ready(self) -> bool:
        """Whether enough samples have been collected to trust the baseline."""
        min_samples = max(5, self.history_size // 4)
        return len(self._history) >= min_samples

    @property
    def mean(self) -> float:
        return mean(self._history) if self._history else 0.0

    @property
    def stdev(self) -> float:
        if len(self._history) < 2:
            return 0.0
        return pstdev(self._history)

    def upper_bound(self, k: float = 3.0) -> float:
        """Return the ``mean + k * stdev`` anomaly threshold."""
        return self.mean + k * self.stdev
