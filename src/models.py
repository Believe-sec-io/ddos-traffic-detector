"""Core data models shared across the DDoS detector package."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Protocol(str, Enum):
    """Transport-layer protocol classification for a captured packet."""

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class AlertType(str, Enum):
    """Category of anomaly detected in a traffic window."""

    VOLUMETRIC_FLOOD = "VOLUMETRIC_FLOOD"
    SYN_FLOOD = "SYN_FLOOD"
    UDP_FLOOD = "UDP_FLOOD"
    ICMP_FLOOD = "ICMP_FLOOD"
    SOURCE_FLOOD = "SOURCE_FLOOD"
    DISTRIBUTED_FLOOD = "DISTRIBUTED_FLOOD"
    ANOMALY_SPIKE = "ANOMALY_SPIKE"


class Severity(str, Enum):
    """Relative severity of a raised alert."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class PacketEvent:
    """A normalized representation of a single captured packet.

    This is the boundary object between the capture layer (scapy) and the
    detection logic, allowing the detector to be unit tested without any
    real network I/O or scapy dependency.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: Protocol
    size: int
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    src_port: Optional[int] = None
    dst_port: Optional[int] = None


@dataclass
class Alert:
    """An anomaly raised by the detector for a given traffic window."""

    timestamp: float
    alert_type: AlertType
    severity: Severity
    message: str
    metric_value: float
    threshold: float
    src_ip: Optional[str] = None
