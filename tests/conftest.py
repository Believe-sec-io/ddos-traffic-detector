"""Shared fixtures and synthetic traffic generators for the test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.detector import DetectorConfig
from src.models import PacketEvent, Protocol

DST_IP = "10.0.0.1"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def project_root() -> Path:
    """Absolute path to the project root (directory containing config.yaml)."""
    return PROJECT_ROOT


def make_event(
    ts: float,
    src: str,
    protocol: Protocol = Protocol.TCP,
    syn: bool = False,
    ack: bool = False,
    size: int = 60,
    dst: str = DST_IP,
) -> PacketEvent:
    """Build a synthetic :class:`PacketEvent` for deterministic tests."""
    return PacketEvent(
        timestamp=ts,
        src_ip=src,
        dst_ip=dst,
        protocol=protocol,
        size=size,
        syn=syn,
        ack=ack,
    )


@pytest.fixture
def default_config() -> DetectorConfig:
    """Default detector thresholds (same values as config.yaml)."""
    return DetectorConfig()


@pytest.fixture
def syn_flood_packets():
    """100 bare SYNs from a single IP inside a single 1-second window."""
    return [make_event(1000.0 + i * 0.001, "203.0.113.5", syn=True) for i in range(100)]


@pytest.fixture
def udp_flood_packets():
    """600 UDP packets/sec from a single IP (UDP flood signature)."""
    return [make_event(1000.0 + i * 0.001, "198.51.100.9", protocol=Protocol.UDP) for i in range(600)]


@pytest.fixture
def icmp_flood_packets():
    """400 ICMP packets/sec (ping flood signature)."""
    return [make_event(1000.0 + i * 0.001, "198.51.100.20", protocol=Protocol.ICMP) for i in range(400)]


@pytest.fixture
def distributed_flood_packets():
    """1000 packets/sec spread evenly across 50 distinct source IPs."""
    packets = []
    for src_index in range(50):
        for i in range(20):
            packets.append(make_event(1000.0 + i * 0.001, f"203.0.113.{src_index}"))
    return packets


@pytest.fixture
def normal_packets():
    """A light, benign traffic sample spread across 5 source IPs."""
    return [
        make_event(1000.0 + i * 0.01, f"192.168.1.{10 + (i % 5)}", ack=True)
        for i in range(20)
    ]
