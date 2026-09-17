"""Tests for the scapy -> PacketEvent conversion layer.

These tests build packets in memory (no capture privileges required) and are
skipped automatically when scapy is not installed.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from src.capture import packet_to_event
from src.models import Protocol

scapy = pytest.importorskip("scapy")
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402


def test_tcp_syn_packet_conversion():
    pkt = IP(src="203.0.113.5", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S")
    event = packet_to_event(pkt, timestamp=1000.0)

    assert event is not None
    assert event.timestamp == 1000.0
    assert event.src_ip == "203.0.113.5"
    assert event.dst_ip == "10.0.0.1"
    assert event.protocol is Protocol.TCP
    assert event.syn is True
    assert event.ack is False
    assert event.src_port == 12345
    assert event.dst_port == 80
    assert event.size > 0


def test_tcp_syn_ack_is_marked_both_flags():
    pkt = IP(src="10.0.0.1", dst="203.0.113.5") / TCP(sport=80, dport=12345, flags="SA")
    event = packet_to_event(pkt, timestamp=1000.0)
    assert event is not None
    assert event.syn is True
    assert event.ack is True


def test_udp_packet_conversion():
    pkt = IP(src="198.51.100.9", dst="10.0.0.1") / UDP(sport=53, dport=33333)
    event = packet_to_event(pkt, timestamp=1000.0)
    assert event is not None
    assert event.protocol is Protocol.UDP
    assert event.src_port == 53
    assert event.syn is False


def test_icmp_packet_conversion():
    pkt = IP(src="198.51.100.20", dst="10.0.0.1") / ICMP()
    event = packet_to_event(pkt, timestamp=1000.0)
    assert event is not None
    assert event.protocol is Protocol.ICMP
    assert event.src_port is None


def test_non_ip_packet_is_ignored():
    from scapy.layers.l2 import ARP

    assert packet_to_event(ARP(pdst="10.0.0.1"), timestamp=1000.0) is None


def test_timestamp_defaults_to_packet_time_when_available():
    pkt = IP(src="203.0.113.5", dst="10.0.0.1") / TCP()
    pkt.time = 1234.5
    event = packet_to_event(pkt)
    assert event is not None
    assert event.timestamp == pytest.approx(1234.5)


REPLAY_CHECK_SCRIPT = '''
import sys
sys.path.insert(0, r"{project_root}")
from src.capture import replay_pcap

events = []
replay_pcap(r"{pcap_path}", on_event=events.append, speed=1000000.0)
print("EVENTS", len(events))
'''


def test_replay_pcap_works_in_a_fresh_interpreter(tmp_path, project_root):
    """Regression test: replaying a pcap must not depend on scapy layers having
    been imported earlier in the process.

    Earlier versions used only lazy ``scapy.utils`` imports, so a pcap whose
    link type had not been registered yet was decoded as ``Raw`` packets and
    every packet was silently dropped. This test runs the replay in a brand
    new interpreter to reproduce a "cold" process.
    """
    pytest.importorskip("scapy")
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    packets = []
    for i in range(3):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="203.0.113.5", dst="10.0.0.1") / TCP(sport=1024 + i, dport=80, flags="S")
        packet.time = 1000.0 + i
        packets.append(packet)

    pcap_path = tmp_path / "cold_start.pcap"
    wrpcap(str(pcap_path), packets)

    script_path = tmp_path / "replay_check.py"
    script_path.write_text(
        REPLAY_CHECK_SCRIPT.format(project_root=project_root, pcap_path=pcap_path),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        cwd=str(project_root),
    )
    assert result.returncode == 0, result.stderr
    assert "EVENTS 3" in result.stdout, f"stdout={result.stdout!r} stderr={result.stderr!r}"
