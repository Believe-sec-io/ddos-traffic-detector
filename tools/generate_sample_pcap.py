#!/usr/bin/env python3
"""Generate a synthetic .pcap file containing benign traffic followed by a
SYN-flood style DDoS burst.

This lets you demo/validate the whole pipeline offline, without needing
Administrator privileges or touching a real network:

    python tools\\generate_sample_pcap.py sample_attack.pcap
    python main.py replay sample_attack.pcap --speed 0

Requires scapy (installed via requirements.txt).
"""

from __future__ import annotations

import argparse
import random
from typing import List

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

SERVER_IP = "10.0.0.1"
BENIGN_CLIENT_IPS = [f"192.168.1.{i}" for i in range(10, 15)]


def build_benign_traffic(start_time: float, duration: float = 1.0, pps: int = 50) -> List:
    """Light, evenly distributed TCP traffic from a handful of clients."""
    packets = []
    for i in range(pps):
        ts = start_time + i * (duration / pps)
        src = random.choice(BENIGN_CLIENT_IPS)
        packet = Ether() / IP(src=src, dst=SERVER_IP) / TCP(sport=random.randint(1024, 65535), dport=443, flags="A")
        packet.time = ts
        packets.append(packet)
    return packets


def build_syn_flood(start_time: float, duration: float = 1.0, pps: int = 500, src_ip: str = "203.0.113.5") -> List:
    """Bare SYN packets at a high rate from a single spoofed-looking source."""
    packets = []
    for i in range(pps):
        ts = start_time + i * (duration / pps)
        packet = Ether() / IP(src=src_ip, dst=SERVER_IP) / TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        packet.time = ts
        packets.append(packet)
    return packets


def build_udp_flood(start_time: float, duration: float = 1.0, pps: int = 400) -> List:
    """UDP flood spread across several sources (reflection/amplification style)."""
    packets = []
    for i in range(pps):
        ts = start_time + i * (duration / pps)
        src = f"198.51.100.{i % 20 + 1}"
        packet = Ether() / IP(src=src, dst=SERVER_IP) / UDP(sport=123, dport=53)
        packet.time = ts
        packets.append(packet)
    return packets


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a synthetic DDoS demo pcap")
    parser.add_argument("output", help="Output .pcap path")
    parser.add_argument("--start-time", type=float, default=1_700_000_000.0, help="Epoch start time")
    parser.add_argument("--seed", type=int, default=1337, help="Random seed for reproducibility")
    args = parser.parse_args()

    random.seed(args.seed)
    packets = []
    packets += build_benign_traffic(args.start_time, duration=1.0, pps=50)
    packets += build_udp_flood(args.start_time + 1.0, duration=1.0, pps=400)
    packets += build_syn_flood(args.start_time + 2.0, duration=1.0, pps=500)
    packets.sort(key=lambda p: p.time)

    wrpcap(args.output, packets)
    print(f"Wrote {len(packets)} packets to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())