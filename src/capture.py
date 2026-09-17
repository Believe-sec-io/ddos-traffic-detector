"""Packet capture layer: converts real network traffic (via scapy) into the
protocol-agnostic :class:`PacketEvent` objects consumed by the detector.

Scapy is imported lazily inside functions so that the rest of the package
(models, stats, detector, mitigator) can be unit tested without requiring
scapy/Npcap to be installed or without needing Administrator privileges.
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional

from .models import PacketEvent, Protocol

logger = logging.getLogger("ddos_detector.capture")


def _load_scapy_layers() -> None:
    """Populate scapy's protocol/link-type registries before reading packets.

    scapy registers link types (e.g. LINKTYPE_IPV4 -> IP, LINKTYPE_ETHERNET
    -> Ether) lazily when the corresponding layer modules are imported.
    Without this import, ``PcapReader`` silently falls back to ``Raw``
    packets for files whose link type has not been registered yet, and every
    packet would be discarded as "not IP".
    """
    import scapy.all  # noqa: F401  (side effect: fills conf.l2types/l3types)


def _protocol_of(pkt) -> Protocol:
    from scapy.layers.inet import ICMP, TCP, UDP

    if pkt.haslayer(TCP):
        return Protocol.TCP
    if pkt.haslayer(UDP):
        return Protocol.UDP
    if pkt.haslayer(ICMP):
        return Protocol.ICMP
    return Protocol.OTHER


def packet_to_event(pkt, timestamp: Optional[float] = None) -> Optional[PacketEvent]:
    """Convert a scapy packet into a :class:`PacketEvent`.

    Returns ``None`` for non-IP packets (e.g. ARP), which are ignored by the
    detector since DDoS analysis operates on IP traffic.

    Handles both a bare ``IP()`` packet and an ``Ether()/IP()`` frame, so it
    works with captures written by this project as well as with any real
    pcap produced by tcpdump/Wireshark.
    """
    from scapy.layers.inet import IP, TCP, UDP

    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    proto = _protocol_of(pkt)
    syn = ack = False
    src_port = dst_port = None

    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        flags = str(tcp_layer.flags)
        syn = "S" in flags
        ack = "A" in flags
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)

    ts = timestamp if timestamp is not None else float(getattr(pkt, "time", time.time()))

    return PacketEvent(
        timestamp=ts,
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        protocol=proto,
        size=len(pkt),
        syn=syn,
        ack=ack,
        src_port=src_port,
        dst_port=dst_port,
    )


def sniff_live(
    interface: Optional[str],
    on_event: Callable[[PacketEvent], None],
    bpf_filter: str = "ip",
    stop_event=None,
) -> None:
    """Sniff packets live on ``interface`` and invoke ``on_event`` for each
    resulting :class:`PacketEvent`.

    Requires Npcap (Windows) or libpcap (Linux/macOS) and, in most cases,
    Administrator/root privileges.
    """
    _load_scapy_layers()
    from scapy.all import sniff

    def _prn(pkt):
        event = packet_to_event(pkt)
        if event is not None:
            on_event(event)

    def _stop_filter(_pkt):
        return stop_event.is_set() if stop_event is not None else False

    logger.info("Starting live capture on interface=%s filter=%r", interface or "default", bpf_filter)
    sniff(iface=interface, prn=_prn, filter=bpf_filter, store=False, stop_filter=_stop_filter)


def replay_pcap(path: str, on_event: Callable[[PacketEvent], None], speed: float = 1.0) -> None:
    """Replay packets from a ``.pcap``/``.pcapng`` file, invoking ``on_event``
    for each one.

    ``speed`` scales the original inter-packet delay: ``speed=1`` replays in
    real time, ``speed=2`` replays twice as fast, very large values replay
    effectively "as fast as possible".
    """
    _load_scapy_layers()
    from scapy.utils import PcapReader

    logger.info("Replaying pcap file=%s speed=%.2fx", path, speed)
    last_ts: Optional[float] = None
    with PcapReader(path) as reader:
        for pkt in reader:
            ts = float(getattr(pkt, "time", time.time()))
            if last_ts is not None and speed > 0:
                delay = (ts - last_ts) / speed
                if delay > 0:
                    time.sleep(delay)
            last_ts = ts
            event = packet_to_event(pkt, timestamp=ts)
            if event is not None:
                on_event(event)
