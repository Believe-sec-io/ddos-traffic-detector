"""Tests for the command-line interface, including an end-to-end replay run."""

from __future__ import annotations

import pytest

from src.cli import parse_args


def test_parse_live_with_options_after_subcommand():
    args = parse_args(["live", "--interface", "Wi-Fi", "--filter", "tcp", "--log-level", "DEBUG"])
    assert args.command == "live"
    assert args.interface == "Wi-Fi"
    assert args.filter == "tcp"
    assert args.log_level == "DEBUG"


def test_parse_live_with_global_options_before_subcommand():
    args = parse_args(["--log-file", "run.log", "live"])
    assert args.command == "live"
    assert args.log_file == "run.log"


def test_parse_replay_defaults():
    args = parse_args(["replay", "capture.pcap"])
    assert args.command == "replay"
    assert args.pcap_path == "capture.pcap"
    assert args.speed == 0.0
    # Defaults are suppressed so that config/log-level are resolved by main().
    assert getattr(args, "config", "config.yaml") == "config.yaml"


def test_main_replay_end_to_end_detects_and_mitigates(tmp_path):
    """Full pipeline check: real pcap -> detector -> dry-run mitigation."""
    pytest.importorskip("scapy")
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    from src.cli import main

    packets = []
    for i in range(200):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="203.0.113.5", dst="10.0.0.1") / TCP(sport=1024 + i, dport=80, flags="S")
        packet.time = 1000.0 + i * 0.005
        packets.append(packet)

    pcap_path = tmp_path / "flood.pcap"
    wrpcap(str(pcap_path), packets)

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "detector:\n"
        "  max_per_src_pps: 50\n"
        "  min_syn_count: 10\n"
        "  syn_ratio_threshold: 0.5\n",
        encoding="utf-8",
    )

    log_path = tmp_path / "run.log"
    exit_code = main([
        "replay", str(pcap_path),
        "--speed", "0",
        "--config", str(config_path),
        "--log-file", str(log_path),
    ])

    assert exit_code == 0
    log_text = log_path.read_text(encoding="utf-8")
    assert "ALERT[SYN_FLOOD" in log_text
    assert "ALERT[SOURCE_FLOOD" in log_text
    assert "[DRY-RUN] Would block IP 203.0.113.5" in log_text
    assert "Total alerts raised" in log_text


def test_main_with_missing_config_and_pcap_fails_cleanly(tmp_path):
    from src.cli import main

    missing = tmp_path / "does_not_exist.yaml"
    exit_code = main(["replay", str(missing), "--config", str(missing)])
    # Missing config falls back to defaults; the missing pcap is reported and
    # returns a clean non-zero exit code instead of raising.
    assert exit_code == 1
