"""Command-line interface for the DDoS traffic detector."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional, Sequence

from .capture import replay_pcap, sniff_live
from .engine import build_engine_from_config, load_config
from .logger_config import setup_logging

logger = logging.getLogger("ddos_detector.cli")

DEFAULT_CONFIG_PATH = "config.yaml"


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    """Add options shared by the top-level parser and every subcommand.

    ``default=argparse.SUPPRESS`` keeps the attribute out of the namespace
    unless the user actually provides it, so a value given after the
    subcommand does not clobber a value given before it.
    """
    parser.add_argument(
        "--config", default=argparse.SUPPRESS, help="Path to YAML config file"
    )
    parser.add_argument(
        "--log-level", default=argparse.SUPPRESS, help="Logging level (DEBUG, INFO, WARNING, ...)"
    )
    parser.add_argument(
        "--log-file", default=argparse.SUPPRESS, help="Optional log file path"
    )


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    common = argparse.ArgumentParser(add_help=False)
    _add_common_options(common)

    parser = argparse.ArgumentParser(
        prog="ddos-detector",
        description="DDoS traffic anomaly detector and mitigator",
        parents=[common],
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    live_parser = subparsers.add_parser(
        "live", help="Capture and analyze live network traffic", parents=[common]
    )
    live_parser.add_argument("--interface", default=None, help="Network interface to sniff on (default: scapy default)")
    live_parser.add_argument("--filter", default="ip", help="BPF filter expression")

    replay_parser = subparsers.add_parser(
        "replay", help="Replay a pcap file through the detector", parents=[common]
    )
    replay_parser.add_argument("pcap_path", help="Path to a .pcap/.pcapng file")
    replay_parser.add_argument(
        "--speed", type=float, default=0.0,
        help="Replay speed multiplier relative to real time (0 = as fast as possible)",
    )

    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    config_path = getattr(args, "config", DEFAULT_CONFIG_PATH)
    setup_logging(getattr(args, "log_level", "INFO"), getattr(args, "log_file", None))

    try:
        config = load_config(config_path)
    except FileNotFoundError:
        logger.warning("Config file %s not found, using built-in defaults", config_path)
        config = {}

    engine = build_engine_from_config(config)

    if args.command == "live":
        logger.info("Mode: LIVE capture. Press Ctrl+C to stop.")
        try:
            sniff_live(args.interface, on_event=engine.on_event, bpf_filter=args.filter)
        except KeyboardInterrupt:
            logger.info("Stopping capture (Ctrl+C received)...")
        finally:
            engine.force_flush()
    elif args.command == "replay":
        logger.info("Mode: REPLAY from %s", args.pcap_path)
        speed = args.speed if args.speed > 0 else 1_000_000.0  # effectively "as fast as possible"
        try:
            replay_pcap(args.pcap_path, on_event=engine.on_event, speed=speed)
        except FileNotFoundError:
            logger.error("Pcap file not found: %s", args.pcap_path)
            return 1
        engine.force_flush()
    else:  # pragma: no cover - argparse enforces valid subcommands
        logger.error("Unknown command %s", args.command)
        return 1

    logger.info("Done. Total alerts raised: %d", engine.alerts_raised)
    return 0


if __name__ == "__main__":
    sys.exit(main())
