#!/usr/bin/env python3
"""Entry point for the DDoS Traffic Detector.

Usage:
    python main.py live --interface "Wi-Fi"
    python main.py replay path\\to\\capture.pcap
"""
from src.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
