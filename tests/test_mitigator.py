"""Tests for the mitigation layer (always exercised in dry-run mode so no real
firewall rules are created).
"""

from __future__ import annotations

from src.mitigator import Mitigator
from src.models import Alert, AlertType, Severity


def _alert(src_ip=None, message="synthetic alert") -> Alert:
    return Alert(
        timestamp=1.0,
        alert_type=AlertType.SOURCE_FLOOD,
        severity=Severity.HIGH,
        message=message,
        metric_value=300.0,
        threshold=200.0,
        src_ip=src_ip,
    )


def test_block_ip_is_dry_run_and_tracked():
    mitigator = Mitigator(dry_run=True, block_duration=60.0)
    assert not mitigator.is_blocked("203.0.113.5")

    action = mitigator.block_ip("203.0.113.5", _alert(src_ip="203.0.113.5"))
    assert action.action == "BLOCK_IP"
    assert action.target == "203.0.113.5"
    assert action.dry_run is True
    assert mitigator.is_blocked("203.0.113.5")
    assert "203.0.113.5" in mitigator.blocklist


def test_blocking_again_extends_the_block():
    mitigator = Mitigator(dry_run=True, block_duration=60.0)
    mitigator.block_ip("203.0.113.5")
    first_expiry = mitigator.blocklist["203.0.113.5"]
    action = mitigator.block_ip("203.0.113.5")
    assert "block extended" in action.detail
    assert mitigator.blocklist["203.0.113.5"] >= first_expiry


def test_handle_alert_with_source_ip_blocks_it():
    mitigator = Mitigator(dry_run=True)
    actions = mitigator.handle_alert(_alert(src_ip="198.51.100.9"))
    assert len(actions) == 1
    assert actions[0].action == "BLOCK_IP"
    assert mitigator.is_blocked("198.51.100.9")


def test_handle_alert_without_source_ip_is_alert_only():
    mitigator = Mitigator(dry_run=True)
    actions = mitigator.handle_alert(_alert(src_ip=None))
    assert len(actions) == 1
    assert actions[0].action == "ALERT_ONLY"
    assert actions[0].target is None
    assert mitigator.blocklist == {}


def test_unblock_expired_removes_only_expired_entries():
    mitigator = Mitigator(dry_run=True, block_duration=60.0)
    mitigator.block_ip("203.0.113.5")
    mitigator.block_ip("198.51.100.9")

    # Force one entry to already be expired.
    mitigator._blocklist["198.51.100.9"] = 10.0
    unblocked = mitigator.unblock_expired(now=100.0)

    assert unblocked == ["198.51.100.9"]
    assert not mitigator.is_blocked("198.51.100.9")
    assert mitigator.is_blocked("203.0.113.5")
