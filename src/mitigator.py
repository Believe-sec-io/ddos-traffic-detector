"""Mitigation actions taken in response to alerts (IP blocking)."""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from .models import Alert

logger = logging.getLogger("ddos_detector.mitigator")


@dataclass
class MitigationAction:
    """A single mitigation action taken (or that would be taken in dry-run)."""

    timestamp: float
    action: str
    target: Optional[str]
    dry_run: bool
    detail: str


class Mitigator:
    """Applies mitigation for raised alerts.

    By default operates in ``dry_run`` mode: actions are logged and tracked
    internally but no real firewall rule is created. Set ``dry_run=False``
    (and run as Administrator on Windows) to actually block IPs via
    ``netsh advfirewall``.
    """

    def __init__(
        self,
        dry_run: bool = True,
        block_duration: float = 300.0,
        firewall_rule_prefix: str = "DDOS_BLOCK",
    ):
        self.dry_run = dry_run
        self.block_duration = block_duration
        self.firewall_rule_prefix = firewall_rule_prefix
        self._blocklist: Dict[str, float] = {}  # ip -> expiry timestamp

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocklist

    @property
    def blocklist(self) -> Dict[str, float]:
        """A copy of the current IP -> expiry-timestamp blocklist."""
        return dict(self._blocklist)

    def handle_alert(self, alert: Alert) -> List[MitigationAction]:
        """Dispatch mitigation for a raised alert.

        If the alert identifies a single offending source IP, that IP is
        blocked. Otherwise (e.g. a distributed or volumetric flood with no
        single culprit) the action is logged only.
        """
        actions: List[MitigationAction] = []
        if alert.src_ip:
            actions.append(self.block_ip(alert.src_ip, alert))
        else:
            # No source IP attached: the traffic is distributed (or the alert
            # is purely volumetric), so there is nothing meaningful to block
            # locally. Upstream scrubbing / rate limiting is required instead.
            logger.warning(
                "ALERT [%s/%s] %s (distributed or volumetric pattern; "
                "no single source IP to block)",
                alert.alert_type.value,
                alert.severity.value,
                alert.message,
            )
            actions.append(MitigationAction(
                timestamp=alert.timestamp,
                action="ALERT_ONLY",
                target=None,
                dry_run=self.dry_run,
                detail=alert.message,
            ))
        return actions

    def block_ip(self, ip: str, alert: Optional[Alert] = None) -> MitigationAction:
        """Block (or simulate blocking) a single IP address."""
        now = time.time()
        expiry = now + self.block_duration
        already_blocked = self.is_blocked(ip)
        self._blocklist[ip] = expiry

        detail = alert.message if alert else f"Manual block of {ip}"
        if already_blocked:
            detail += " (block extended)"

        if self.dry_run:
            logger.info(
                "[DRY-RUN] Would block IP %s until %s | reason: %s",
                ip, time.ctime(expiry), detail,
            )
        else:
            rule_name = f"{self.firewall_rule_prefix}_{ip}"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}",
            ]
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                logger.warning("Blocked IP %s via Windows Firewall (rule=%s)", ip, rule_name)
            except (subprocess.CalledProcessError, FileNotFoundError) as exc:
                logger.error("Failed to block IP %s: %s", ip, exc)

        return MitigationAction(
            timestamp=now,
            action="BLOCK_IP",
            target=ip,
            dry_run=self.dry_run,
            detail=detail,
        )

    def unblock_expired(self, now: Optional[float] = None) -> List[str]:
        """Remove any blocks whose expiry has passed. Returns unblocked IPs."""
        now = now if now is not None else time.time()
        expired = [ip for ip, expiry in self._blocklist.items() if expiry <= now]
        for ip in expired:
            self._unblock(ip)
        return expired

    def _unblock(self, ip: str) -> None:
        del self._blocklist[ip]
        if self.dry_run:
            logger.info("[DRY-RUN] Would unblock IP %s", ip)
            return
        rule_name = f"{self.firewall_rule_prefix}_{ip}"
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.info("Unblocked IP %s (removed rule=%s)", ip, rule_name)
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            logger.error("Failed to unblock IP %s: %s", ip, exc)
