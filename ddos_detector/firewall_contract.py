"""Proposed W3 adapter messages, pending component-owner review."""
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from ipaddress import IPv4Address
import math


class RuleState(str, Enum):
    INSTALLED = "installed"
    ABSENT = "absent"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class BlockRequest:
    """Identify one temporary IPv4 block action across retries."""

    block_id: str
    source_ip: str
    reason: str
    duration_seconds: float = 300

    def __post_init__(self):
        if (not isinstance(self.block_id, str) or not self.block_id.strip()
                or not isinstance(self.reason, str) or not self.reason.strip()):
            raise ValueError("Block ID and reason must be nonempty")
        if not isinstance(self.source_ip, str):
            raise ValueError("Source IP must be a dotted-decimal IPv4 string")
        IPv4Address(self.source_ip)
        if (not isinstance(self.duration_seconds, (int, float))
                or isinstance(self.duration_seconds, bool)
                or self.duration_seconds <= 0
                or self.duration_seconds >= timedelta.max.total_seconds()
                or not math.isfinite(self.duration_seconds)
                or timedelta(seconds=self.duration_seconds) <= timedelta(0)):
            raise ValueError("Block duration must be finite, positive, and representable")


@dataclass(frozen=True)
class FirewallResult:
    """Report verified rule state separately from command success.

    UNKNOWN retains the action's capacity reservation until reconciliation.
    observed_at records the observation, not the first installation time.
    """

    block_id: str
    operation: str
    success: bool
    rule_state: RuleState
    observed_at: datetime
    error: str | None = None

    def __post_init__(self):
        if not isinstance(self.block_id, str) or not self.block_id.strip():
            raise ValueError("Block ID must be nonempty")
        if self.operation not in {"apply", "verify", "expire", "remove"}:
            raise ValueError("Unsupported firewall operation")
        if not isinstance(self.rule_state, RuleState):
            raise ValueError("Rule state must be a RuleState value")
        if not isinstance(self.observed_at, datetime) or self.observed_at.utcoffset() is None:
            raise ValueError("Observation time must include a timezone")
        if not isinstance(self.success, bool):
            raise ValueError("Success must be a boolean")
        if self.success and self.rule_state == RuleState.UNKNOWN:
            raise ValueError("An unknown rule state cannot establish success")
        if self.success and self.operation in {"apply", "remove", "expire"}:
            expected = RuleState.INSTALLED if self.operation == "apply" else RuleState.ABSENT
            if self.rule_state != expected:
                raise ValueError("Successful operation requires its expected verified state")
        if not self.success and not self.error:
            raise ValueError("An unsuccessful operation requires error details")
