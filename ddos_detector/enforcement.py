"""Source-policy decisions connected to the verified W3 firewall lifecycle."""
from dataclasses import dataclass
from ipaddress import IPv4Address
import math
from uuid import uuid4

from .firewall_contract import BlockRequest
from .firewall_cli import report


def finite(value, name, minimum=0):
    if type(value) not in (int, float) or not math.isfinite(value) or value < minimum:
        raise ValueError(f"{name} must be finite and >= {minimum}")
    return value


@dataclass(frozen=True)
class PolicySettings:
    packet_thresholds: tuple  # ((protocol, threshold-or-None), ...)
    syn_threshold: float | None
    min_share: float | None
    consecutive: int = 3
    block_seconds: float = 300
    review_ref: str | None = None
    max_window_age_seconds: float | None = None

    def __post_init__(self):
        if dict(self.packet_thresholds).keys() != {"tcp", "udp", "icmp"} or len(self.packet_thresholds) != 3:
            raise ValueError("Expected exactly tcp/udp/icmp thresholds")
        for name, value in (*self.packet_thresholds, ("syn", self.syn_threshold), ("share", self.min_share)):
            if value is not None:
                finite(value, name)
        if self.min_share is not None and self.min_share > 1:
            raise ValueError("Minimum share must be <= 1")
        if type(self.consecutive) is not int or self.consecutive < 1:
            raise ValueError("Consecutive-window count must be a positive integer")
        BlockRequest("validation", "10.10.10.30", "validation", self.block_seconds)
        if self.max_window_age_seconds is not None:
            finite(self.max_window_age_seconds, "Maximum window age", 0.001)

    @classmethod
    def from_document(cls, document):
        if document["schema"] != "policy-defaults-draft-1":
            raise ValueError("Unsupported policy schema")
        attribution, blocks, window = document["attribution"], document["blocks"], document["window"]
        expected = {"share_basis": "all_selected_packets", "block_key": "src_ip",
                    "streak_key": ["src_ip", "protocol"],
                    "unset_threshold_behavior": "never qualifies",
                    "threshold_comparison": "rate_strictly_greater_than_threshold; share_greater_or_equal_to_min_share"}
        if any(attribution[key] != value for key, value in expected.items()):
            raise ValueError("Unsupported attribution semantics")
        if (window["window_seconds"] != 1 or window["origin"] != "epoch"
                or window["interval"] != "start_inclusive_end_exclusive"
                or document["scope"]["protocols"] != ["tcp", "udp", "icmp"]):
            raise ValueError("Expected version-one epoch windows and protocols")
        expected_blocks = {"renew_on_repeat_detection": False, "reset_streak_on_expiry": True,
                           "reset_streaks_on_mode_change": True, "cap_reached_behavior": "alert_only_no_eviction",
                           "pending_requests_reserve_cap_slots": True, "expiry_requires_confirmed_removal": True,
                           "unknown_outcome_behavior": "retain_reservation_until_verified_reconciliation",
                           "priority": "packet_count_desc_then_numeric_ipv4_asc",
                           "expiry_clock_starts": "first firewall-confirmed installation"}
        if any(blocks[key] != value for key, value in expected_blocks.items()):
            raise ValueError("Unsupported block lifecycle semantics")
        return cls(tuple(sorted(attribution["packet_rate_thresholds"].items())),
                   attribution["syn_rate_threshold"], attribution["min_share"],
                   attribution["required_consecutive_windows"], blocks["block_seconds"],
                   document.get("policy_review_ref"), document.get("max_window_age_seconds"))

    def require_automatic(self, scope):
        if not scope.verified:
            raise ValueError("Automatic mode requires verified lab scope/allowlist")
        if not isinstance(self.review_ref, str) or not self.review_ref.strip():
            raise ValueError("Automatic mode requires policy_review_ref for approved settings")
        if (self.min_share is None or self.max_window_age_seconds is None
                or all(value is None for _, value in self.packet_thresholds) and self.syn_threshold is None):
            raise ValueError("Automatic mode requires reviewed share/rate settings and maximum window age")


class SourcePolicy:
    def __init__(self, settings, scope):
        self.settings, self.scope = settings, scope
        self._streaks = {}
        self._last_end = None

    def reset(self, source_ip=None):
        if source_ip is None:
            self._streaks.clear()
            self._last_end = None
        else:
            self._streaks = {key: n for key, n in self._streaks.items() if key[0] != source_ip}

    def evaluate(self, event, record):
        start, end = record.window_start, record.window_end
        finite(start, "Window start")
        finite(end, "Window end")
        if end - start != 1 or start % 1:
            raise ValueError("Expected finalized epoch-aligned one-second window")
        if self._last_end is not None and start < self._last_end:
            self.reset()
            raise ValueError("Duplicate or out-of-order policy window")
        if start != self._last_end:
            self._streaks.clear()
        self._last_end = end
        if (event.get("window_start"), event.get("window_end"), event.get("packet_count")) != (start, end, record.packet_count):
            self.reset()
            raise ValueError("Scored event does not match attribution window")
        if (event.get("scored") is not True or event.get("predicted_attack") is not True
                or record.capped or record.untracked_source_packets or record.packet_count == 0):
            self._streaks.clear()
            return []
        counts, seen = record.source_counts, set()
        for row in counts:
            IPv4Address(row.source_ip)
            key = row.source_ip, row.protocol
            if (key in seen or row.protocol not in {"tcp", "udp", "icmp"}
                    or type(row.packets) is not int or row.packets <= 0
                    or type(row.syn_packets) is not int or not 0 <= row.syn_packets <= row.packets
                    or row.protocol != "tcp" and row.syn_packets):
                self.reset()
                raise ValueError("Invalid source/protocol counts")
            seen.add(key)
        if sum(row.packets for row in counts) != record.packet_count:
            self.reset()
            raise ValueError("Attribution does not account for all selected packets")
        next_streaks, candidates = {}, []
        thresholds = dict(self.settings.packet_thresholds)
        for row in counts:
            share = row.packets / record.packet_count
            rate_limit = thresholds[row.protocol]
            rate_ok = rate_limit is not None and row.packets > rate_limit
            syn_ok = row.protocol == "tcp" and self.settings.syn_threshold is not None and row.syn_packets > self.settings.syn_threshold
            if (self.scope.is_protected(row.source_ip) or self.settings.min_share is None
                    or share < self.settings.min_share or not (rate_ok or syn_ok)):
                continue
            key = row.source_ip, row.protocol
            streak = min(self._streaks.get(key, 0) + 1, self.settings.consecutive)
            next_streaks[key] = streak
            candidates.append({"source_ip": row.source_ip, "protocol": row.protocol,
                               "packets_per_second": row.packets, "syn_per_second": row.syn_packets if row.protocol == "tcp" else None,
                               "packet_share": share, "consecutive_windows": streak,
                               "eligible": streak >= self.settings.consecutive})
        self._streaks = next_streaks
        return sorted(candidates, key=lambda row: (-row["packets_per_second"], int(IPv4Address(row["source_ip"])), row["protocol"]))


class Enforcement:
    """One serialized owner. Call tick regularly even when capture is silent."""

    def __init__(self, policy, emit, *, mode="monitor_only", adapter=None):
        self.policy, self.emit, self.adapter = policy, emit, adapter
        self.mode = "monitor_only"
        self.set_mode(mode)

    def set_mode(self, mode):
        if mode not in {"monitor_only", "automatic"}:
            raise ValueError("Unsupported mitigation mode")
        if mode == "automatic":
            self.policy.settings.require_automatic(self.policy.scope)
            if self.adapter is None or self.adapter.scope != self.policy.scope:
                raise ValueError("Automatic mode requires the matching firewall adapter")
        if mode != self.mode:
            if self.mode == "automatic":
                self.cleanup()
            self.policy.reset()
            self.mode = mode

    def _state(self, operation):
        self.emit({"record_type": "firewall_state", "operation": operation,
                   "mode": self.mode, **report(self.adapter, include_events=False)})

    def tick(self):
        if self.adapter is None:
            return
        before = {r.block_id: r.source_ip for r in self.adapter.pending_requests}
        self.adapter.expire_due()
        after = {r.block_id for r in self.adapter.pending_requests}
        for block_id in before.keys() - after:
            self.policy.reset(before[block_id])
        self._state("poll")

    def handle(self, event, record=None):
        if record is None:
            self.policy.reset()
            return
        self.tick()
        if self.mode == "automatic":
            age = self.adapter.clock().timestamp() - record.window_end
            if age < 0 or age > self.policy.settings.max_window_age_seconds:
                self.policy.reset()
                self.emit({"record_type": "policy_window", "window_start": record.window_start,
                           "mode": self.mode, "candidates": [], "reason": "stale_or_future_window"})
                return
        candidates = self.policy.evaluate(event, record)
        handled = set()
        for candidate in candidates:
            candidate["decision"] = "alert"
            if self.mode != "automatic" or not candidate["eligible"]:
                continue
            if candidate["source_ip"] in handled:
                candidate["decision"] = "source_already_considered"
                continue
            handled.add(candidate["source_ip"])
            reserved = {r.source_ip for r in self.adapter.pending_requests}
            if candidate["source_ip"] in reserved:
                candidate["decision"] = "already_reserved"
                continue
            if self.adapter.reserved_count >= self.adapter.max_blocks:
                candidate["decision"] = "cap_reached_alert"
                continue
            request = BlockRequest(str(uuid4()), candidate["source_ip"],
                                   f"Policy {candidate['protocol']} at {record.window_start}",
                                   self.policy.settings.block_seconds)
            # Flush the decision before applying; the adapter journals the mutation.
            self.emit({"record_type": "block_requested", "block_id": request.block_id,
                       "aggregate_detection_id": f"aggregate-{int(record.window_start)}",
                       "window_start": record.window_start, "mode": self.mode,
                       "policy_review_ref": self.policy.settings.review_ref, **candidate})
            result = self.adapter.apply(request)
            candidate.update(decision="block_requested", block_id=request.block_id,
                             success=result.success, rule_state=result.rule_state.value)
            self._state("apply")
        self.emit({"record_type": "policy_window", "window_start": record.window_start,
                   "mode": self.mode, "candidates": candidates})

    def cleanup(self):
        self.policy.reset()
        if self.adapter is None:
            return True
        self.adapter.cleanup()
        self._state("cleanup")
        if self.adapter.reserved_count:
            return False
        self.adapter.transport.cleanup_empty_table()
        return True
