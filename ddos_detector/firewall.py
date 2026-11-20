"""Offline-testable block lifecycle with an injected firewall transport.

The transport must check the exact scoped rule and report UNKNOWN on ambiguous
outcomes. A real UFW-compatible transport and restart recovery need lab review.
"""
from dataclasses import asdict, dataclass, replace
from collections import deque
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv4Network
from threading import RLock
from typing import Protocol
import re

from .firewall_contract import BlockRequest, FirewallResult, RuleState


@dataclass(frozen=True)
class FirewallScope:
    interface: str
    protected_ip: str
    allowlist: tuple[str, ...]
    verified: bool = False

    def __post_init__(self):
        if not isinstance(self.interface, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", self.interface):
            raise ValueError("A lab interface is required")
        IPv4Address(self.protected_ip)
        # Copy mutable caller input so checks cannot change during an action.
        object.__setattr__(self, "allowlist", tuple(self.allowlist))
        for entry in self.allowlist:
            IPv4Network(entry)
        if not isinstance(self.verified, bool):
            raise ValueError("Scope verification must be a boolean")

    def check_source(self, source_ip):
        if not self.verified:
            raise ValueError("Lab scope and allowlist must be verified before use")
        if self.is_protected(source_ip):
            raise ValueError("Source is protected or allowlisted")

    def is_protected(self, source_ip):
        """Pure address check; live mutations additionally require verified scope."""
        address = IPv4Address(source_ip)
        return (address == IPv4Address(self.protected_ip) or address == IPv4Address("10.10.10.20")
                or address.is_loopback or address.is_multicast or address.is_unspecified
                or address == IPv4Address("255.255.255.255")
                or any(address in IPv4Network(entry) for entry in self.allowlist))


class FirewallTransport(Protocol):
    def apply(self, request: BlockRequest, scope: FirewallScope) -> None:
        """Install a rule matching source, lab interface and protected destination."""

    def verify(self, request: BlockRequest, scope: FirewallScope) -> RuleState:
        """Independently observe this action's exact scoped rule."""

    def remove(self, request: BlockRequest, scope: FirewallScope) -> None:
        """Idempotently remove only this action's exact scoped rule."""


@dataclass(frozen=True)
class ConfirmedBlock:
    request: BlockRequest
    blocked_at: datetime
    expires_at: datetime


class FirewallAdapter:
    """Serialize local requests and reserve capacity until verified absent.

    Live callers supply a FirewallState journal and reconcile before accepting
    requests. The journal locks out another owner and preserves original times.
    """

    def __init__(self, transport: FirewallTransport, scope: FirewallScope,
                 max_blocks=20, clock=None, state_store=None, audit_limit=None):
        if isinstance(max_blocks, bool) or not isinstance(max_blocks, int) or max_blocks < 1:
            raise ValueError("Block capacity must be a positive integer")
        self.transport = transport
        self.scope = scope
        self.max_blocks = max_blocks
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._requests = {}
        self._confirmed = {}
        self._removed = {}
        self._removing = set()
        if audit_limit is not None and (type(audit_limit) is not int or audit_limit < 1):
            raise ValueError("Audit memory limit must be a positive integer")
        self._audit = deque(maxlen=audit_limit)
        self._latest_states = {}
        self.had_failures = False
        self._lock = RLock()
        self._state_store = state_store
        self._faulted = False
        if state_store is not None:
            snapshot = state_store.load()
            if snapshot is not None:
                self._restore(snapshot)

    def _snapshot(self):
        return {
            "version": 1, "scope": {**asdict(self.scope), "allowlist": list(self.scope.allowlist)},
            "max_blocks": self.max_blocks,
            "requests": [asdict(request) for request in self._requests.values()],
            "removing": sorted(self._removing),
            "confirmed": [{"request": asdict(block.request), "blocked_at": block.blocked_at.isoformat(),
                           "expires_at": block.expires_at.isoformat()} for block in self._confirmed.values()],
            "removed": [{"request": asdict(request), "result": self._event(result)}
                        for request, result in self._removed.values()],
        }

    @staticmethod
    def _event(result):
        return {**asdict(result), "rule_state": result.rule_state.value,
                "observed_at": result.observed_at.isoformat()}

    def _restore(self, snapshot):
        expected = self._snapshot()
        if any(snapshot[key] != expected[key] for key in ("version", "scope", "max_blocks")):
            raise ValueError("Saved firewall scope/capacity differs; reconcile with the original configuration")
        for row in snapshot["requests"]:
            request = BlockRequest(**row)
            self.scope.check_source(request.source_ip)
            if request.block_id in self._requests or any(r.source_ip == request.source_ip for r in self._requests.values()):
                raise ValueError("Duplicate saved block reservation")
            self._requests[request.block_id] = request
        for row in snapshot["confirmed"]:
            request = BlockRequest(**row["request"])
            start, end = datetime.fromisoformat(row["blocked_at"]), datetime.fromisoformat(row["expires_at"])
            if (self._requests.get(request.block_id) != request or start.utcoffset() is None
                    or end.utcoffset() is None or end != start + timedelta(seconds=request.duration_seconds)):
                raise ValueError("Invalid saved block deadline or reservation")
            self._confirmed[request.block_id] = ConfirmedBlock(request, start, end)
        for row in snapshot["removed"]:
            request = BlockRequest(**row["request"])
            result = row["result"]
            result = FirewallResult(**{**result, "rule_state": RuleState(result["rule_state"]),
                                      "observed_at": datetime.fromisoformat(result["observed_at"])})
            if result.block_id != request.block_id or result.rule_state != RuleState.ABSENT or request.block_id in self._requests:
                raise ValueError("Invalid saved retired action")
            self._removed[request.block_id] = (request, result)
        self._removing = set(snapshot["removing"])
        if not self._removing.issubset(self._requests):
            raise ValueError("Removal intent has no saved reservation")

    def _save(self, result=None):
        if self._state_store is not None:
            try:
                self._state_store.save(self._snapshot(), None if result is None else self._event(result))
            except Exception:
                self._faulted = True
                raise

    @property
    def confirmed_blocks(self):
        with self._lock:
            return tuple(self._confirmed.values())

    @property
    def reserved_count(self):
        with self._lock:
            return len(self._requests)

    @property
    def pending_requests(self):
        with self._lock:
            return tuple(self._requests.values())

    @property
    def audit_events(self):
        with self._lock:
            return tuple(self._audit)

    @property
    def audit_records(self):
        with self._lock:
            return tuple(self._event(result) for result in self._audit)

    @property
    def latest_rule_states(self):
        with self._lock:
            return self._latest_states.copy()

    def _check_request(self, request):
        if self._faulted:
            raise RuntimeError("Firewall journal failed; restart and reconcile before further actions")
        self.scope.check_source(request.source_ip)
        for pending in self._requests.values():
            if pending.block_id == request.block_id and pending != request:
                raise ValueError("Block ID is already associated with a different request")
            if pending.source_ip == request.source_ip and pending != request:
                raise ValueError("Source already has a reserved block action")

    def _observe(self, request):
        try:
            state = self.transport.verify(request, self.scope)
            if not isinstance(state, RuleState):
                raise ValueError("Transport returned an invalid rule state")
            return state, None if state != RuleState.UNKNOWN else "Rule state is unknown"
        except Exception as exc:
            return RuleState.UNKNOWN, f"Verification failed: {type(exc).__name__}: {exc}"

    def _record(self, request, operation, state, error=None):
        observed_at = self.clock()
        expected = RuleState.ABSENT if operation in {"remove", "expire"} else RuleState.INSTALLED
        success = state != RuleState.UNKNOWN and (operation == "verify" or state == expected)
        failure = "Rule remains installed" if operation in {"remove", "expire"} else "Rule was not installed"
        result = FirewallResult(request.block_id, operation, success, state, observed_at,
                                None if success else (error or failure))
        if state == RuleState.INSTALLED:
            if request.block_id not in self._confirmed:
                self._confirmed[request.block_id] = ConfirmedBlock(
                    request, observed_at, observed_at + timedelta(seconds=request.duration_seconds))
        elif state == RuleState.ABSENT:
            self._requests.pop(request.block_id, None)
            previously_confirmed = self._confirmed.pop(request.block_id, None)
            if operation in {"remove", "expire"} or previously_confirmed is not None or request.block_id in self._removing:
                self._removed[request.block_id] = (request, result)
            self._removing.discard(request.block_id)
        self._audit.append(result)
        self._latest_states[request.block_id] = state
        self.had_failures |= not result.success
        self._save(result)
        return result

    def apply(self, request: BlockRequest):
        with self._lock:
            self._check_request(request)
            if request.block_id in self._removed:
                raise ValueError("A removed block action requires a new block ID")
            if request.block_id in self._requests:
                # Retrying a reserved request only reconciles it. An uncertain
                # installation must never cause a second insertion or renewal.
                state, error = self._observe(request)
                return self._record(request, "apply", state, error)
            if len(self._requests) >= self.max_blocks:
                raise ValueError("Block capacity reached")
            # Reject a duration beyond the clock's range before touching the transport.
            try:
                self.clock() + timedelta(seconds=request.duration_seconds)
            except OverflowError as exc:
                raise ValueError("Block deadline exceeds the clock range") from exc
            self._requests[request.block_id] = request
            self._save()  # Write-ahead reservation before any firewall command.
            state, error = self._observe(request)
            if state == RuleState.ABSENT:
                try:
                    self.transport.apply(request, self.scope)
                except Exception as exc:
                    error = f"Apply failed: {type(exc).__name__}: {exc}"
                state, verification_error = self._observe(request)
                error = verification_error or error
            return self._record(request, "apply", state, error)

    def validate_batch(self, requests):
        """Validate a complete explicit batch before its first mutation."""
        with self._lock:
            by_id = self._requests.copy()
            by_source = {request.source_ip: request for request in self._requests.values()}
            for request in requests:
                self._check_request(request)
                if request.block_id in self._removed:
                    raise ValueError("Removed action requires a new block ID")
                if request.block_id in by_id and by_id[request.block_id] != request:
                    raise ValueError("Conflicting block IDs in request batch")
                if request.source_ip in by_source and by_source[request.source_ip] != request:
                    raise ValueError("Conflicting source actions in request batch")
                by_id[request.block_id] = request
                by_source[request.source_ip] = request
            if len(by_id) > self.max_blocks:
                raise ValueError("Request batch exceeds block capacity")

    def verify(self, request: BlockRequest):
        with self._lock:
            self._check_request(request)
            if self._requests.get(request.block_id) != request:
                raise ValueError("Verification requires an existing reserved request")
            state, error = self._observe(request)
            return self._record(request, "verify", state, error)

    def remove(self, request: BlockRequest):
        """Remove a reserved action, retaining capacity until verified absent."""
        with self._lock:
            return self._remove(request, "remove")

    def _remove(self, request, operation):
        self._check_request(request)
        if request.block_id in self._removed:
            original, result = self._removed[request.block_id]
            if original != request:
                raise ValueError("Block ID is already associated with a different request")
            if result.operation in {"apply", "verify"}:
                return replace(result, operation=operation, success=True, error=None)
            return result
        if self._requests.get(request.block_id) != request:
            raise ValueError("Removal requires an existing reserved request")
        self._removing.add(request.block_id)
        self._save()  # A crash must preserve the intent to finish removal.
        state, error = self._observe(request)
        if state != RuleState.ABSENT:
            try:
                self.transport.remove(request, self.scope)
            except Exception as exc:
                error = f"Removal failed: {type(exc).__name__}: {exc}"
            state, verification_error = self._observe(request)
            error = verification_error or error
        return self._record(request, operation, state, error)

    def expire_due(self):
        """Check deadlines when polled; confirm removal before releasing slots.

        Recheck active rules before their deadline so externally removed rules
        release their slots. Unknown observations keep the original deadline.
        Failed removals remain due for retry on the next poll.
        """
        with self._lock:
            now = self.clock()
            expired = []
            for block_id, request in list(self._requests.items()):
                block = self._confirmed.get(block_id)
                if block_id in self._removing or (block is not None and block.expires_at <= now):
                    expired.append(self._remove(request, "expire"))
                else:
                    self.verify(request)
            return tuple(expired)

    def reconcile(self):
        """Observe all saved actions before accepting new requests after restart."""
        with self._lock:
            return tuple(self.verify(request) for request in list(self._requests.values()))

    def cleanup(self):
        """Remove only journal-owned actions; uncertain outcomes retain slots."""
        with self._lock:
            return tuple(self._remove(request, "remove") for request in list(self._requests.values()))
