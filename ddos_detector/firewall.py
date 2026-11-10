"""Offline-testable block lifecycle with an injected firewall transport.

The transport must check the exact scoped rule and report UNKNOWN on ambiguous
outcomes. A real UFW-compatible transport and restart recovery need lab review.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv4Network
from threading import RLock
from typing import Protocol

from .firewall_contract import BlockRequest, FirewallResult, RuleState


@dataclass(frozen=True)
class FirewallScope:
    interface: str
    protected_ip: str
    allowlist: tuple[str, ...]
    verified: bool = False

    def __post_init__(self):
        if not self.interface or not self.interface.strip():
            raise ValueError("A lab interface is required")
        IPv4Address(self.protected_ip)
        # Copy mutable caller input so checks cannot change during an action.
        object.__setattr__(self, "allowlist", tuple(self.allowlist))
        for entry in self.allowlist:
            IPv4Network(entry)
        if not isinstance(self.verified, bool):
            raise ValueError("Scope verification must be a boolean")


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

    One instance must own the transport. Reservations and audit results are
    currently in memory; a live implementation needs restart reconciliation.
    """

    def __init__(self, transport: FirewallTransport, scope: FirewallScope,
                 max_blocks=20, clock=None):
        if isinstance(max_blocks, bool) or not isinstance(max_blocks, int) or max_blocks < 1:
            raise ValueError("Block capacity must be a positive integer")
        self.transport = transport
        self.scope = scope
        self.max_blocks = max_blocks
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._requests = {}
        self._confirmed = {}
        self._removed = {}
        self._audit = []
        self._lock = RLock()

    @property
    def confirmed_blocks(self):
        with self._lock:
            return tuple(self._confirmed.values())

    @property
    def reserved_count(self):
        with self._lock:
            return len(self._requests)

    @property
    def audit_events(self):
        with self._lock:
            return tuple(self._audit)

    def _check_request(self, request):
        if not self.scope.verified:
            raise ValueError("Lab scope and allowlist must be verified before use")
        address = IPv4Address(request.source_ip)
        protected = IPv4Address(self.scope.protected_ip)
        if (address == protected or address == IPv4Address("10.10.10.20")
                or address.is_loopback or address.is_multicast
                or address.is_unspecified or address == IPv4Address("255.255.255.255")
                or any(address in IPv4Network(entry) for entry in self.scope.allowlist)):
            raise ValueError("Source is protected or allowlisted")
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
            self._confirmed.pop(request.block_id, None)
        self._audit.append(result)
        if success and operation in {"remove", "expire"}:
            self._removed[request.block_id] = (request, result)
        return result

    def apply(self, request: BlockRequest):
        with self._lock:
            self._check_request(request)
            if request.block_id in self._removed:
                raise ValueError("A removed block action requires a new block ID")
            if request.block_id in self._requests:
                # Retrying a reserved request only reconciles it. An uncertain
                # installation must never cause a second insertion or renewal.
                return self.verify(request)
            if len(self._requests) >= self.max_blocks:
                raise ValueError("Block capacity reached")
            self._requests[request.block_id] = request
            state, error = self._observe(request)
            if state == RuleState.ABSENT:
                try:
                    self.transport.apply(request, self.scope)
                except Exception as exc:
                    error = f"Apply failed: {type(exc).__name__}: {exc}"
                state, verification_error = self._observe(request)
                error = verification_error or error
            return self._record(request, "apply", state, error)

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
            return result
        if self._requests.get(request.block_id) != request:
            raise ValueError("Removal requires an existing reserved request")
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

        The caller must invoke this regularly. Failed/unknown removals remain
        due for retry on the next poll, using the original expiry time.
        """
        with self._lock:
            now = self.clock()
            due = [block.request for block in self._confirmed.values()
                   if block.expires_at <= now]
            return tuple(self._remove(request, "expire") for request in due)
