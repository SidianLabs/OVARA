from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional


@dataclass
class AgentIdentity:
    id: str
    issuer: str
    subject_id: str
    owner: str
    lifecycle: Literal["active", "suspended", "revoked"] = "active"
    verify_key: Optional[str] = None


@dataclass
class CapabilityLease:
    lease_id: str
    issuer: str
    subject: str
    allowed_actions: list[str]
    resource_scope: str
    """Unix seconds; serialized to RFC3339 for the gateway."""
    expiry: int
    delegation_depth: int = 0
    """Unix seconds; serialized to RFC3339 for the gateway."""
    issued_at: int = 0
    revocation_handle: Optional[str] = None
    """ed25519 signature over the canonical lease payload. On the
    gateway wire this is base64 (Go []byte marshals to base64 in JSON)."""
    signature: Optional[str] = None


@dataclass
class DelegationAuthority:
    """Mirrors models.Authority in the gateway (snake_case on the wire:
    subject_id, delegated_at)."""

    issuer: str
    subject_id: str
    delegated_at: Optional[str] = None  # RFC3339


@dataclass
class DelegationChain:
    """Mirrors models.DelegationChain in the gateway."""

    authorities: list[DelegationAuthority] = field(default_factory=list)
    chain_hash: Optional[str] = None
    depth: int = 0


@dataclass
class ActionRequest:
    action_type: str
    resource: str
    environment: str = "local"
    agent_identity: Optional[AgentIdentity] = None
    capability_lease: Optional[CapabilityLease] = None
    delegation_chain: Optional[DelegationChain] = None
    metadata: Optional[dict] = None
    nonce: Optional[str] = None
    issued_at: Optional[str] = None


@dataclass
class ReceiptStub:
    receipt_id: str = ""
    action_digest: str = ""
    action_type: str = ""
    resource: str = ""
    policy_version: str = ""
    trust_context_score: Optional[float] = None
    issued_at: str = ""


@dataclass
class DecisionResponse:
    """Mirrors models.DecisionResponse in the gateway (snake_case JSON)."""

    decision_id: str = ""
    decision: Literal["allow", "deny", "escalate"] = "deny"
    reason_codes: list[str] = field(default_factory=list)
    trust_score: Optional[float] = None
    trust_level: Optional[str] = None
    requires_approval: bool = False
    approval_id: Optional[str] = None
    receipt_stub: Optional[dict] = None
    trust_context: Optional[dict] = None
    evaluation_summary: Optional[str] = None

    @classmethod
    def from_gateway(cls, data: dict) -> "DecisionResponse":
        """Build from a gateway JSON object, ignoring unknown keys."""
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class GatewayStatus:
    gateway_id: str = ""
    gateway_name: str = ""
    enrollment_state: str = "local"
    environment: str = ""
    enrollment_healthy: bool = False
    is_healthy: bool = False
    policy_version: str = ""
    uptime_seconds: int = 0

    @classmethod
    def from_gateway(cls, data: dict) -> "GatewayStatus":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class ReceiptRecord:
    """Mirrors models.Receipt in the gateway (snake_case JSON)."""

    receipt_id: str = ""
    decision_id: str = ""
    action_digest: str = ""
    action_type: str = ""
    resource: str = ""
    agent_id: Optional[str] = None
    capability_lease_id: Optional[str] = None
    decision: str = ""
    policy_version: str = ""
    trust_score: Optional[float] = None
    trust_level: Optional[str] = None
    approval_id: Optional[str] = None
    approval_decision: Optional[str] = None
    issued_at: str = ""
    signature: str = ""

    @classmethod
    def from_gateway(cls, data: dict) -> "ReceiptRecord":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class PortableReceipt:
    """Receipt produced by the Ovara egress proxy (proxy/internal/receipts).

    Proxy receipts are ed25519-signed ("sig_v1:<hex>") and verifiable
    offline with the proxy's public key. Gateway decision receipts are
    HMAC-signed and cannot be verified client-side — fetch them via
    GET /v1/receipts/{id} instead.
    """

    receipt_id: str
    session_id: str
    timestamp: str  # RFC3339 / RFC3339Nano
    method: str
    url: str
    decision: str
    status: int
    # Links an escalated-then-approved receipt to the approval that
    # authorized it. Present only on such receipts; it is part of the
    # signed canonical payload (appended as "|approval_id").
    approval_id: Optional[str] = None
    prev_hash: str = ""
    signature: str = ""  # "sig_v1:<hex ed25519>"
