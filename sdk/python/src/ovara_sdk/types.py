from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Optional


@dataclass
class AgentIdentity:
    id: str
    issuer: str
    subject_id: str
    owner: str
    lifecycle: Literal["active", "suspended", "revoked"] = "active"
    public_key: Optional[str] = None


@dataclass
class CapabilityLease:
    lease_id: str
    issuer: str
    subject: str
    allowed_actions: list[str]
    resource_scope: str
    expiry: int
    delegation_depth: int = 0
    issued_at: int = 0
    revocation_handle: Optional[str] = None
    signature: Optional[str] = None


@dataclass
class ActionRequest:
    action_type: str
    resource: str
    environment: str = "local"
    agent_identity: Optional[AgentIdentity] = None
    capability_lease: Optional[CapabilityLease] = None
    metadata: Optional[dict] = None
    trace_id: Optional[str] = None


@dataclass
class DecisionResponse:
    request_id: str
    decision: Literal["allow", "deny", "pending"]
    reason: Optional[str] = None
    trust_score: Optional[float] = None
    receipt_id: Optional[str] = None
    approval_id: Optional[str] = None
    continuation_id: Optional[str] = None
    evaluated_at: str = ""


@dataclass
class ExecutionRequest:
    command: str
    args: Optional[list[str]] = None
    env: Optional[dict[str, str]] = None
    working_dir: Optional[str] = None
    timeout_ms: Optional[int] = None


@dataclass
class ExecutionResponse:
    execution_id: str
    status: Literal["succeeded", "failed", "timed_out"]
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    receipt_id: Optional[str] = None


@dataclass
class GatewayStatus:
    gateway_id: str = ""
    enrollment_state: str = "local"
    environment: str = ""
    is_healthy: bool = False
    policy_version: str = ""
    uptime_seconds: int = 0


@dataclass
class ReceiptRecord:
    receipt_id: str = ""
    decision_id: str = ""
    action_type: str = ""
    resource: str = ""
    decision: str = ""
    agent_id: Optional[str] = None
    trust_score: Optional[float] = None
    signature: str = ""
    issued_at: str = ""


@dataclass
class PortableReceipt:
    receipt_id: str
    decision_id: str
    issuing_gateway: str
    issuing_org: str
    action_type: str
    resource: str
    decision: str
    agent_identity: str
    trust_score: float
    timestamp: int
    signature: str
    lease_digest: Optional[str] = None
