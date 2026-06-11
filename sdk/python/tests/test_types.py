from __future__ import annotations

from ovara_sdk.types import (
    ActionRequest,
    AgentIdentity,
    CapabilityLease,
    DecisionResponse,
    ExecutionRequest,
    ExecutionResponse,
    GatewayStatus,
    PortableReceipt,
    ReceiptRecord,
)


class TestAgentIdentity:
    def test_default_lifecycle(self):
        identity = AgentIdentity(id="agent-001", issuer="ovara", subject_id="sub-001", owner="team-a")
        assert identity.lifecycle == "active"

    def test_custom_lifecycle(self):
        identity = AgentIdentity(id="agent-001", issuer="ovara", subject_id="sub-001", owner="team-a", lifecycle="revoked")
        assert identity.lifecycle == "revoked"

    def test_optional_fields_default_none(self):
        identity = AgentIdentity(id="agent-001", issuer="ovara", subject_id="sub-001", owner="team-a")
        assert identity.public_key is None


class TestCapabilityLease:
    def test_default_delegation_depth(self):
        lease = CapabilityLease(lease_id="lease-001", issuer="ovara", subject="agent-001", allowed_actions=["shell"], resource_scope="*", expiry=9999999999)
        assert lease.delegation_depth == 0

    def test_default_issued_at(self):
        lease = CapabilityLease(lease_id="lease-001", issuer="ovara", subject="agent-001", allowed_actions=["shell"], resource_scope="*", expiry=9999999999)
        assert lease.issued_at == 0


class TestActionRequest:
    def test_default_environment(self):
        request = ActionRequest(action_type="shell", resource="shell:ls")
        assert request.environment == "local"

    def test_custom_environment(self):
        request = ActionRequest(action_type="exec", resource="exec:ls", environment="dev")
        assert request.environment == "dev"

    def test_all_optional_fields_none(self):
        request = ActionRequest(action_type="shell", resource="shell:ls")
        assert request.agent_identity is None
        assert request.capability_lease is None
        assert request.metadata is None
        assert request.trace_id is None


class TestDecisionResponse:
    def test_decision_allow(self):
        resp = DecisionResponse(request_id="req-001", decision="allow")
        assert resp.decision == "allow"
        assert resp.reason is None
        assert resp.trust_score is None

    def test_decision_deny(self):
        resp = DecisionResponse(request_id="req-001", decision="deny", reason="policy deny")
        assert resp.decision == "deny"
        assert resp.reason == "policy deny"

    def test_decision_pending(self):
        resp = DecisionResponse(request_id="req-001", decision="pending", approval_id="apr-001")
        assert resp.decision == "pending"
        assert resp.approval_id == "apr-001"


class TestExecutionRequest:
    def test_all_optional(self):
        req = ExecutionRequest(command="ls")
        assert req.args is None
        assert req.env is None
        assert req.working_dir is None
        assert req.timeout_ms is None


class TestExecutionResponse:
    def test_default_values(self):
        resp = ExecutionResponse(execution_id="exe-001", status="succeeded")
        assert resp.exit_code == 0
        assert resp.stdout == ""
        assert resp.stderr == ""
        assert resp.duration_ms == 0
        assert resp.receipt_id is None


class TestGatewayStatus:
    def test_default_values(self):
        status = GatewayStatus()
        assert status.gateway_id == ""
        assert status.enrollment_state == "local"
        assert status.environment == ""
        assert status.is_healthy is False
        assert status.policy_version == ""
        assert status.uptime_seconds == 0


class TestReceiptRecord:
    def test_default_values(self):
        record = ReceiptRecord()
        assert record.receipt_id == ""
        assert record.decision_id == ""
        assert record.action_type == ""
        assert record.resource == ""
        assert record.decision == ""
        assert record.agent_id is None
        assert record.trust_score is None
        assert record.signature == ""
        assert record.issued_at == ""


class TestPortableReceipt:
    def test_required_fields(self):
        receipt = PortableReceipt(
            receipt_id="rcpt-001",
            decision_id="dec-001",
            issuing_gateway="gw-local",
            issuing_org="org-demo",
            action_type="shell",
            resource="shell:ls",
            decision="allow",
            agent_identity="agent-001",
            trust_score=0.95,
            timestamp=1718000000,
            signature="00" * 64,
        )
        assert receipt.receipt_id == "rcpt-001"
        assert receipt.lease_digest is None