from __future__ import annotations

from ovara_sdk.types import (
    ActionRequest,
    AgentIdentity,
    CapabilityLease,
    DecisionResponse,
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
        assert identity.verify_key is None


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
    def test_from_gateway_allow(self):
        resp = DecisionResponse.from_gateway({
            "decision_id": "dec-001",
            "decision": "allow",
            "reason_codes": ["allowed"],
            "trust_score": 0.95,
            "requires_approval": False,
        })
        assert resp.decision == "allow"
        assert resp.decision_id == "dec-001"
        assert resp.reason_codes == ["allowed"]
        assert resp.trust_score == 0.95

    def test_from_gateway_escalate(self):
        resp = DecisionResponse.from_gateway({
            "decision_id": "dec-002",
            "decision": "escalate",
            "reason_codes": ["policy_escalate"],
            "requires_approval": True,
            "approval_id": "apr-001",
        })
        assert resp.decision == "escalate"
        assert resp.requires_approval is True
        assert resp.approval_id == "apr-001"

    def test_from_gateway_ignores_unknown_keys(self):
        resp = DecisionResponse.from_gateway({
            "decision_id": "dec-003",
            "decision": "deny",
            "reason_codes": ["policy_deny"],
            "requires_approval": False,
            "some_future_field": {"nested": True},
        })
        assert resp.decision == "deny"
        assert not hasattr(resp, "some_future_field")


class TestGatewayStatus:
    def test_default_values(self):
        status = GatewayStatus()
        assert status.gateway_id == ""
        assert status.enrollment_state == "local"
        assert status.environment == ""
        assert status.is_healthy is False
        assert status.policy_version == ""
        assert status.uptime_seconds == 0

    def test_from_gateway_ignores_unknown_keys(self):
        status = GatewayStatus.from_gateway({
            "gateway_id": "gw-1",
            "enrollment_state": "local",
            "environment": "dev",
            "enrollment_healthy": True,
            "decision_cache_count": 42,
        })
        assert status.gateway_id == "gw-1"
        assert status.enrollment_healthy is True


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

    def test_from_gateway_ignores_unknown_keys(self):
        record = ReceiptRecord.from_gateway({
            "receipt_id": "rcpt-1",
            "decision": "allow",
            "policy_version": "v1",
            "future_field": 123,
        })
        assert record.receipt_id == "rcpt-1"
        assert record.policy_version == "v1"


class TestPortableReceipt:
    def test_required_fields(self):
        receipt = PortableReceipt(
            receipt_id="rcpt-001",
            session_id="sess-1",
            timestamp="2025-09-14T12:34:56.123456789Z",
            method="POST",
            url="https://api.example.com/v1",
            decision="allow",
            status=200,
            prev_hash="",
            signature="sig_v1:" + "00" * 64,
        )
        assert receipt.receipt_id == "rcpt-001"
        assert receipt.prev_hash == ""
