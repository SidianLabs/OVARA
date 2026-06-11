from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from ovara_sdk.verify import (
    PortableIdentity,
    PortableLease,
    PortableReceipt,
    compute_identity_digest,
    compute_receipt_digest,
    has_action,
    is_lease_expired,
    scope_covers,
    verify_agent_identity,
    verify_capability_lease,
    verify_receipt,
)
from ovara_sdk.types import PortableReceipt as TypesPortableReceipt


def make_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(private_key: ed25519.Ed25519PrivateKey, message: str) -> str:
    return private_key.sign(message.encode()).hex()


def public_key_hex(public_key: ed25519.Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


class TestComputeIdentityDigest:
    def test_deterministic_output(self):
        identity = PortableIdentity(
            id="agent-001",
            issuer="ovara",
            subject_id="sub-001",
            owner="team-a",
            lifecycle="active",
            public_key="00" * 32,
        )
        digest1 = compute_identity_digest(identity)
        digest2 = compute_identity_digest(identity)
        assert digest1 == digest2

    def test_different_inputs_produce_different_digests(self):
        identity1 = PortableIdentity(
            id="agent-001",
            issuer="ovara",
            subject_id="sub-001",
            owner="team-a",
            lifecycle="active",
            public_key="00" * 32,
        )
        identity2 = PortableIdentity(
            id="agent-002",
            issuer="ovara",
            subject_id="sub-001",
            owner="team-a",
            lifecycle="active",
            public_key="00" * 32,
        )
        assert compute_identity_digest(identity1) != compute_identity_digest(identity2)

    def test_hex_format(self):
        identity = PortableIdentity(
            id="agent-001",
            issuer="ovara",
            subject_id="sub-001",
            owner="team-a",
            lifecycle="active",
            public_key="00" * 32,
        )
        digest = compute_identity_digest(identity)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)


class TestVerifyAgentIdentity:
    def test_valid_signature_passes(self):
        private_key, public_key = make_keypair()
        payload = "agent-001|ovara|sub-001|team-a|active"
        signature = sign_message(private_key, payload)

        identity = PortableIdentity(
            id="agent-001",
            issuer="ovara",
            subject_id="sub-001",
            owner="team-a",
            lifecycle="active",
            public_key=public_key_hex(public_key),
            signature=signature,
        )

        assert verify_agent_identity(identity) is True

    def test_tampered_signature_fails(self):
        private_key, public_key = make_keypair()
        payload = "agent-001|ovara|sub-001|team-a|active"
        wrong_signature = sign_message(private_key, "wrong-message")

        identity = PortableIdentity(
            id="agent-001",
            issuer="ovara",
            subject_id="sub-001",
            owner="team-a",
            lifecycle="active",
            public_key=public_key_hex(public_key),
            signature=wrong_signature,
        )

        assert verify_agent_identity(identity) is False

    def test_no_signature_returns_false(self):
        identity = PortableIdentity(
            id="agent-001",
            issuer="ovara",
            subject_id="sub-001",
            owner="team-a",
            lifecycle="active",
            public_key="00" * 32,
            signature=None,
        )
        assert verify_agent_identity(identity) is False

    def test_no_public_key_returns_false(self):
        identity = PortableIdentity(
            id="agent-001",
            issuer="ovara",
            subject_id="sub-001",
            owner="team-a",
            lifecycle="active",
            public_key=None,
            signature="00" * 64,
        )
        assert verify_agent_identity(identity) is False

    def test_malformed_public_key_returns_false(self):
        identity = PortableIdentity(
            id="agent-001",
            issuer="ovara",
            subject_id="sub-001",
            owner="team-a",
            lifecycle="active",
            public_key="not-hex",
            signature="00" * 64,
        )
        assert verify_agent_identity(identity) is False

    def test_malformed_signature_returns_false(self):
        private_key, public_key = make_keypair()
        identity = PortableIdentity(
            id="agent-001",
            issuer="ovara",
            subject_id="sub-001",
            owner="team-a",
            lifecycle="active",
            public_key=public_key_hex(public_key),
            signature="not-hex",
        )
        assert verify_agent_identity(identity) is False


class TestVerifyCapabilityLease:
    def test_valid_signature_passes(self):
        private_key, public_key = make_keypair()
        pk_hex = public_key_hex(public_key)
        payload = f"lease-001|{pk_hex}|agent-001|['shell', 'exec']|*|9999999999|0|1234567890"
        signature = sign_message(private_key, payload)

        lease = PortableLease(
            lease_id="lease-001",
            issuer=pk_hex,
            subject="agent-001",
            allowed_actions=["shell", "exec"],
            resource_scope="*",
            expiry=9999999999,
            delegation_depth=0,
            issued_at=1234567890,
            signature=signature,
        )

        assert verify_capability_lease(lease) is True

    def test_tampered_payload_fails(self):
        private_key, public_key = make_keypair()
        pk_hex = public_key_hex(public_key)
        wrong_signature = sign_message(private_key, "tampered-payload")

        lease = PortableLease(
            lease_id="lease-001",
            issuer=pk_hex,
            subject="agent-001",
            allowed_actions=["shell", "exec"],
            resource_scope="*",
            expiry=9999999999,
            delegation_depth=0,
            issued_at=1234567890,
            signature=wrong_signature,
        )

        assert verify_capability_lease(lease) is False

    def test_no_signature_returns_false(self):
        lease = PortableLease(
            lease_id="lease-001",
            issuer="00" * 32,
            subject="agent-001",
            allowed_actions=["shell"],
            resource_scope="*",
            expiry=9999999999,
            delegation_depth=0,
            issued_at=1234567890,
            signature=None,
        )
        assert verify_capability_lease(lease) is False


class TestVerifyReceipt:
    def test_valid_signature_passes(self):
        private_key, public_key = make_keypair()
        payload = "|".join([
            "rcpt-001", "dec-001", "gw-local", "org-demo",
            "shell", "shell:ls", "allow", "agent-001",
            "0.950", "1718000000",
        ])
        signature = sign_message(private_key, payload)

        receipt = PortableReceipt(
            receipt_id="rcpt-001",
            decision_id="dec-001",
            issuing_gateway="gw-local",
            issuing_org="org-demo",
            action_type="shell",
            resource="shell:ls",
            decision="allow",
            agent_identity="agent-001",
            trust_score=0.950,
            timestamp=1718000000,
            signature=signature,
        )

        assert verify_receipt(receipt, public_key_hex(public_key)) is True

    def test_tampered_signature_fails(self):
        private_key, public_key = make_keypair()
        receipt = PortableReceipt(
            receipt_id="rcpt-001",
            decision_id="dec-001",
            issuing_gateway="gw-local",
            issuing_org="org-demo",
            action_type="shell",
            resource="shell:ls",
            decision="allow",
            agent_identity="agent-001",
            trust_score=0.950,
            timestamp=1718000000,
            signature="00" * 64,
        )
        assert verify_receipt(receipt, public_key_hex(public_key)) is False

    def test_no_signature_returns_false(self):
        receipt = PortableReceipt(
            receipt_id="rcpt-001",
            decision_id="dec-001",
            issuing_gateway="gw-local",
            issuing_org="org-demo",
            action_type="shell",
            resource="shell:ls",
            decision="allow",
            agent_identity="agent-001",
            trust_score=0.950,
            timestamp=1718000000,
            signature=None,
        )
        assert verify_receipt(receipt, "00" * 32) is False

    def test_no_public_key_returns_false(self):
        receipt = PortableReceipt(
            receipt_id="rcpt-001",
            decision_id="dec-001",
            issuing_gateway="gw-local",
            issuing_org="org-demo",
            action_type="shell",
            resource="shell:ls",
            decision="allow",
            agent_identity="agent-001",
            trust_score=0.950,
            timestamp=1718000000,
            signature="00" * 64,
        )
        assert verify_receipt(receipt, None) is False


class TestComputeReceiptDigest:
    def test_deterministic(self):
        receipt = PortableReceipt(
            receipt_id="rcpt-001",
            decision_id="dec-001",
            issuing_gateway="gw-local",
            issuing_org="org-demo",
            action_type="shell",
            resource="shell:ls",
            decision="allow",
            agent_identity="agent-001",
            trust_score=0.950,
            timestamp=1718000000,
            signature="00" * 64,
        )
        d1 = compute_receipt_digest(receipt)
        d2 = compute_receipt_digest(receipt)
        assert d1 == d2

    def test_hex_format(self):
        receipt = PortableReceipt(
            receipt_id="rcpt-001",
            decision_id="dec-001",
            issuing_gateway="gw-local",
            issuing_org="org-demo",
            action_type="shell",
            resource="shell:ls",
            decision="allow",
            agent_identity="agent-001",
            trust_score=0.950,
            timestamp=1718000000,
            signature="00" * 64,
        )
        digest = compute_receipt_digest(receipt)
        assert len(digest) == 64


class TestIsLeaseExpired:
    def test_expired_lease(self):
        lease = PortableLease(
            lease_id="lease-001",
            issuer="00" * 32,
            subject="agent-001",
            allowed_actions=["shell"],
            resource_scope="*",
            expiry=int(time.time()) - 3600,
            delegation_depth=0,
            issued_at=0,
            signature="00" * 64,
        )
        assert is_lease_expired(lease) is True

    def test_valid_lease(self):
        lease = PortableLease(
            lease_id="lease-001",
            issuer="00" * 32,
            subject="agent-001",
            allowed_actions=["shell"],
            resource_scope="*",
            expiry=int(time.time()) + 3600,
            delegation_depth=0,
            issued_at=0,
            signature="00" * 64,
        )
        assert is_lease_expired(lease) is False


class TestHasAction:
    def test_exact_match(self):
        lease = PortableLease(
            lease_id="lease-001",
            issuer="00" * 32,
            subject="agent-001",
            allowed_actions=["shell", "exec"],
            resource_scope="*",
            expiry=9999999999,
            delegation_depth=0,
            issued_at=0,
            signature="00" * 64,
        )
        assert has_action(lease, "shell") is True
        assert has_action(lease, "exec") is True

    def test_wildcard_allows_any(self):
        lease = PortableLease(
            lease_id="lease-001",
            issuer="00" * 32,
            subject="agent-001",
            allowed_actions=["*"],
            resource_scope="*",
            expiry=9999999999,
            delegation_depth=0,
            issued_at=0,
            signature="00" * 64,
        )
        assert has_action(lease, "shell") is True
        assert has_action(lease, "git.push") is True

    def test_missing_action_returns_false(self):
        lease = PortableLease(
            lease_id="lease-001",
            issuer="00" * 32,
            subject="agent-001",
            allowed_actions=["shell"],
            resource_scope="*",
            expiry=9999999999,
            delegation_depth=0,
            issued_at=0,
            signature="00" * 64,
        )
        assert has_action(lease, "git.push") is False


class TestScopeCovers:
    def test_wildcard_scope_covers_all(self):
        lease = PortableLease(
            lease_id="lease-001",
            issuer="00" * 32,
            subject="agent-001",
            allowed_actions=["shell"],
            resource_scope="*",
            expiry=9999999999,
            delegation_depth=0,
            issued_at=0,
            signature="00" * 64,
        )
        assert scope_covers(lease, "shell:ls") is True
        assert scope_covers(lease, "shell:rm -rf /") is True

    def test_exact_match(self):
        lease = PortableLease(
            lease_id="lease-001",
            issuer="00" * 32,
            subject="agent-001",
            allowed_actions=["shell"],
            resource_scope="shell:ls",
            expiry=9999999999,
            delegation_depth=0,
            issued_at=0,
            signature="00" * 64,
        )
        assert scope_covers(lease, "shell:ls") is True
        assert scope_covers(lease, "shell:cat file.txt") is False

    def test_empty_scope_covers_all(self):
        lease = PortableLease(
            lease_id="lease-001",
            issuer="00" * 32,
            subject="agent-001",
            allowed_actions=["shell"],
            resource_scope="",
            expiry=9999999999,
            delegation_depth=0,
            issued_at=0,
            signature="00" * 64,
        )
        assert scope_covers(lease, "shell:anything") is True