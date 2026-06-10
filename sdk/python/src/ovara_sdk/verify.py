from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


@dataclass
class PortableIdentity:
    id: str
    issuer: str
    subject_id: str
    owner: str
    lifecycle: str
    public_key: str
    signature: Optional[str] = None


@dataclass
class PortableLease:
    lease_id: str
    issuer: str
    subject: str
    allowed_actions: list[str]
    resource_scope: str
    expiry: int
    delegation_depth: int
    issued_at: int
    signature: str


def compute_identity_digest(identity: PortableIdentity) -> str:
    payload = f"{identity.id}|{identity.issuer}|{identity.subject_id}|{identity.owner}|{identity.lifecycle}"
    return hashlib.sha256(payload.encode()).hexdigest()


def verify_agent_identity(identity: PortableIdentity) -> bool:
    if not identity.signature or not identity.public_key:
        return False

    payload = f"{identity.id}|{identity.issuer}|{identity.subject_id}|{identity.owner}|{identity.lifecycle}"
    return _ed25519_verify(identity.public_key, payload, identity.signature)


def verify_capability_lease(lease: PortableLease) -> bool:
    if not lease.signature:
        return False

    payload = "|".join([
        lease.lease_id, lease.issuer, lease.subject,
        str(lease.allowed_actions), lease.resource_scope,
        str(lease.expiry), str(lease.delegation_depth), str(lease.issued_at),
    ])
    return _ed25519_verify(lease.issuer, payload, lease.signature)


def verify_receipt(receipt: PortableReceipt, public_key_hex: str) -> bool:
    if not receipt.signature or not public_key_hex:
        return False

    payload = "|".join([
        receipt.receipt_id, receipt.decision_id, receipt.issuing_gateway,
        receipt.issuing_org, receipt.action_type, receipt.resource,
        receipt.decision, receipt.agent_identity,
        f"{receipt.trust_score:.3f}", str(receipt.timestamp),
    ])
    return _ed25519_verify(public_key_hex, payload, receipt.signature)


def compute_receipt_digest(receipt: PortableReceipt) -> str:
    payload = "|".join([
        receipt.receipt_id, receipt.decision_id, receipt.issuing_gateway,
        receipt.issuing_org, receipt.action_type, receipt.resource,
        receipt.decision, receipt.agent_identity,
        f"{receipt.trust_score:.3f}", str(receipt.timestamp),
    ])
    return hashlib.sha256(payload.encode()).hexdigest()


def is_lease_expired(lease: PortableLease) -> bool:
    return datetime.now(timezone.utc).timestamp() > lease.expiry


def has_action(lease: PortableLease, action: str) -> bool:
    return action in lease.allowed_actions or "*" in lease.allowed_actions


def scope_covers(lease: PortableLease, resource: str) -> bool:
    return not lease.resource_scope or lease.resource_scope == "*" or lease.resource_scope == resource


def _ed25519_verify(public_key_hex: str, message: str, signature_hex: str) -> bool:
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, message.encode())
        return True
    except (ValueError, InvalidSignature):
        return False


# Re-export for convenience
from .types import PortableReceipt
