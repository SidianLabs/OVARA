from __future__ import annotations

import datetime
import json
import uuid
from typing import Any, Optional

import httpx

from .types import (
    ActionRequest,
    AgentIdentity,
    CapabilityLease,
    DecisionResponse,
    DelegationChain,
    GatewayStatus,
    ReceiptRecord,
)


def _unix_to_rfc3339(unix: int) -> str:
    return (
        datetime.datetime.fromtimestamp(unix, tz=datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _serialize_agent_identity(identity: AgentIdentity) -> dict:
    """Map to the gateway's agent_identity JSON tags."""
    out: dict = {
        "issuer": identity.issuer,
        "subject_id": identity.subject_id,
    }
    if identity.owner:
        out["owner"] = identity.owner
    if identity.lifecycle:
        out["lifecycle"] = identity.lifecycle
    if identity.verify_key is not None:
        out["verify_key"] = identity.verify_key
    return out


def _serialize_capability_lease(lease: CapabilityLease) -> dict:
    """Map to the gateway's capability_lease JSON tags; expiry/issued_at
    are unix seconds here but RFC3339 on the wire."""
    out: dict = {
        "lease_id": lease.lease_id,
        "issuer": lease.issuer,
        "subject": lease.subject,
        "allowed_actions": lease.allowed_actions,
        "resource_scope": lease.resource_scope,
        "expiry": _unix_to_rfc3339(lease.expiry),
        "delegation_depth": lease.delegation_depth,
    }
    if lease.issued_at:
        out["issued_at"] = _unix_to_rfc3339(lease.issued_at)
    if lease.revocation_handle is not None:
        out["revocation_handle"] = lease.revocation_handle
    if lease.signature is not None:
        out["signature"] = lease.signature
    return out


def _serialize_delegation_chain(chain: DelegationChain) -> dict:
    """Map to the gateway's delegation_chain JSON tags."""
    authorities = []
    for a in chain.authorities:
        entry: dict = {"issuer": a.issuer, "subject_id": a.subject_id}
        if a.delegated_at is not None:
            entry["delegated_at"] = a.delegated_at
        authorities.append(entry)
    return {
        "authorities": authorities,
        "chain_hash": chain.chain_hash,
        "depth": chain.depth,
    }


def _serialize_action_request(request: ActionRequest) -> dict:
    return {
        "action_type": request.action_type,
        "resource": request.resource,
        "environment": request.environment,
        "agent_identity": (
            _serialize_agent_identity(request.agent_identity)
            if request.agent_identity
            else None
        ),
        "capability_lease": (
            _serialize_capability_lease(request.capability_lease)
            if request.capability_lease
            else None
        ),
        "delegation_chain": (
            _serialize_delegation_chain(request.delegation_chain)
            if request.delegation_chain
            else None
        ),
        "metadata": request.metadata,
        "nonce": request.nonce or uuid.uuid4().hex,
        "issued_at": request.issued_at
        or datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


class OvaraClient:
    def __init__(
        self,
        base_url: str,
        *,
        api_key: Optional[str] = None,
        timeout_ms: int = 5000,
        retries: int = 2,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_ms / 1000.0
        self._retries = retries
        self._client: Optional[httpx.AsyncClient] = None

    async def aclose(self) -> None:
        """Close the underlying HTTP client, if one was created."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def check(self, request: ActionRequest) -> dict:
        """POST /v1/runtime/check. Returns the gateway's DecisionResponse
        JSON object verbatim (snake_case keys)."""
        return await self._post("/v1/runtime/check", _serialize_action_request(request))

    async def allow(self, action_type: str, resource: str, env: str = "local") -> bool:
        resp = await self.check(
            ActionRequest(action_type=action_type, resource=resource, environment=env, nonce=uuid.uuid4().hex)
        )
        return resp.get("decision") == "allow"

    async def batch_check(self, requests: list[ActionRequest]) -> list[DecisionResponse]:
        payload = {"requests": [_serialize_action_request(r) for r in requests]}
        result = await self._post("/v1/runtime/batch-check", payload)
        return [DecisionResponse.from_gateway(d) for d in result.get("decisions", [])]

    async def status(self) -> GatewayStatus:
        data = await self._get("/v1/runtime/status")
        return GatewayStatus.from_gateway(data) if data else GatewayStatus()

    async def health(self) -> dict:
        return await self._get("/v1/runtime/health")

    async def list_receipts(self, limit: int = 50, offset: int = 0) -> list[ReceiptRecord]:
        params = {"limit": limit, "offset": offset}
        result = await self._get("/v1/receipts", params=params)
        # Gateway responds with {"receipts": [...], "count": n}.
        return [ReceiptRecord.from_gateway(r) for r in result.get("receipts", [])] if result else []

    async def get_receipt(self, receipt_id: str) -> ReceiptRecord:
        return await self._get(f"/v1/receipts/{receipt_id}")

    async def list_approvals(self, limit: int = 50, offset: int = 0) -> list[dict]:
        return await self._get("/v1/approvals", params={"limit": limit, "offset": offset})

    async def list_executions(self, limit: int = 50, offset: int = 0) -> list[dict]:
        return await self._get("/v1/executions", params={"limit": limit, "offset": offset})

    async def list_continuations(self, limit: int = 50, offset: int = 0) -> list[dict]:
        return await self._get("/v1/continuations", params={"limit": limit, "offset": offset})

    async def get_capabilities(self) -> dict:
        return await self._get("/v1/capabilities")

    async def get_metrics(self) -> dict:
        return await self._get("/v1/runtime/metrics")

    async def _get(self, path: str, params: Optional[dict] = None) -> Any:
        return await self._request("GET", path, params=params)

    async def _post(self, path: str, body: dict) -> Any:
        return await self._request("POST", path, body=body)

    def _get_client(self) -> httpx.AsyncClient:
        # Lazily create one client and reuse it across retries/requests.
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def _request(self, method: str, path: str, *, params: Optional[dict] = None, body: Optional[dict] = None) -> Any:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        client = self._get_client()
        last_error: Optional[Exception] = None

        for attempt in range(self._retries + 1):
            try:
                resp = await client.request(
                    method,
                    f"{self._base_url}{path}",
                    headers=headers,
                    params=params,
                    json=body,
                )
                resp.raise_for_status()
                text = resp.text
                if not text:
                    return {}
                return json.loads(text)
            except httpx.HTTPStatusError as exc:
                last_error = exc
                # Only retry transient failures: 5xx and 429. Other 4xx
                # are policy/validation rejections — fail fast.
                status = exc.response.status_code if exc.response is not None else 0
                if status != 429 and status < 500:
                    raise
            except Exception as exc:
                # Network/transport errors are retryable.
                last_error = exc
            if attempt < self._retries:
                import asyncio
                await asyncio.sleep(0.1 * (2**attempt))

        raise last_error or RuntimeError("Request failed")
