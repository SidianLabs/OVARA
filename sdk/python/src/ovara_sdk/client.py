from __future__ import annotations

import json
import uuid
from typing import Any, Optional, Sequence

import httpx

from .types import (
    ActionRequest,
    DecisionResponse,
    ExecutionRequest,
    ExecutionResponse,
    GatewayStatus,
    ReceiptRecord,
)


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

    async def check(self, request: ActionRequest) -> DecisionResponse:
        return await self._post(
            "/v1/runtime/check",
            {
                "action_type": request.action_type,
                "resource": request.resource,
                "environment": request.environment,
                "agent_identity": _maybe_dict(request.agent_identity),
                "capability_lease": _maybe_dict(request.capability_lease),
                "metadata": request.metadata,
                "trace_id": request.trace_id or uuid.uuid4().hex,
            },
        )

    async def allow(self, action_type: str, resource: str, env: str = "local") -> bool:
        resp = await self.check(
            ActionRequest(action_type=action_type, resource=resource, environment=env, trace_id=uuid.uuid4().hex)
        )
        return resp.decision == "allow"

    async def batch_check(self, requests: Sequence[ActionRequest]) -> list[DecisionResponse]:
        payload = {
            "requests": [
                {
                    "action_type": r.action_type,
                    "resource": r.resource,
                    "environment": r.environment,
                    "agent_identity": _maybe_dict(r.agent_identity),
                    "capability_lease": _maybe_dict(r.capability_lease),
                    "metadata": r.metadata,
                    "trace_id": r.trace_id or uuid.uuid4().hex,
                }
                for r in requests
            ]
        }
        result = await self._post("/v1/runtime/batch-check", payload)
        return [DecisionResponse(**d) for d in result.get("decisions", [])]

    async def execute(self, request: ExecutionRequest) -> ExecutionResponse:
        return await self._post(
            "/v1/runtime/execute",
            {
                "command": request.command,
                "args": request.args,
                "env": request.env,
                "working_dir": request.working_dir,
                "timeout_ms": request.timeout_ms,
            },
        )

    async def status(self) -> GatewayStatus:
        return await self._get("/v1/runtime/status")

    async def health(self) -> dict:
        return await self._get("/v1/runtime/health")

    async def list_receipts(self, limit: int = 50, offset: int = 0) -> list[ReceiptRecord]:
        params = {"limit": limit, "offset": offset}
        result = await self._get("/v1/runtime/receipts", params=params)
        return [ReceiptRecord(**r) for r in result] if result else []

    async def get_receipt(self, receipt_id: str) -> ReceiptRecord:
        return await self._get(f"/v1/runtime/receipts/{receipt_id}")

    async def verify_identity(self, identity: dict) -> dict:
        return await self._post("/v1/runtime/identity/verify", identity)

    async def list_approvals(self, limit: int = 50, offset: int = 0) -> list[dict]:
        return await self._get("/v1/runtime/approvals", params={"limit": limit, "offset": offset})

    async def list_executions(self, limit: int = 50, offset: int = 0) -> list[dict]:
        return await self._get("/v1/runtime/executions", params={"limit": limit, "offset": offset})

    async def list_continuations(self, limit: int = 50, offset: int = 0) -> list[dict]:
        return await self._get("/v1/runtime/continuations", params={"limit": limit, "offset": offset})

    async def get_capabilities(self) -> dict:
        return await self._get("/v1/runtime/capabilities")

    async def get_trust_score(self, agent_id: str) -> dict:
        return await self._get(f"/v1/runtime/trust/{agent_id}")

    async def get_metrics(self) -> dict:
        return await self._get("/v1/runtime/metrics")

    async def get_policy(self) -> dict:
        return await self._get("/v1/runtime/policy")

    async def _get(self, path: str, params: Optional[dict] = None) -> Any:
        return await self._request("GET", path, params=params)

    async def _post(self, path: str, body: dict) -> Any:
        return await self._request("POST", path, body=body)

    async def _request(self, method: str, path: str, *, params: Optional[dict] = None, body: Optional[dict] = None) -> Any:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        last_error: Optional[Exception] = None

        for attempt in range(self._retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
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
            except Exception as exc:
                last_error = exc
                if attempt < self._retries:
                    import asyncio
                    await asyncio.sleep(0.1 * (2**attempt))

        raise last_error or RuntimeError("Request failed")


def _maybe_dict(obj: Any) -> Optional[dict]:
    if obj is None:
        return None
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in obj.__dict__.items() if v is not None}
    return obj
