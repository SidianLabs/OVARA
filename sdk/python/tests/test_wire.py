from __future__ import annotations

import json

import httpx
import pytest

from ovara_sdk import ActionRequest, OvaraClient


def _client(handler, retries: int = 2) -> OvaraClient:
    c = OvaraClient(base_url="http://gw", retries=retries)
    c._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return c


@pytest.mark.asyncio
async def test_retry_sends_a_fresh_nonce():
    """A retry that re-sent the first attempt's nonce would be rejected by
    the gateway's replay protection."""
    nonces: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonces.append(json.loads(request.content)["nonce"])
        if len(nonces) < 3:
            return httpx.Response(503, text="busy")
        return httpx.Response(200, json={"decision": "allow"})

    c = _client(handler)
    await c.check(ActionRequest(action_type="http.request", resource="r", environment="dev"))
    assert len(nonces) == 3
    assert len(set(nonces)) == 3
    await c.aclose()


@pytest.mark.asyncio
async def test_caller_supplied_nonce_is_kept_across_retries():
    nonces: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonces.append(json.loads(request.content)["nonce"])
        return httpx.Response(500) if len(nonces) < 2 else httpx.Response(200, json={"decision": "allow"})

    c = _client(handler, retries=1)
    await c.check(ActionRequest(action_type="http.request", resource="r", environment="dev", nonce="mine"))
    assert nonces == ["mine", "mine"]
    await c.aclose()


@pytest.mark.asyncio
async def test_list_methods_unwrap_the_gateway_envelope():
    def handler(request: httpx.Request) -> httpx.Response:
        key = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json={key: [{"id": key + "-1"}], "count": 1})

    c = _client(handler)
    assert await c.list_approvals() == [{"id": "approvals-1"}]
    assert await c.list_executions() == [{"id": "executions-1"}]
    assert await c.list_continuations() == [{"id": "continuations-1"}]
    await c.aclose()
