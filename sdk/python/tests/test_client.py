from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ovara_sdk import ActionRequest, OvaraClient


@pytest.fixture
def client():
    return OvaraClient(base_url="http://localhost:8080", api_key="test-key", timeout_ms=5000, retries=2)


@pytest.fixture
def mock_httpx_response():
    def make_response(json_data, status_code=200):
        mock_resp = MagicMock()
        mock_resp.text = json.dumps(json_data)
        mock_resp.status_code = status_code
        mock_resp.raise_for_status = MagicMock()
        return mock_resp
    return make_response


class TestOvaraClientInit:
    def test_base_url_strips_trailing_slash(self):
        c = OvaraClient(base_url="http://localhost:8080/")
        assert c._base_url == "http://localhost:8080"

    def test_base_url_preserves_no_slash(self):
        c = OvaraClient(base_url="http://localhost:8080")
        assert c._base_url == "http://localhost:8080"

    def test_default_timeout(self):
        c = OvaraClient(base_url="http://localhost:8080")
        assert c._timeout == 5.0

    def test_custom_timeout(self):
        c = OvaraClient(base_url="http://localhost:8080", timeout_ms=2000)
        assert c._timeout == 2.0

    def test_default_retries(self):
        c = OvaraClient(base_url="http://localhost:8080")
        assert c._retries == 2

    def test_api_key_set(self):
        c = OvaraClient(base_url="http://localhost:8080", api_key="my-key")
        assert c._api_key == "my-key"


class TestOvaraClientCheck:
    @pytest.mark.asyncio
    async def test_check_returns_decision(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({
            "request_id": "req-123",
            "decision": "allow",
            "reason": "local policy",
            "trust_score": 0.95,
            "receipt_id": "rcpt-456",
        })

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            result = await client.check(ActionRequest(action_type="shell", resource="shell:ls", environment="local"))

        assert result["decision"] == "allow"
        assert result["request_id"] == "req-123"
        assert result["trust_score"] == 0.95

    @pytest.mark.asyncio
    async def test_check_sends_correct_payload(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({"request_id": "req-123", "decision": "deny"})

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            await client.check(ActionRequest(action_type="exec", resource="exec:ls", environment="dev"))

            call_args = mock_client.request.call_args
            assert call_args[0][0] == "POST"
            assert call_args[0][1] == "http://localhost:8080/v1/runtime/check"
            body = call_args[1]["json"]
            assert body["action_type"] == "exec"
            assert body["resource"] == "exec:ls"
            assert body["environment"] == "dev"

    @pytest.mark.asyncio
    async def test_check_includes_api_key_header(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({"request_id": "req-123", "decision": "allow"})

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            await client.check(ActionRequest(action_type="shell", resource="shell:echo test", environment="local"))

            headers = mock_client.request.call_args[1]["headers"]
            assert headers["Authorization"] == "Bearer test-key"

    @pytest.mark.asyncio
    async def test_check_no_api_key_header_when_not_set(self, mock_httpx_response):
        client = OvaraClient(base_url="http://localhost:8080")
        mock_resp = mock_httpx_response({"request_id": "req-123", "decision": "allow"})

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            await client.check(ActionRequest(action_type="shell", resource="shell:ls", environment="local"))

            headers = mock_client.request.call_args[1]["headers"]
            assert "Authorization" not in headers

    @pytest.mark.asyncio
    async def test_check_retries_on_failure(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({"request_id": "req-123", "decision": "allow"})

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            call_count = 0
            async def request_side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise Exception("transient error")
                return mock_resp
            mock_client.request = request_side_effect
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            result = await client.check(ActionRequest(action_type="shell", resource="shell:ls", environment="local"))

            assert result["decision"] == "allow"
            assert call_count == 2

    @pytest.mark.asyncio
    async def test_check_raises_after_all_retries_fail(self, client, mock_httpx_response):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(side_effect=Exception("permanent error"))
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            with pytest.raises(Exception, match="permanent error"):
                await client.check(ActionRequest(action_type="shell", resource="shell:ls", environment="local"))

    @pytest.mark.asyncio
    async def test_check_returns_empty_dict_on_empty_response(self, client, mock_httpx_response):
        mock_resp = MagicMock()
        mock_resp.text = ""
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            result = await client.check(ActionRequest(action_type="shell", resource="shell:ls", environment="local"))
            assert result == {}


class TestOvaraClientAllow:
    @pytest.mark.asyncio
    async def test_allow_returns_true_on_allow_decision(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({"request_id": "req-123", "decision": "allow"})
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            result = await client.allow("shell", "shell:echo test", "local")
            assert result is True

    @pytest.mark.asyncio
    async def test_allow_returns_false_on_deny_decision(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({"request_id": "req-123", "decision": "deny"})
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            result = await client.allow("shell", "shell:rm -rf /", "production")
            assert result is False

    @pytest.mark.asyncio
    async def test_allow_returns_false_on_pending_decision(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({"request_id": "req-123", "decision": "pending"})
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            result = await client.allow("git.push", "git:origin/main", "staging")
            assert result is False


class TestOvaraClientBatchCheck:
    @pytest.mark.asyncio
    async def test_batch_check_returns_decision_list(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({
            "decisions": [
                {"request_id": "req-1", "decision": "allow"},
                {"request_id": "req-2", "decision": "deny"},
            ]
        })
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            requests = [
                ActionRequest(action_type="shell", resource="shell:ls", environment="local"),
                ActionRequest(action_type="shell", resource="shell:rm -rf /", environment="production"),
            ]
            results = await client.batch_check(requests)

            assert len(results) == 2
            assert results[0].decision == "allow"
            assert results[1].decision == "deny"

    @pytest.mark.asyncio
    async def test_batch_check_empty_list(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({"decisions": []})
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            results = await client.batch_check([])
            assert results == []


class TestOvaraClientStatus:
    @pytest.mark.asyncio
    async def test_status_returns_gateway_status(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({
            "gateway_id": "gw-abc123",
            "enrollment_state": "local",
            "is_healthy": True,
        })
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            result = await client.status()
            assert result.gateway_id == "gw-abc123"
            assert result.enrollment_state == "local"
            assert result.is_healthy is True


class TestOvaraClientHealth:
    @pytest.mark.asyncio
    async def test_health_returns_dict(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({"healthy": True, "sla": {"approvals_breaching": 0}})
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            result = await client.health()
            assert result["healthy"] is True
            assert result["sla"]["approvals_breaching"] == 0


class TestOvaraClientListReceipts:
    @pytest.mark.asyncio
    async def test_list_receipts_returns_receipt_list(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response([
            {"receipt_id": "rcpt-1", "decision_id": "dec-1", "action_type": "shell", "decision": "allow"},
            {"receipt_id": "rcpt-2", "decision_id": "dec-2", "action_type": "exec", "decision": "deny"},
        ])
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            results = await client.list_receipts(limit=10)
            assert len(results) == 2
            assert results[0].receipt_id == "rcpt-1"
            assert results[1].receipt_id == "rcpt-2"

    @pytest.mark.asyncio
    async def test_list_receipts_empty_response(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response([])
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            results = await client.list_receipts()
            assert results == []


class TestOvaraClientGetReceipt:
    @pytest.mark.asyncio
    async def test_get_receipt_builds_correct_path(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({"receipt_id": "rcpt-abc", "decision_id": "dec-xyz", "decision": "allow"})
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            await client.get_receipt("rcpt-abc")

            call_args = mock_client.request.call_args
            assert call_args[0][0] == "GET"
            assert call_args[0][1] == "http://localhost:8080/v1/receipts/rcpt-abc"


class TestOvaraClientListApprovals:
    @pytest.mark.asyncio
    async def test_list_approvals_sends_params(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response([])
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            await client.list_approvals(limit=100, offset=50)

            call_args = mock_client.request.call_args
            params = call_args[1]["params"]
            assert params["limit"] == 100
            assert params["offset"] == 50


class TestOvaraClientListExecutions:
    @pytest.mark.asyncio
    async def test_list_executions_default_params(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response([])
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            await client.list_executions()

            call_args = mock_client.request.call_args
            params = call_args[1]["params"]
            assert params["limit"] == 50
            assert params["offset"] == 0


class TestOvaraClientListContinuations:
    @pytest.mark.asyncio
    async def test_list_continuations(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response([])
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            result = await client.list_continuations()
            assert result == []


class TestOvaraClientGetCapabilities:
    @pytest.mark.asyncio
    async def test_get_capabilities(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({"capabilities": ["shell", "exec", "git.push"]})
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            result = await client.get_capabilities()
            assert result["capabilities"] == ["shell", "exec", "git.push"]


class TestOvaraClientGetMetrics:
    @pytest.mark.asyncio
    async def test_get_metrics(self, client, mock_httpx_response):
        mock_resp = mock_httpx_response({"decisions": {"allow": 10, "deny": 2}})
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            result = await client.get_metrics()
            assert result["decisions"]["allow"] == 10