"""The tool guard against a stand-in for the gateway's decision API.

The fake keeps the gateway's rules that matter to the guard: an approval
is opened only for an escalated decision, an identical request gets a
pending or approved-unused approval back, a claim is single use, and an
outcome is taken once, never for a denied decision."""
from __future__ import annotations

import hashlib
import json

import httpx
import pytest

from ovara_sdk import GuardError, ToolDenied, ToolGuard, ToolHeld, tool_resource
from ovara_sdk.guard import canonical_arguments, mask_secrets

TOKEN = "agent-token"


class FakeGateway:
    def __init__(self, decide):
        self.decide = decide            # resource -> allow | deny | escalate
        self.requests = []              # (method, path, body)
        self.decisions = {}
        self.approvals = {}
        self.human = None               # called with the approval on every poll
        self.claim_conflict = False     # every claim answers 409
        self.outcome_status = 200

    @property
    def transport(self):
        return httpx.MockTransport(self.handle)

    def calls(self, path):
        return [b for (m, p, b) in self.requests if p == path]

    def handle(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        body = json.loads(request.content) if request.content else {}
        self.requests.append((method, path, body))
        if request.headers.get("Authorization") != "Bearer " + TOKEN:
            return httpx.Response(401, json={"error": "unauthorized"})
        if path == "/v1/runtime/check":
            dec = self.decide(body["resource"])
            did = "dec_%d" % (len(self.decisions) + 1)
            self.decisions[did] = {"decision": dec, "request": body, "outcome": None}
            return httpx.Response(200, json={
                "decision_id": did, "decision": dec, "reason_codes": ["policy_" + dec],
                "requires_approval": dec == "escalate",
                "matched_rule": "" if dec == "escalate" else "the %s rule" % dec,
            })
        if path == "/v1/approval/create":
            d = self.decisions.get(body.get("decision_id"))
            if d is None:
                return httpx.Response(404, json={"error": "unknown decision"})
            if d["decision"] != "escalate":
                return httpx.Response(409, json={"error": "not escalated"})
            key = self._key(d["request"])
            for a in self.approvals.values():
                if a["_key"] == key and (a["status"] == "pending" or (a["status"] == "approved" and not a["_claimed"])):
                    return httpx.Response(200, json=self._public(a))
            aid = "apr_%d" % (len(self.approvals) + 1)
            self.approvals[aid] = {"approval_id": aid, "decision_id": body["decision_id"], "status": "pending",
                                   "resolved_by": "", "_key": key, "_claimed": False, "polls": 0}
            return httpx.Response(201, json=self._public(self.approvals[aid]))
        if path.startswith("/v1/approval/") and path.endswith("/claim"):
            a = self.approvals.get(path.split("/")[3])
            if a is None:
                return httpx.Response(404, json={})
            if self.claim_conflict or a["_claimed"]:
                return httpx.Response(409, json={"error": "approval already used"})
            if a["status"] != "approved":
                return httpx.Response(200, json={"approval_id": a["approval_id"], "status": a["status"], "claimed": False})
            a["_claimed"] = True
            return httpx.Response(200, json={"approval_id": a["approval_id"], "status": "approved", "claimed": True})
        if path.startswith("/v1/approval/"):
            a = self.approvals.get(path.split("/")[3])
            if a is None:
                return httpx.Response(404, json={})
            a["polls"] += 1
            if self.human is not None:
                self.human(a)
            return httpx.Response(200, json=self._public(a))
        if path == "/v1/runtime/outcome":
            d = self.decisions.get(body.get("decision_id"))
            if d is None:
                return httpx.Response(404, json={})
            if d["decision"] == "deny" or d["outcome"] is not None:
                return httpx.Response(409, json={})
            if self.outcome_status != 200:
                return httpx.Response(self.outcome_status, json={})
            d["outcome"] = body
            return httpx.Response(200, json={"decision_id": body["decision_id"], "status": body["status"], "recorded": True})
        return httpx.Response(404, json={"error": "no such route"})

    @staticmethod
    def _key(req):
        ctx = (req.get("metadata") or {}).get("proxy_context") or {}
        return (req["resource"], ctx.get("arguments_sha256"))

    @staticmethod
    def _public(a):
        return {k: v for k, v in a.items() if not k.startswith("_")}


def approve_on_second_poll(a):
    if a["polls"] >= 2 and a["status"] == "pending":
        a["status"], a["resolved_by"] = "approved", "alice"


def deny_on_first_poll(a):
    if a["status"] == "pending":
        a["status"], a["resolved_by"] = "denied", "bob"


def guard_for(gw, **kw):
    kw.setdefault("wait_seconds", 5.0)
    kw.setdefault("poll_seconds", 0.001)
    return ToolGuard("http://gateway.test/", api_key=TOKEN, agent="support-bot", framework="pytest", transport=gw.transport, **kw)


# --- the record of a call -----------------------------------------------

def test_an_allowed_tool_runs_and_its_outcome_is_recorded():
    gw = FakeGateway(lambda r: "allow")
    guard = guard_for(gw)
    ran = []

    @guard.tool("send_email")
    def send_email(to: str, subject: str, password: str = "") -> str:
        ran.append(to)
        return "sent"

    assert send_email("a@example.com", subject="hi", password="hunter2") == "sent"
    assert ran == ["a@example.com"]

    (check,) = gw.calls("/v1/runtime/check")
    assert check["action_type"] == "tool.call"
    assert check["resource"] == "tool:send_email"
    assert check["environment"] == "local"
    assert check["nonce"] and check["issued_at"].endswith("Z")
    ctx = check["metadata"]["proxy_context"]
    args = {"to": "a@example.com", "subject": "hi", "password": "hunter2"}
    assert ctx["tool"] == "send_email"
    assert ctx["agent"] == "support-bot" and ctx["framework"] == "pytest"
    assert ctx["arguments_sha256"] == hashlib.sha256(canonical_arguments(args)).hexdigest()
    assert ctx["arguments_bytes"] == str(len(canonical_arguments(args)))
    assert "hunter2" not in ctx["arguments"] and '"password": "***"' in ctx["arguments"]
    assert '"to": "a@example.com"' in ctx["arguments"]
    assert all(isinstance(v, str) for v in ctx.values())

    (outcome,) = gw.calls("/v1/runtime/outcome")
    assert outcome["decision_id"] == "dec_1"
    assert outcome["status"] == "ok" and outcome["duration_ms"] >= 0 and "error" not in outcome
    assert guard.last.decision == "allow" and guard.last.outcome_recorded is True
    assert guard.last.rule == "the allow rule"
    assert not gw.calls("/v1/approval/create")


def test_a_denied_tool_never_runs():
    gw = FakeGateway(lambda r: "deny")
    guard = guard_for(gw)
    ran = []
    delete_everything = guard.wrap(lambda: ran.append(1), "delete_everything")
    with pytest.raises(ToolDenied) as e:
        delete_everything()
    assert ran == []
    assert "denied by policy" in str(e.value) and "the deny rule" in str(e.value) and "policy_deny" in str(e.value)
    assert e.value.call.decision_id == "dec_1"
    assert not gw.calls("/v1/runtime/outcome") and not gw.calls("/v1/approval/create")


def test_a_failing_tool_reports_an_error_outcome_and_raises():
    gw = FakeGateway(lambda r: "allow")
    guard = guard_for(gw)

    @guard.tool
    def flaky(n):
        raise ValueError("boom %d" % n)

    with pytest.raises(ValueError):
        flaky(3)
    (outcome,) = gw.calls("/v1/runtime/outcome")
    assert outcome["status"] == "error" and outcome["error"] == "ValueError: boom 3"
    assert gw.calls("/v1/runtime/check")[0]["resource"] == "tool:flaky"
    assert gw.calls("/v1/runtime/check")[0]["metadata"]["proxy_context"]["arguments"] == '{"n": 3}'


def test_an_unrecorded_outcome_does_not_fail_the_call(caplog):
    gw = FakeGateway(lambda r: "allow")
    gw.outcome_status = 500
    guard = guard_for(gw)
    assert guard.wrap(lambda: "done", "t")() == "done"
    assert guard.last.outcome_recorded is False
    assert any("was not recorded" in r.message for r in caplog.records)


# --- a person in the loop -----------------------------------------------

def test_a_held_tool_runs_once_a_person_approves_and_the_approval_is_claimed():
    gw = FakeGateway(lambda r: "escalate")
    gw.human = approve_on_second_poll
    guard = guard_for(gw)
    held = []
    guard.on_hold = lambda call: held.append(call.approval_id)
    ran = []
    post = guard.wrap(lambda text: ran.append(text) or "posted", "post_tweet")

    assert post("hello") == "posted"
    assert ran == ["hello"] and held == ["apr_1"]
    paths = [p for (_, p, _) in gw.requests]
    assert paths.count("/v1/approval/apr_1/claim") == 1
    assert paths.index("/v1/approval/apr_1/claim") < paths.index("/v1/runtime/outcome")
    last = guard.last
    assert last.decision == "escalate" and last.approval_id == "apr_1" and last.claimed
    assert last.approval_status == "approved" and last.resolved_by == "alice"
    assert last.outcome_recorded is True


def test_a_tool_a_person_denies_never_runs():
    gw = FakeGateway(lambda r: "escalate")
    gw.human = deny_on_first_poll
    guard = guard_for(gw)
    ran = []
    with pytest.raises(ToolDenied) as e:
        guard.wrap(lambda: ran.append(1), "wire_money")()
    assert ran == [] and "denied by bob" in str(e.value)
    assert not gw.calls("/v1/runtime/outcome")
    assert not [p for (_, p, _) in gw.requests if p.endswith("/claim")]


def test_fail_fast_raises_held_with_the_approval_open():
    gw = FakeGateway(lambda r: "escalate")
    guard = guard_for(gw, wait_seconds=0)
    ran = []
    with pytest.raises(ToolHeld) as e:
        guard.wrap(lambda: ran.append(1), "deploy")()
    assert ran == []
    assert e.value.approval_id == "apr_1" and e.value.retry_after >= 1
    assert gw.approvals["apr_1"]["status"] == "pending"   # open for a person


def test_the_identical_call_gets_the_late_answer_back_and_uses_it_once():
    gw = FakeGateway(lambda r: "escalate")
    guard = guard_for(gw, wait_seconds=0)
    ran = []
    deploy = guard.wrap(lambda env: ran.append(env), "deploy")

    with pytest.raises(ToolHeld):
        deploy("prod")
    # the person answers after the guard stopped waiting
    gw.approvals["apr_1"].update(status="approved", resolved_by="alice")

    deploy("prod")                       # identical: gets apr_1 back, claims it, runs
    assert ran == ["prod"] and guard.last.approval_id == "apr_1" and guard.last.claimed

    with pytest.raises(ToolHeld) as e:   # claimed: the next identical call is asked afresh
        deploy("prod")
    assert e.value.approval_id == "apr_2" and ran == ["prod"]

    with pytest.raises(ToolHeld) as e2:  # different arguments: a different approval
        deploy("staging")
    assert e2.value.approval_id == "apr_3"


def test_an_approval_already_used_does_not_run_the_tool():
    gw = FakeGateway(lambda r: "escalate")
    gw.human = approve_on_second_poll
    gw.claim_conflict = True
    guard = guard_for(gw)
    ran = []
    with pytest.raises(ToolDenied) as e:
        guard.wrap(lambda: ran.append(1), "t")()
    assert ran == [] and "already used" in str(e.value)


def test_a_timed_out_wait_raises_held():
    gw = FakeGateway(lambda r: "escalate")
    guard = guard_for(gw, wait_seconds=0.02, poll_seconds=0.005)
    with pytest.raises(ToolHeld):
        guard.wrap(lambda: None, "t")()
    assert gw.approvals["apr_1"]["polls"] >= 1


# --- failing closed -----------------------------------------------------

def test_an_unreachable_gateway_means_the_tool_does_not_run():
    def down(request):
        raise httpx.ConnectError("refused", request=request)

    guard = ToolGuard("http://gateway.test", api_key=TOKEN, transport=httpx.MockTransport(down))
    ran = []
    with pytest.raises(GuardError) as e:
        guard.wrap(lambda: ran.append(1), "t")()
    assert ran == [] and "did not run" in str(e.value)


def test_a_rejected_check_means_the_tool_does_not_run():
    gw = FakeGateway(lambda r: "allow")
    guard = ToolGuard("http://gateway.test", api_key="wrong", transport=gw.transport)
    with pytest.raises(GuardError) as e:
        guard.wrap(lambda: None, "t")()
    assert "HTTP 401" in str(e.value)


# --- async frameworks ---------------------------------------------------

@pytest.mark.asyncio
async def test_an_async_tool_is_guarded_the_same_way():
    gw = FakeGateway(lambda r: "escalate")
    gw.human = approve_on_second_poll
    guard = guard_for(gw)

    @guard.tool("fetch_page")
    async def fetch_page(url: str) -> str:
        return "<html>" + url

    assert await fetch_page("https://example.com") == "<html>https://example.com"
    paths = [p for (_, p, _) in gw.requests]
    assert paths[:2] == ["/v1/runtime/check", "/v1/approval/create"]
    assert paths[-2:] == ["/v1/approval/apr_1/claim", "/v1/runtime/outcome"]
    assert guard.last.outcome_recorded is True
    await guard.aclose()


@pytest.mark.asyncio
async def test_an_async_denial_never_runs():
    gw = FakeGateway(lambda r: "deny")
    guard = guard_for(gw)
    ran = []

    async def drop_table(name):
        ran.append(name)

    with pytest.raises(ToolDenied):
        await guard.wrap(drop_table)("users")
    assert ran == []


# --- adapters and helpers ------------------------------------------------

def test_the_langchain_adapter_wraps_func_and_coroutine():
    class Tool:  # a stand-in for langchain_core.tools.StructuredTool
        name = "search"

        def __init__(self):
            self.func = lambda q: "r:" + q
            self.coroutine = None

    gw = FakeGateway(lambda r: "allow")
    guard = guard_for(gw)
    t = guard.langchain(Tool())
    assert t.func("x") == "r:x"
    assert gw.calls("/v1/runtime/check")[0]["resource"] == "tool:search"
    with pytest.raises(TypeError):
        guard.langchain(object())


def test_tool_resource_escapes_like_the_mcp_gate():
    assert tool_resource("send_email") == "tool:send_email"
    assert tool_resource("we ird") == "tool:we%20ird"
    assert tool_resource("a/b*c") == "tool:a%2Fb%2Ac"
    assert tool_resource("réglé") == "tool:r%C3%A9gl%C3%A9"


def test_secret_looking_arguments_are_masked_in_the_preview_only():
    args = {"url": "https://x", "headers": {"Authorization": "Bearer abc"}, "items": [{"api_key": "k"}], "n": 1}
    masked = mask_secrets(args)
    assert masked == {"url": "https://x", "headers": {"Authorization": "***"}, "items": [{"api_key": "***"}], "n": 1}
    assert canonical_arguments(args) != canonical_arguments(masked)
    assert canonical_arguments({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_positional_and_keyword_arguments_are_bound_by_name():
    gw = FakeGateway(lambda r: "allow")
    guard = guard_for(gw)

    def move(src, dst, *, force=False):
        return (src, dst, force)

    assert guard.wrap(move)("a", dst="b", force=True) == ("a", "b", True)
    assert gw.calls("/v1/runtime/check")[0]["metadata"]["proxy_context"]["arguments"] == '{"dst": "b", "force": true, "src": "a"}'
