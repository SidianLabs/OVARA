"""A custom agent harness: ask the gateway before every action, obey the answer.

This is the integration an agent author does for actions the proxy cannot see
(running a shell command, deleting a file). It uses the AGENT credential only.
It then tries to cheat the gateway the way a compromised or malicious agent
loop would. Every cheat must fail.

  python3 harness.py GATEWAY_URL AGENT_TOKEN
"""
import asyncio
import json
import sys
import time
import urllib.error
import urllib.request
import uuid

from ovara_sdk import ActionRequest, OvaraClient, ToolDenied, ToolGuard, ToolHeld

base, token = sys.argv[1].rstrip("/"), sys.argv[2]
results = []


def say(ok, name, detail=""):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + (("  -- " + detail) if detail and not ok else ""))


def http(method, path, body=None, tok=token):
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if tok:
        req.add_header("Authorization", "Bearer " + tok)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def raw_check(action, resource, **extra):
    body = {"action_type": action, "resource": resource, "environment": "local",
            "nonce": uuid.uuid4().hex,
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    body.update(extra)
    return http("POST", "/v1/runtime/check", body)


async def main():
    c = OvaraClient(base_url=base, api_key=token)

    print("=== the harness doing its job")
    d = await c.check(ActionRequest(action_type="shell", resource="shell:ls", environment="local"))
    say(d.get("decision") == "escalate", "an unlisted shell command is escalated, not allowed", str(d.get("decision")))
    approval = http("POST", "/v1/approval/create", {"decision_id": d.get("decision_id")})
    say(approval[0] in (200, 201) and approval[1].get("approval_id", "").startswith("apr_"),
        "the harness can open an approval for its own escalated decision", str(approval))
    aid = approval[1].get("approval_id", "")
    print("APPROVAL " + aid, flush=True)       # the shell script plays the human

    # wait for the human
    deadline, status = time.time() + 40, "pending"
    while time.time() < deadline and status == "pending":
        await asyncio.sleep(1)
        status = http("GET", "/v1/approval/" + aid)[1].get("status", "pending")
    say(status == "approved", "the harness proceeds only after a human approves", status)

    # a second action the human DENIES
    d2 = await c.check(ActionRequest(action_type="shell", resource="shell:cat /etc/hostname", environment="local"))
    a2 = http("POST", "/v1/approval/create", {"decision_id": d2.get("decision_id")})[1].get("approval_id", "")
    print("APPROVAL " + a2, flush=True)
    deadline, status2 = time.time() + 40, "pending"
    while time.time() < deadline and status2 == "pending":
        await asyncio.sleep(1)
        status2 = http("GET", "/v1/approval/" + a2)[1].get("status", "pending")
    say(status2 == "denied", "a denied action is not executed", status2)

    print("=== a hard deny written in policy")
    dd = await c.check(ActionRequest(action_type="shell", resource="shell:rm -rf /", environment="local"))
    say(dd.get("decision") == "deny", "a policy deny rule stops the action outright", str(dd.get("decision")))

    print("=== the harness tries to cheat the gateway")
    # 1. replay a request nonce
    n = uuid.uuid4().hex
    body = {"action_type": "shell", "resource": "shell:pwd", "environment": "local", "nonce": n,
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    first = http("POST", "/v1/runtime/check", body)
    second = http("POST", "/v1/runtime/check", body)
    say(first[0] == 200 and second[1].get("decision") == "deny" or second[0] >= 400,
        "replaying a request (same nonce) is refused", "first=%s second=%s %s" % (first[0], second[0], second[1].get("decision")))
    # 2. claim to be a different agent
    sp = raw_check("shell", "shell:ls", agent_identity={"issuer": "x", "subject_id": "ag_someone_else"})
    say(sp[0] in (400, 401, 403), "claiming another agent's identity is rejected", "HTTP %s" % sp[0])
    # 3. forge a decision id, then try to open an approval for a decision the gateway never made
    fg = http("POST", "/v1/approval/create", {"decision_id": "dec_forged-" + uuid.uuid4().hex})
    say(fg[0] in (403, 404), "an approval cannot be opened for a decision the gateway never produced", "HTTP %s" % fg[0])
    # 4. open an approval for an ALLOWED decision (to approve something that was never escalated)
    # (no allow rule for shell exists, so use an http.request the default policy allows)
    allow = raw_check("http.request", "GET https://pypi.org/simple/")
    if allow[1].get("decision") == "allow":
        ua = http("POST", "/v1/approval/create", {"decision_id": allow[1].get("decision_id")})
        say(ua[0] == 409, "an approval cannot be minted for a request that was already allowed", "HTTP %s" % ua[0])
    else:
        say(False, "setup: expected an allowed decision for pypi.org", str(allow[1].get("decision")))
    # 5. approve its own request with the agent credential
    own = http("POST", "/v1/approval/%s/approve" % aid)
    say(own[0] in (401, 403), "the agent credential cannot approve (a human operator must)", "HTTP %s" % own[0])
    own2 = http("POST", "/v1/approval/%s/approve" % uuid.uuid4().hex)
    say(own2[0] in (401, 403, 404), "...nor any other approval", "HTTP %s" % own2[0])
    # 6. read or change policy, list everyone's approvals
    for name, (m, p) in {"read the policy": ("GET", "/v1/policy/rules"), "list pending approvals": ("GET", "/v1/approval/pending"),
                         "push a policy": ("PUT", "/v1/policy")}.items():
        r = http(m, p, {} if m != "GET" else None)
        say(r[0] in (401, 403, 404, 405), "the agent credential cannot " + name, "HTTP %s" % r[0])
    # 7. no credential at all
    say(http("POST", "/v1/runtime/check", {"action_type": "shell"}, tok="")[0] == 401, "an unauthenticated check is refused")
    # 8. a stale request (old issued_at)
    old = {"action_type": "shell", "resource": "shell:ls", "environment": "local", "nonce": uuid.uuid4().hex,
           "issued_at": "2020-01-01T00:00:00Z"}
    st = http("POST", "/v1/runtime/check", old)
    say(st[0] >= 400 or st[1].get("decision") == "deny", "a request dated years ago is refused", "HTTP %s %s" % (st[0], st[1].get("decision")))

    print("=== a tool guard: the framework's own tool calls, decided by the gateway")
    # The guard wraps the functions the model calls. It holds the agent token,
    # like the rest of this harness, and cannot approve anything.
    guard = ToolGuard(base, api_key=token, agent="harness", framework="custom", wait_seconds=40, poll_seconds=1)
    ran = []
    guard.on_hold = lambda call: print("APPROVAL " + call.approval_id, flush=True)   # the shell script plays the human

    @guard.tool("send_email")
    async def send_email(to, subject):
        ran.append(to)
        return "sent"

    @guard.tool("post_tweet")
    async def post_tweet(text):
        ran.append(text)
        return "posted"

    @guard.tool("delete_everything")
    async def delete_everything():
        ran.append("rm")
        return "gone"

    @guard.tool("deploy")
    async def deploy(env):
        ran.append(env)
        return "deployed"

    # the human approves (third answer)
    try:
        r = await send_email("a@example.com", "hello")
        say(r == "sent" and ran == ["a@example.com"], "a held tool call runs once a person approves it", "ran=%s" % ran)
    except Exception as e:  # noqa: BLE001
        say(False, "a held tool call runs once a person approves it", repr(e))
    last = guard.last
    say(last is not None and last.claimed and last.outcome_recorded is True,
        "the approval is claimed before the tool runs and the outcome is on record", str(last))
    # the human denies (fourth answer)
    try:
        await post_tweet("hi")
        say(False, "a tool call a person denies never runs", "it ran")
    except ToolDenied as e:
        say("denied" in str(e) and "hi" not in ran, "a tool call a person denies never runs", str(e))
    except Exception as e:  # noqa: BLE001
        say(False, "a tool call a person denies never runs", repr(e))
    # a deny written in policy: refused outright, nobody is asked
    try:
        await delete_everything()
        say(False, "a tool the policy denies is refused outright", "it ran")
    except ToolDenied as e:
        say("denied by policy" in str(e) and "rm" not in ran, "a tool the policy denies is refused outright", str(e))
    except Exception as e:  # noqa: BLE001
        say(False, "a tool the policy denies is refused outright", repr(e))
    # fail fast: nobody answers these; the approval stays open for a person
    guard.wait_seconds, guard.on_hold = 0, None
    try:
        await deploy("prod")
        say(False, "with wait_seconds=0 a held call fails fast with the approval id", "it ran")
    except ToolHeld as e:
        say(e.approval_id.startswith("apr_") and "prod" not in ran, "with wait_seconds=0 a held call fails fast with the approval id", str(e))
        try:
            await deploy("prod")
            say(False, "the identical call gets the same open approval back", "it ran")
        except ToolHeld as e2:
            say(e2.approval_id == e.approval_id, "the identical call gets the same open approval back", "%s then %s" % (e.approval_id, e2.approval_id))
    except Exception as e:  # noqa: BLE001
        say(False, "with wait_seconds=0 a held call fails fast with the approval id", repr(e))
    # the record cannot be faked
    forged = http("POST", "/v1/runtime/outcome", {"decision_id": "dec_forged-" + uuid.uuid4().hex, "status": "ok"})
    say(forged[0] == 404, "an outcome cannot be reported for a decision the gateway never made", "HTTP %s" % forged[0])
    denied = await c.check(ActionRequest(action_type="tool.call", resource="tool:delete_everything", environment="local"))
    lied = http("POST", "/v1/runtime/outcome", {"decision_id": denied.get("decision_id"), "status": "ok"})
    say(denied.get("decision") == "deny" and lied[0] == 409,
        "an outcome reported for a denied decision is refused and kept as a security event", "decision=%s HTTP %s" % (denied.get("decision"), lied[0]))
    await guard.aclose()

    await c.aclose()
    print("HARNESS_RESULT %d passed %d failed" % (sum(results), len(results) - sum(results)))


asyncio.run(main())
