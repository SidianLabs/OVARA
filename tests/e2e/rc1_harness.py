#!/usr/bin/env python3
"""Ovara RC1 end-to-end adversarial harness.

Builds a fully fresh clean-room (keys, tokens, config, CA, state) and
exercises the entire authorization chain end-to-end:

    identity -> delegation -> lease -> policy -> approval
             -> proxy -> execution -> receipts

Every case asserts a specific expected outcome. Anything unexpected is
reported; the harness never treats silence as success.

Usage: python3 e2e_harness.py [workdir]
Requires: running-from-source gateway+proxy binaries (built by harness
setup if absent), cryptography, and outbound HTTPS for real-transit
proxy cases (example.com / httpbin.org).
"""
import base64, hashlib, importlib.util, json, os, secrets, signal, socket
import subprocess, sys, time, urllib.request, urllib.error, uuid

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/rc1-e2e"
GW_PORT, PX_PORT, UP_PORT = 18560, 19443, 18080
GW = f"http://127.0.0.1:{GW_PORT}"
PX = f"http://127.0.0.1:{PX_PORT}"
REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))  # tests/e2e/ -> repo root
import shutil
GO = os.environ.get("GO") or shutil.which("go") or "/usr/local/go/bin/go"

spec = importlib.util.spec_from_file_location(
    "canon", f"{REPO}/sdk/python/src/ovara_sdk/canon.py")
canon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canon)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

RESULTS = []
def rec(stage, case, expected, got, ok):
    RESULTS.append((stage, case, expected, got, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {case:<58} want={expected} got={got}")

def rfc(u): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(u))

def http(method, url, token=None, body=None, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if token: r.add_header("Authorization", "Bearer " + token)
    if body is not None: r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b"{}")
        except Exception: return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}

# ---------------------------------------------------------------- setup
def setup():
    os.makedirs(f"{WORK}/var/data", exist_ok=True)
    for d in (f"{REPO}/proxy", f"{REPO}/runtime/gateway"):
        subprocess.run([GO, "build", "-o", f"{WORK}/" +
                        ("ovara-proxy" if "proxy" in d else "ovara-gateway"),
                        "./cmd/" + ("ovara-proxy/" if d.endswith("proxy") else "server/")],
                       cwd=d, check=True, capture_output=True)
    keys, toks = {}, {}
    for name in ("issuer-A", "issuer-B"):
        k = Ed25519PrivateKey.generate()
        keys[name] = {
            "seed": k.private_bytes(serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex(),
            "pub": k.public_key().public_bytes(serialization.Encoding.Raw,
                serialization.PublicFormat.Raw).hex()}
    toks["agent"], toks["operator"], toks["proxyclient"] = (
        "rc1-agent-" + secrets.token_hex(16),
        "rc1-op-" + secrets.token_hex(16),
        "rc1-pxc-" + secrets.token_hex(16))
    principal = "ag_" + hashlib.sha256(toks["agent"].encode()).hexdigest()[:16]
    toks["principal"] = principal
    json.dump(keys, open(f"{WORK}/keys.json", "w"))
    json.dump(toks, open(f"{WORK}/tokens.json", "w"))
    json.dump({
        "agent_tokens": [toks["agent"]], "operator_tokens": [toks["operator"]],
        "auth_enabled": True, "fail_closed": True,
        "listen_addr": "127.0.0.1", "server_port": str(GW_PORT),
        "log_level": "info", "policy_file": "policy.json",
        "policy_version": "v1-rc1", "enrollment_file": "var/data/enrollment.json",
        "enable_host_executors": True,
        "execution_working_dir": WORK + "/exec",
        "receipts_file": "var/gw_receipts.jsonl",
        "trusted_issuers": {"issuer-A": keys["issuer-A"]["pub"],
                            "issuer-B": keys["issuer-B"]["pub"]},
    }, open(f"{WORK}/config.json", "w"), indent=1)
    os.makedirs(f"{WORK}/exec", exist_ok=True)
    json.dump({"version": "v1-rc1", "rules": [
        {"action_type": "http.request", "environment": "local",
         "resource": "*blocked.example.com*", "deny": True},
        {"action_type": "http.request", "environment": "local", "allow": True},
        {"action_type": "shell", "environment": "local", "escalate": True},
        {"action_type": "*", "environment": "*", "escalate": True},
    ]}, open(f"{WORK}/policy.json", "w"))
    json.dump({
        "listen_addr": f"127.0.0.1:{PX_PORT}", "gateway_url": GW,
        "gateway_token": toks["agent"], "agent_token": toks["proxyclient"],
        "environment": "local",
        "ca_cert_file": "var/ca.pem", "ca_key_file": "var/ca.key",
        "receipt_key_file": "var/receipt.key",
        "receipts_file": "var/receipts.jsonl",
        "pubkey_file": "var/receipt.pubkey", "fail_open": False,
        "credentials": [{"host": "httpbin.org", "headers":
            {"Authorization": "Bearer RC1-CANARY-SECRET-7f3a9b2c"}}],
    }, open(f"{WORK}/proxy.json", "w"), indent=1)
    return keys, toks

PROCS = []
def launch():
    PROCS.append(subprocess.Popen(["./ovara-gateway"], cwd=WORK,
        env={**os.environ, "OVARA_CONFIG": "config.json"},
        stdout=open(f"{WORK}/gw.log", "w"), stderr=subprocess.STDOUT))
    PROCS.append(subprocess.Popen(["./ovara-proxy", "-config", "proxy.json"],
        cwd=WORK, stdout=open(f"{WORK}/proxy.log", "w"),
        stderr=subprocess.STDOUT))
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", GW_PORT), 0.2).close()
            socket.create_connection(("127.0.0.1", PX_PORT), 0.2).close()
            return
        except OSError: time.sleep(0.2)
    raise SystemExit("services did not start — see logs in " + WORK)

def teardown(*_):
    for p in PROCS:
        try: p.terminate()
        except Exception: pass

# ------------------------------------------------------------- identities
KEYS = TOKS = PRIN = GWID = None
def key(name):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(KEYS[name]["seed"]))

def chain(hops):
    """hops: list of (issuer_key_name, subject, audience, scope, actions,
    exp_unix, nonce). Signs canonically, links prev-signature."""
    auths, prev = [], ""
    for kname, subj, aud, scope, acts, exp, nonce in hops:
        p = canon.hop_payload(kname, subj, aud, scope, acts, exp,
                              int(time.time()), nonce, prev)
        sig = key(kname).sign(p)
        prev = sig.hex()
        auths.append({"issuer": kname, "subject_id": subj, "actions": acts,
            "resource_scope": scope, "audience": aud,
            "expires_at": rfc(exp), "nonce": nonce,
            "delegated_at": rfc(int(time.time())),
            "signature": base64.b64encode(sig).decode()})
    return {"authorities": auths, "depth": len(auths)}

def check(resource, action="http.request", tok=None, subject=None,
          chain_obj=None, lease=None, extra=None):
    unrestrict()
    req = {"action_type": action, "resource": resource,
           "environment": "local", "nonce": uuid.uuid4().hex,
           "issued_at": rfc(int(time.time())),
           "agent_identity": {"issuer": "ovara",
                              "subject_id": subject or PRIN}}
    if chain_obj: req["delegation_chain"] = chain_obj
    if lease: req["capability_lease"] = lease
    if extra: req.update(extra)
    return http("POST", GW + "/v1/runtime/check", tok or TOKS["agent"], req)

def lease(subj=None, aud=None, acts=None, scope="*", exp=None, issuer="issuer-A"):
    exp = exp or int(time.time()) + 3600
    iat = int(time.time())
    # NOTE: leases REQUIRE exact audience match when the gateway has an
    # identity — empty is denied (stricter than delegation hops, where
    # empty is issuer-chosen unscoped). Default to this gateway.
    aud = GWID if aud is None else aud
    p = canon.lease_payload("lease-rc1", issuer, subj or PRIN, aud,
        acts or ["http.request"], scope, exp, iat, 0)
    sig = key(issuer).sign(p)
    return {"lease_id": "lease-rc1", "issuer": issuer,
            "subject": subj or PRIN, "allowed_actions": acts or ["http.request"],
            "resource_scope": scope, "expiry": rfc(exp), "delegation_depth": 0,
            "issued_at": rfc(iat), "audience": aud,
            "signature": base64.b64encode(sig).decode()}

def curl_proxy(target, auth=True, timeout=20):
    """curl through the proxy. Returns (http_code, body)."""
    cmd = ["curl", "-s", "-o", "-", "-w", "\n%{http_code}", "-x", PX,
           "--max-time", str(timeout)]
    if auth:
        cmd += ["--proxy-user", "agent:" + TOKS["proxyclient"]]
    if target.startswith("https"):
        cmd += ["--cacert", f"{WORK}/var/ca.pem"]
    cmd.append(target)
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    body, _, code = out.rpartition("\n")
    return code.strip(), body

def receipts():
    try:
        return [json.loads(l) for l in open(f"{WORK}/var/receipts.jsonl")]
    except FileNotFoundError:
        return []

def unrestrict():
    """Repeated denials trigger trust containment (by design) — reset so
    each case is judged on its own merits, not accumulated trust state."""
    http("POST", GW + f"/v1/shield/unrestrict/{PRIN}", TOKS["operator"])

# ---------------------------------------------------------------- stages
def s_identity():
    print("\n== STAGE: identity ==")
    st, _ = http("POST", GW + "/v1/runtime/check", None,
                 {"action_type": "http.request", "resource": "GET http://x/",
                  "environment": "local", "nonce": "n", "issued_at": rfc(0)})
    rec("identity", "no token", "401", st, st == 401)
    st, _ = http("POST", GW + "/v1/runtime/check", "bogus-token",
                 {"action_type": "http.request", "resource": "GET http://x/",
                  "environment": "local", "nonce": "n", "issued_at": rfc(0)})
    rec("identity", "forged token", "401", st, st == 401)
    st, d = check("GET http://example.com/x", subject="ag_attacker")
    rec("identity", "foreign subject_id vs credential principal",
        "400 identity_mismatch", f"{st} {d.get('error','')[:40]}",
        st == 400 and "identity_mismatch" in str(d.get("error", "")))
    st, d = check("GET http://example.com/x")
    rec("identity", "valid credential, honest identity",
        "allow/deny by policy", f"{st} {d.get('decision')}",
        st == 200 and d.get("decision") in ("allow", "deny", "escalate"))
    st, _ = http("POST", GW + "/v1/runtime/check", TOKS["operator"],
                 {"action_type": "http.request", "resource": "GET http://x/",
                  "environment": "local", "nonce": "n", "issued_at": rfc(0)})
    rec("identity", "operator token reaches check", "200", st, st == 200)
    st, _ = http("GET", GW + "/v1/status", TOKS["agent"])
    rec("identity", "agent token on operator route", "403", st, st == 403)

def s_delegation():
    print("\n== STAGE: delegation ==")
    exp = int(time.time()) + 3600
    good = chain([("issuer-A", "issuer-B", GWID, "*",
                   ["http.request", "shell"], exp, ""),
                  ("issuer-B", PRIN, GWID, "GET https://api.example.com/foo/*",
                   ["http.request"], exp, uuid.uuid4().hex)])
    unrestrict()
    st, d = check("GET https://api.example.com/foo/x", chain_obj=good)
    rec("delegation", "valid A→B→C, in-scope request", "allow",
        f"{st} {d.get('decision')}", d.get("decision") == "allow")
    unrestrict()
    st, d = check("POST https://api.example.com/foo/x", chain_obj=good)
    rec("delegation", "capability GET but POST requested", "deny",
        d.get("decision"), d.get("decision") == "deny")
    unrestrict()
    st, d = check("GET https://evil.example/x", chain_obj=good)
    rec("delegation", "resource outside terminal scope", "deny",
        d.get("decision"), d.get("decision") == "deny")
    bad = json.loads(json.dumps(good))
    bad["authorities"][1]["signature"] = base64.b64encode(
        b"\x00" * 64).decode()
    unrestrict()
    st, d = check("GET https://api.example.com/foo/x", chain_obj=bad)
    rec("delegation", "forged terminal signature", "deny",
        d.get("decision"), d.get("decision") == "deny")
    bad = json.loads(json.dumps(good))
    bad["authorities"][1]["issuer"] = "issuer-X"
    unrestrict()
    st, d = check("GET https://api.example.com/foo/x", chain_obj=bad)
    rec("delegation", "untrusted intermediate issuer", "deny",
        d.get("decision"), d.get("decision") == "deny")
    bad = json.loads(json.dumps(good))
    bad["authorities"][1]["subject_id"] = "ag_someoneelse"
    unrestrict()
    st, d = check("GET https://api.example.com/foo/x", chain_obj=bad)
    rec("delegation", "terminal subject != authenticated principal", "deny",
        d.get("decision"), d.get("decision") == "deny")
    bad = json.loads(json.dumps(good))
    bad["authorities"][1]["nonce"] = "mutated-" + uuid.uuid4().hex
    unrestrict()
    st, d = check("GET https://api.example.com/foo/x", chain_obj=bad)
    rec("delegation", "mutated signed nonce", "deny",
        d.get("decision"), d.get("decision") == "deny")
    unrestrict()
    st, d = check("GET https://api.example.com/foo/x", chain_obj=good)
    rec("delegation", "replay of validated chain (window)", "deny",
        d.get("decision"), d.get("decision") == "deny")

def s_lease():
    print("\n== STAGE: lease ==")
    unrestrict()
    st, d = check("GET http://example.com/x", lease=lease(
        acts=["http.request"], scope="*"))
    rec("lease", "valid lease + in-scope request", "allow",
        f"{st} {d.get('decision')} {d.get('reason_codes')}",
        d.get("decision") == "allow")
    unrestrict()
    st, d = check("GET http://example.com/x", lease=lease(subj="ag_other"))
    rec("lease", "lease subject != principal", "deny",
        d.get("decision"), d.get("decision") == "deny")
    unrestrict()
    st, d = check("GET http://example.com/x",
                  lease=lease(acts=["shell"]))
    rec("lease", "lease capability mismatch", "deny",
        d.get("decision"), d.get("decision") == "deny")
    unrestrict()
    st, d = check("GET http://example.com/x",
                  lease=lease(aud="gw_otherdomain"))
    rec("lease", "lease audience mismatch", "deny",
        d.get("decision"), d.get("decision") == "deny")
    unrestrict()
    st, d = check("GET http://example.com/x",
                  lease=lease(exp=int(time.time()) - 60))
    rec("lease", "expired lease", "deny",
        d.get("decision"), d.get("decision") == "deny")
    unrestrict()
    st, d = check("GET http://example.com/x",
                  lease=lease(scope="https://api.other.com/*"))
    rec("lease", "lease resource scope mismatch", "deny",
        d.get("decision"), d.get("decision") == "deny")

def s_policy():
    print("\n== STAGE: policy ==")
    st, d = check("GET http://example.com/x")
    rec("policy", "matching allow rule", "allow",
        d.get("decision"), d.get("decision") == "allow")
    st, d = check("GET http://blocked.example.com/x")
    rec("policy", "explicit deny rule", "deny",
        d.get("decision"), d.get("decision") == "deny")
    st, d = check("POST http://unknown.example/x", action="mystery.action")
    rec("policy", "catch-all escalate", "escalate",
        d.get("decision"), d.get("decision") == "escalate")

def s_approval():
    print("\n== STAGE: approval ==")
    marker = f"{WORK}/exec/approved_marker"
    if os.path.exists(marker): os.remove(marker)
    st, d = check(f"shell:echo rc1-executed > {marker}", action="shell")
    rec("approval", "shell action escalates", "escalate",
        f"{st} {d.get('decision')}", d.get("decision") == "escalate")
    did = d.get("decision_id")
    st, ap = http("POST", GW + "/v1/approval/create", TOKS["agent"],
                  {"decision_id": did})
    rec("approval", "owner creates approval", "201+id",
        f"{st} {ap.get('approval_id')}", st == 201 and ap.get("approval_id"))
    aid = ap.get("approval_id")
    st, d2 = check("shell:echo other > /tmp/x", action="shell",
                   subject="ag_attacker")
    st, ap2 = http("POST", GW + "/v1/approval/create", TOKS["agent"],
                   {"decision_id": "dec_fabricated-000"})
    rec("approval", "fabricated decision_id", "404",
        st, st == 404)
    st, _ = http("POST", GW + f"/v1/approval/{aid}/approve", TOKS["agent"], {})
    rec("approval", "agent token cannot approve (operator-only)", "403",
        st, st == 403)
    st, _ = http("POST", GW + f"/v1/approval/{aid}/approve", TOKS["operator"], {})
    rec("approval", "operator approves", "200", st, st == 200)
    st, _ = http("POST", GW + f"/v1/approval/{aid}/resume", TOKS["operator"], {})
    # In the wired path approve→queued and the orchestrator executes
    # within its poll window — resume finds nothing resumable → honest
    # 409. Execution itself is asserted by the marker file below.
    rec("approval", "resume after auto-execution", "409 (nothing resumable)",
        st, st == 409)
    time.sleep(3)  # orchestrator poll interval
    ran = os.path.exists(marker)
    rec("approval", "approved action actually executed on host",
        "marker exists", "exists" if ran else "absent", ran)
    st, _ = http("POST", GW + f"/v1/approval/{aid}/resume", TOKS["operator"], {})
    rec("approval", "second resume (single-use)", "409", st, st == 409)
    st, _ = http("GET", GW + f"/v1/approval/{aid}", "bogus-other-agent")
    rec("approval", "foreign approval read", "401/404", st, st in (401, 404))

def s_proxy():
    print("\n== STAGE: proxy ==")
    code, _ = curl_proxy("http://example.com/", auth=False)
    rec("proxy", "unauthenticated transit", "407", code, code == "407")
    n0 = len(receipts())
    code, _ = curl_proxy("https://example.com:444/")
    rec("proxy", "CONNECT non-443 tunnel attempt", "000/403",
        code, code in ("000", "403"))
    rec("proxy", "non-443 attempt receipted as deny", "deny receipt",
        receipts()[-1]["decision"] if len(receipts()) > n0 else "none",
        len(receipts()) > n0 and receipts()[-1]["decision"] == "deny")
    code, _ = curl_proxy("http://169.254.169.254/latest/meta-data")
    rec("proxy", "SSRF to link-local metadata", "403", code, code == "403")
    code, _ = curl_proxy("http://127.0.0.1:18560/v1/status")
    rec("proxy", "SSRF to gateway loopback", "403", code, code == "403")
    code, body = curl_proxy("http://example.com/")
    rec("proxy", "plain-HTTP transit (policy allow)", "200",
        code, code == "200")
    code, body = curl_proxy("https://example.com/")
    rec("proxy", "MITM HTTPS transit (policy allow)", "200",
        code, code == "200")
    code, body = curl_proxy("http://blocked.example.com/x")
    rec("proxy", "policy deny blocks transit", "403",
        code, code == "403")
    code, body = curl_proxy("https://httpbin.org/headers")
    leaked = "RC1-CANARY-SECRET-7f3a9b2c" in body
    rec("proxy", "injected credential echoed by upstream",
        "redacted", "leaked" if leaked else "[REDACTED]",
        code == "200" and not leaked)

def s_execution():
    print("\n== STAGE: execution (denied cannot execute) ==")
    marker = f"{WORK}/exec/denied_marker"
    if os.path.exists(marker): os.remove(marker)
    st, d = check(f"shell:touch {marker}", action="shell")
    # shell escalates; do NOT approve — orchestrator must not run it.
    time.sleep(3)
    rec("execution", "unapproved escalated action does not execute",
        "absent", "exists" if os.path.exists(marker) else "absent",
        not os.path.exists(marker))

def s_receipts():
    print("\n== STAGE: receipts ==")
    rs = receipts()
    rec("receipts", "proxy receipt chain non-empty",
        ">0", len(rs), len(rs) > 0)
    r = subprocess.run(["./ovara-proxy", "-config", "proxy.json", "-verify",
                        "var/receipts.jsonl", "-pubkey",
                        open(f"{WORK}/var/receipt.pubkey").read().strip()],
                       cwd=WORK, capture_output=True, text=True)
    ok = "valid=true" in r.stdout or "VALID" in r.stdout.upper()
    rec("receipts", "proxy chain verify (hash+ed25519)", "valid",
        r.stdout.strip()[:60] or r.stderr.strip()[:60], r.returncode == 0 and ok)
    # tamper: flip a byte in a receipt decision, re-verify must fail
    lines = open(f"{WORK}/var/receipts.jsonl").read().splitlines()
    last = json.loads(lines[-1])
    sig = last.get("signature") or last.get("sig") or ""
    last["signature"] = ("A" if not sig.startswith("A") else "B") + sig[1:]
    tampered = lines[:-1] + [json.dumps(last)]
    open(f"{WORK}/var/tampered.jsonl", "w").write("\n".join(tampered) + "\n")
    r2 = subprocess.run(["./ovara-proxy", "-config", "proxy.json", "-verify",
                         "var/tampered.jsonl", "-pubkey",
                         open(f"{WORK}/var/receipt.pubkey").read().strip()],
                        cwd=WORK, capture_output=True, text=True)
    rec("receipts", "tampered receipt detected", "invalid",
        (r2.stdout or r2.stderr).strip()[:60],
        "valid=false" in r2.stdout or "INVALID" in (r2.stdout+r2.stderr).upper())
    st, d = http("GET", GW + "/v1/receipts", TOKS["operator"])
    rec("receipts", "gateway receipt store queryable", "200",
        st, st == 200)

def main():
    global KEYS, TOKS, PRIN, GWID
    print(f"RC1 e2e harness — clean-room {WORK}")
    KEYS, TOKS = setup()
    PRIN = TOKS["principal"]
    signal.signal(signal.SIGINT, teardown)
    launch()
    for _ in range(20):
        try:
            GWID = json.load(open(f"{WORK}/var/data/enrollment.json"))["id"]
            break
        except Exception: time.sleep(0.3)
    print(f"principal={PRIN} gateway={GWID}")
    for stage in (s_identity, s_delegation, s_lease, s_policy,
                  s_approval, s_proxy, s_execution, s_receipts):
        try: stage()
        except Exception as e:
            rec(stage.__name__, "STAGE ERROR", "no exception", repr(e), False)
    teardown()
    passed = sum(1 for r in RESULTS if r[4])
    print(f"\n{'='*70}\nRESULT: {passed}/{len(RESULTS)} passed")
    fails = [r for r in RESULTS if not r[4]]
    for r in fails:
        print(f"  FAIL: {r[0]}/{r[1]} — want {r[2]} got {r[3]}")
    json.dump([{"stage": s, "case": c, "expected": e, "got": str(g), "ok": o}
               for s, c, e, g, o in RESULTS],
              open(f"{WORK}/results.json", "w"), indent=1)
    sys.exit(0 if not fails else 1)

if __name__ == "__main__":
    main()
