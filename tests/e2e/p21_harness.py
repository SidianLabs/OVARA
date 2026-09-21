#!/usr/bin/env python3
"""P2.1 durable replay — clean-room e2e.

Fresh gateway with replay_file configured; real signed delegation chain;
SIGKILL restart against the same state dir; identical presentation must
deny. Covers: first-allow, in-run replay deny, kill -9 restart deny,
request-nonce durability, concurrent duplicate (exactly one allow),
batch endpoint sharing the same consume domain, issuer-scoped nonce
identity.

usage: python3 tests/e2e/p21_harness.py [workdir]
"""
import base64, hashlib, importlib.util, json, os, secrets, signal, socket
import subprocess, sys, threading, time, urllib.request, urllib.error, uuid

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p21-e2e"
GW_PORT = 18570
GW = f"http://127.0.0.1:{GW_PORT}"
REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
import shutil
GO = os.environ.get("GO") or shutil.which("go") or "/usr/local/go/bin/go"

spec = importlib.util.spec_from_file_location(
    "canon", f"{REPO}/sdk/python/src/ovara_sdk/canon.py")
canon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canon)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

RESULTS = []
def rec(case, expected, got, ok):
    RESULTS.append((case, expected, got, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {case:<58} want={expected} got={got}")

def rfc(u): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(u))

def http(method, url, token=None, body=None):
    req = urllib.request.Request(url, method=method,
        data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if token: req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b"{}")
        except Exception: return e.code, {}

# ------------------------------------------------------------- clean-room
KEYS = TOKS = PRIN = None
def setup():
    os.makedirs(f"{WORK}/var/data", exist_ok=True)
    subprocess.run([GO, "build", "-o", f"{WORK}/ovara-gateway", "./cmd/server/"],
                   cwd=f"{REPO}/runtime/gateway", check=True, capture_output=True)
    keys, toks = {}, {}
    for name in ("issuer-A", "issuer-B"):
        k = Ed25519PrivateKey.generate()
        keys[name] = {"seed": k.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex(),
            "pub": k.public_key().public_bytes(serialization.Encoding.Raw,
                serialization.PublicFormat.Raw).hex()}
    toks["agent"] = "p21-agent-" + secrets.token_hex(16)
    toks["operator"] = "p21-op-" + secrets.token_hex(16)
    toks["principal"] = "ag_" + hashlib.sha256(toks["agent"].encode()).hexdigest()[:16]
    json.dump({
        "agent_tokens": [toks["agent"]], "operator_tokens": [toks["operator"]],
        "auth_enabled": True, "fail_closed": True,
        "listen_addr": "127.0.0.1", "server_port": str(GW_PORT),
        "log_level": "info", "policy_file": "policy.json",
        "policy_version": "v1-p21", "enrollment_file": "var/data/enrollment.json",
        "replay_file": "var/data/replay.jsonl",
        "trusted_issuers": {"issuer-A": keys["issuer-A"]["pub"],
                            "issuer-B": keys["issuer-B"]["pub"]},
    }, open(f"{WORK}/config.json", "w"), indent=1)
    json.dump({"version": "v1-p21", "rules": [
        {"action_type": "http.request", "environment": "local", "allow": True},
        {"action_type": "shell", "environment": "local", "escalate": True},
        {"action_type": "*", "environment": "*", "escalate": True},
    ]}, open(f"{WORK}/policy.json", "w"))
    return keys, toks

PROC = None
def launch():
    global PROC
    PROC = subprocess.Popen(["./ovara-gateway"], cwd=WORK,
        env={**os.environ, "OVARA_CONFIG": "config.json"},
        stdout=open(f"{WORK}/gw.log", "a"), stderr=subprocess.STDOUT)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", GW_PORT), 0.2).close()
            return
        except OSError: time.sleep(0.2)
    raise SystemExit("gateway did not start — see " + WORK + "/gw.log")

def kill():
    PROC.kill(); PROC.wait()

def teardown(*_):
    try: PROC.kill()
    except Exception: pass

# ------------------------------------------------------------- artifacts
def key(name):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(KEYS[name]["seed"]))

def chain(hops, issuer="issuer-A"):
    """hops: list of (subj, actions, scope, exp_unix, nonce)."""
    auths, prev = [], ""
    for subj, acts, scope, exp, nonce in hops:
        now = int(time.time())
        p = canon.hop_payload(issuer, subj, "", scope, acts,
                              int(exp), now, nonce, prev)
        sig = key(issuer).sign(p)
        prev = sig.hex()
        auths.append({"issuer": issuer, "subject_id": subj, "audience": "",
            "actions": acts, "resource_scope": scope,
            "expires_at": rfc(exp), "delegated_at": rfc(now),
            "nonce": nonce,
            "signature": base64.b64encode(sig).decode()})
    return {"authorities": auths, "depth": len(auths)}

def check(resource, action="http.request", nonce=None, chain_obj=None, tok=None):
    req = {"agent_identity": {"issuer": "ovara", "subject_id": PRIN},
           "action_type": action, "resource": resource,
           "environment": "local", "nonce": nonce or uuid.uuid4().hex,
           "issued_at": rfc(time.time())}
    if chain_obj: req["delegation_chain"] = chain_obj
    return http("POST", f"{GW}/v1/runtime/check", tok or TOKS["agent"], req)

def batch(reqs):
    return http("POST", f"{GW}/v1/runtime/batch-check", TOKS["agent"],
                {"requests": reqs})

def unrestrict():
    """Repeated denials trigger trust containment — reset so each case
    is judged on its own merits (same as the RC1 harness)."""
    http("POST", f"{GW}/v1/shield/unrestrict/{PRIN}", TOKS["operator"])

def mkreq(nonce, chain_obj=None):
    req = {"agent_identity": {"issuer": "ovara", "subject_id": PRIN},
           "action_type": "http.request", "resource": "https://ok.example.com",
           "environment": "local", "nonce": nonce,
           "issued_at": rfc(time.time())}
    if chain_obj: req["delegation_chain"] = chain_obj
    return req

# ------------------------------------------------------------------- run
def main():
    global KEYS, TOKS, PRIN
    print(f"P2.1 durable replay e2e — clean-room {WORK}")
    KEYS, TOKS = setup()
    PRIN = TOKS["principal"]
    signal.signal(signal.SIGINT, teardown)
    launch()

    exp = time.time() + 600
    c1 = chain([(PRIN, ["http.request"], "*", exp, "p21-deleg-nonce-1")])

    s, r = check("https://ok.example.com", chain_obj=c1)
    rec("first delegation presentation", "allow", r.get("decision"),
        s == 200 and r.get("decision") == "allow")

    s, r = check("https://ok.example.com", chain_obj=c1)
    rec("in-run replay (fresh request nonce)", "deny", r.get("decision"),
        r.get("decision") == "deny")

    # Concurrent duplicate presentation over HTTP — exactly one allow.
    c2 = chain([(PRIN, ["http.request"], "*", exp, "p21-deleg-nonce-2")])
    nonce2 = uuid.uuid4().hex
    outs = []
    def one(i):
        s_, r_ = check("https://ok.example.com", chain_obj=c2,
                       nonce=f"{nonce2}-{i}")
        outs.append(r_.get("decision"))
    ts = [threading.Thread(target=one, args=(i,)) for i in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    # At most one authorization — other outcomes (deny/escalate) are
    # both non-authorizing; only "allow" counts against the property.
    rec("8 concurrent same-chain presentations → ≤1 allow",
        "1 allow", f"{outs}",
        outs.count("allow") == 1)

    # Batch endpoint consumes the SAME replay domain.
    unrestrict()
    c3 = chain([(PRIN, ["http.request"], "*", exp, "p21-deleg-nonce-3")])
    s, r = check("https://ok.example.com", chain_obj=c3)
    s, r = batch([mkreq(uuid.uuid4().hex, c3)])
    d = (r.get("decisions") or [{}])[0].get("decision")
    rec("batch-check replay of consumed chain", "deny", d, d == "deny")

    # Request nonce replay after kill -9 restart.
    kill()
    launch()
    s, r = check("https://ok.example.com", chain_obj=c1)
    rec("delegation replay after SIGKILL restart", "deny", r.get("decision"),
        r.get("decision") == "deny")

    n1 = uuid.uuid4().hex
    s, r = check("https://ok.example.com", nonce=n1)
    kill(); launch()
    s, r = check("https://ok.example.com", nonce=n1)
    rec("request nonce replay after SIGKILL restart", "deny", r.get("decision"),
        r.get("decision") == "deny")

    # Issuer-scoped: same nonce from issuer-B is a different replay id.
    c4 = chain([(PRIN, ["http.request"], "*", exp, "p21-deleg-nonce-1")],
               issuer="issuer-B")
    s, r = check("https://ok.example.com", chain_obj=c4)
    rec("same nonce different issuer → distinct replay id", "allow",
        r.get("decision"), s == 200 and r.get("decision") == "allow")

    teardown()
    ok = sum(1 for x in RESULTS if x[3])
    print(f"\n{'='*70}\nRESULT: {ok}/{len(RESULTS)} passed")
    for case, e, g, o in RESULTS:
        if not o: print(f"  FAIL: {case} — want {e} got {g}")
    sys.exit(0 if ok == len(RESULTS) else 1)

if __name__ == "__main__":
    main()
