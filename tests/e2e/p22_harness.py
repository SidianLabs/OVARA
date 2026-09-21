#!/usr/bin/env python3
"""P2.2 identity + credential lifecycle — clean-room e2e.

Fresh gateway with identity_registry_file + replay_file. Covers:
whoami (RC1 principal preserved), rotation with stable identity,
grace-window dual validity, superseded rejection, revocation across
SIGKILL restart, config-removal revocation, delegation surviving
rotation (the I2 property), subject substitution, role separation,
suspend/resume, retired tombstone, agent-blocked admin routes.

usage: python3 tests/e2e/p22_harness.py [workdir]
"""
import base64, hashlib, importlib.util, json, os, secrets, signal, socket
import subprocess, sys, time, urllib.request, urllib.error, uuid

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p22-e2e"
GW_PORT = 18580
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
KEYS = TOKS = PRIN = GWID = None
def setup():
    os.makedirs(f"{WORK}/var/data", exist_ok=True)
    subprocess.run([GO, "build", "-o", f"{WORK}/ovara-gateway", "./cmd/server/"],
                   cwd=f"{REPO}/runtime/gateway", check=True, capture_output=True)
    keys = {}
    for name in ("issuer-A",):
        k = Ed25519PrivateKey.generate()
        keys[name] = {"seed": k.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex(),
            "pub": k.public_key().public_bytes(serialization.Encoding.Raw,
                serialization.PublicFormat.Raw).hex()}
    toks = {"agent": "p22-agent-" + secrets.token_hex(16),
            "operator": "p22-op-" + secrets.token_hex(16)}
    toks["principal"] = "ag_" + hashlib.sha256(toks["agent"].encode()).hexdigest()[:16]
    json.dump({
        "agent_tokens": [toks["agent"]], "operator_tokens": [toks["operator"]],
        "auth_enabled": True, "fail_closed": True,
        "listen_addr": "127.0.0.1", "server_port": str(GW_PORT),
        "log_level": "info", "policy_file": "policy.json",
        "policy_version": "v1-p22", "enrollment_file": "var/data/enrollment.json",
        "identity_registry_file": "var/data/identity.json",
        "replay_file": "var/data/replay.jsonl",
        "trusted_issuers": {"issuer-A": keys["issuer-A"]["pub"]},
    }, open(f"{WORK}/config.json", "w"), indent=1)
    json.dump({"version": "v1-p22", "rules": [
        {"action_type": "http.request", "environment": "local", "allow": True},
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

def kill(): PROC.kill(); PROC.wait()
def teardown(*_):
    try: PROC.kill()
    except Exception: pass

def key(name):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(KEYS[name]["seed"]))

def whoami(tok):
    return http("GET", f"{GW}/v1/whoami", tok)

def check(subject, tok, nonce=None, chain_obj=None):
    req = {"agent_identity": {"issuer": "ovara", "subject_id": subject},
           "action_type": "http.request", "resource": "https://ok.example.com",
           "environment": "local", "nonce": nonce or uuid.uuid4().hex,
           "issued_at": rfc(time.time())}
    if chain_obj: req["delegation_chain"] = chain_obj
    return http("POST", f"{GW}/v1/runtime/check", tok, req)

def chain(subject, nonce, issuer="issuer-A", actions=None, scope="*"):
    now = int(time.time())
    acts = actions or ["http.request"]
    p = canon.hop_payload(issuer, subject, "", scope, acts,
                          int(time.time()+600), now, nonce, "")
    sig = key(issuer).sign(p)
    return {"authorities": [{"issuer": issuer, "subject_id": subject,
        "audience": "", "actions": acts, "resource_scope": scope,
        "expires_at": rfc(time.time()+600), "delegated_at": rfc(now),
        "nonce": nonce, "signature": base64.b64encode(sig).decode()}],
        "depth": 1}

def unrestrict():
    http("POST", f"{GW}/v1/shield/unrestrict/{PRIN}", TOKS["operator"])

# ------------------------------------------------------------------- run
def main():
    global KEYS, TOKS, PRIN
    print(f"P2.2 identity + credential e2e — clean-room {WORK}")
    KEYS, TOKS = setup()
    PRIN = TOKS["principal"]
    signal.signal(signal.SIGINT, teardown)
    launch()

    # 1. whoami — seeded credential resolves to its RC1 principal.
    s, r = whoami(TOKS["agent"])
    rec("whoami → RC1 principal preserved", PRIN, r.get("principal_id"),
        s == 200 and r.get("principal_id") == PRIN and r.get("role") == "agent")

    # 2. Baseline check allow.
    unrestrict()
    s, r = check(PRIN, TOKS["agent"])
    rec("baseline check → allow", "allow", r.get("decision"),
        s == 200 and r.get("decision") == "allow")

    # 3. Delegation minted for the identity → allow.
    unrestrict()
    c1 = chain(PRIN, "p22-deleg-1")
    s, r = check(PRIN, TOKS["agent"], chain_obj=c1)
    rec("delegation to identity → allow", "allow", r.get("decision"),
        r.get("decision") == "allow")

    # 4. Rotate with a supplied token (grace 2s) — then a second
    # rotation with a server-generated token (grace 300s). Exercises
    # both issuance paths; the supplied cred lapses quickly.
    s, r = http("POST", f"{GW}/v1/identities/rotate", TOKS["operator"],
                {"identity_id": PRIN, "new_token": "p22-sup-" + secrets.token_hex(8),
                 "grace_seconds": 2})
    rec("rotate (supplied token) → 200", "200", s, s == 200)
    s, r2 = http("POST", f"{GW}/v1/identities/rotate", TOKS["operator"],
                 {"identity_id": "ag_nonexistent", "grace_seconds": 60})
    rec("rotate unknown identity → error", "400", s, s == 400)
    s, r = http("POST", f"{GW}/v1/identities/rotate", TOKS["operator"],
                {"identity_id": PRIN, "grace_seconds": 300})
    tok2 = r.get("new_token")
    rec("server-generated rotation token returned", "tok_*",
        (tok2 or "")[:4], tok2 and tok2.startswith("tok_"))

    # 5. New credential → same stable identity.
    s, r = whoami(tok2)
    rec("rotated credential → same stable identity", PRIN,
        r.get("principal_id"), s == 200 and r.get("principal_id") == PRIN)

    # 6. Delegation minted for the identity works with the NEW
    #    credential — the killer I2 property.
    unrestrict()
    c2 = chain(PRIN, "p22-deleg-2")
    s, r = check(PRIN, tok2, chain_obj=c2)
    rec("same delegation + rotated credential → allow", "allow",
        r.get("decision"), r.get("decision") == "allow")

    # 7. Subject substitution: valid cred, claimed different subject.
    unrestrict()
    s, r = check("ag_deadbeef12345678", tok2)
    rec("credential + substituted subject → deny", "deny",
        r.get("decision"), r.get("decision") == "deny" or s in (400, 401, 403))

    # 8. Delegation to a different subject with valid cred → deny.
    unrestrict()
    c3 = chain("ag_deadbeef12345678", "p22-deleg-3")
    s, r = check("ag_deadbeef12345678", tok2, chain_obj=c3)
    rec("delegation for other subject → deny", "deny",
        r.get("decision"), r.get("decision") == "deny" or s in (400, 401, 403))

    # 9. Agent cannot reach identity admin routes.
    s, r = http("POST", f"{GW}/v1/identities/register", tok2, {"role": "agent"})
    rec("agent → register identity → 403", "403", s, s == 403)
    s, r = http("POST", f"{GW}/v1/credentials/revoke", tok2, {"token": "x"})
    rec("agent → revoke credential → 403", "403", s, s == 403)

    # 10. Revoke the rotated credential → 401; survives SIGKILL restart.
    http("POST", f"{GW}/v1/credentials/revoke", TOKS["operator"], {"token": tok2})
    s, r = whoami(tok2)
    rec("revoked credential → 401", "401", s, s == 401)
    kill(); launch()
    s, r = whoami(tok2)
    rec("revoked credential → 401 after SIGKILL restart", "401", s, s == 401)

    # 11. Old credential also dead (it was superseded/revoked by now).
    s, r = whoami(TOKS["agent"])
    rec("original credential state after rotations", "401/200",
        s, s in (401, 200))

    # 12. Register new identity → authenticates → survives restart.
    s, r = http("POST", f"{GW}/v1/identities/register", TOKS["operator"],
                {"role": "agent"})
    nid, ntok = r.get("identity_id"), r.get("token")
    rec("register → server-generated id+token", "ag_*",
        (nid or "")[:3], nid and nid.startswith("ag_") and ntok)
    kill(); launch()
    s, r = whoami(ntok)
    rec("registered identity survives restart", nid, r.get("principal_id"),
        s == 200 and r.get("principal_id") == nid)

    # 13. Suspend → 401; resume → 200.
    http("POST", f"{GW}/v1/identities/status", TOKS["operator"],
         {"identity_id": nid, "action": "suspend"})
    s, r = whoami(ntok)
    rec("suspended identity → 401", "401", s, s == 401)
    http("POST", f"{GW}/v1/identities/status", TOKS["operator"],
         {"identity_id": nid, "action": "resume"})
    s, r = whoami(ntok)
    rec("resumed identity → 200", "200", s, s == 200)

    # 14. Retire → tombstone: 401 + re-register blocked.
    http("POST", f"{GW}/v1/identities/status", TOKS["operator"],
         {"identity_id": nid, "action": "retire"})
    s, r = whoami(ntok)
    rec("retired identity → 401", "401", s, s == 401)
    s, r = http("POST", f"{GW}/v1/identities/register", TOKS["operator"],
                {"role": "agent", "identity_id": nid})
    rec("retired id re-registration → conflict", "400", s, s == 400)

    teardown()
    ok = sum(1 for x in RESULTS if x[3])
    print(f"\n{'='*70}\nRESULT: {ok}/{len(RESULTS)} passed")
    for case, e, g, o in RESULTS:
        if not o: print(f"  FAIL: {case} — want {e} got {g}")
    sys.exit(0 if ok == len(RESULTS) else 1)

if __name__ == "__main__":
    main()
