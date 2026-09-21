#!/usr/bin/env python3
"""P2.2 conditional-review gate — authority semantics + adversarial pass.

Verifies the exact revocation boundary across every authorization object:

  credential revocation  → kills that credential only (identity-level objects
                           remain usable by OTHER live credentials of the same
                           identity — the documented model)
  identity suspension    → kills authentication + queued/direct execution
  identity retirement    → tombstone: permanent, survives SIGKILL restart
  stolen credential      → revoked cred dead; containment requires identity
                           suspension or per-object lease revocation

Real gateway, real persisted registry, SIGKILL restarts. Clean-room.

usage: python3 tests/e2e/p22_gate_harness.py [workdir]
"""
import base64, hashlib, importlib.util, json, os, secrets, signal, socket
import subprocess, sys, time, urllib.request, urllib.error, uuid

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p22-gate"
GW_PORT = 18581
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
    toks = {"agent": "p22g-agent-" + secrets.token_hex(16),
            "operator": "p22g-op-" + secrets.token_hex(16)}
    toks["principal"] = "ag_" + hashlib.sha256(toks["agent"].encode()).hexdigest()[:16]
    json.dump({
        "agent_tokens": [toks["agent"]], "operator_tokens": [toks["operator"]],
        "auth_enabled": True, "fail_closed": True,
        "listen_addr": "127.0.0.1", "server_port": str(GW_PORT),
        "log_level": "info", "policy_file": "policy.json",
        "policy_version": "v1-p22g", "enrollment_file": "var/data/enrollment.json",
        "identity_registry_file": "var/data/identity.json",
        "replay_file": "var/data/replay.jsonl",
        "enable_host_executors": True,
        "trusted_issuers": {"issuer-A": keys["issuer-A"]["pub"]},
    }, open(f"{WORK}/config.json", "w"), indent=1)
    json.dump({"version": "v1-p22g", "rules": [
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

def check(subject, tok, nonce=None, chain_obj=None, lease_obj=None,
          action="http.request", resource="https://ok.example.com"):
    req = {"agent_identity": {"issuer": "ovara", "subject_id": subject},
           "action_type": action, "resource": resource,
           "environment": "local", "nonce": nonce or uuid.uuid4().hex,
           "issued_at": rfc(time.time())}
    if chain_obj: req["delegation_chain"] = chain_obj
    if lease_obj: req["capability_lease"] = lease_obj
    return http("POST", f"{GW}/v1/runtime/check", tok, req)

def chain(subject, nonce, issuer="issuer-A", actions=None, scope="*"):
    now = int(time.time())
    acts = actions or ["http.request"]
    p = canon.hop_payload(issuer, subject, "", scope, acts,
                          now + 600, now, nonce, "")
    sig = key(issuer).sign(p)
    return {"authorities": [{"issuer": issuer, "subject_id": subject,
        "audience": "", "actions": acts, "resource_scope": scope,
        "expires_at": rfc(now + 600), "delegated_at": rfc(now),
        "nonce": nonce, "signature": base64.b64encode(sig).decode()}],
        "depth": 1}

def lease(subject, lease_id, aud=None, issuer="issuer-A"):
    now = int(time.time()); exp = now + 3600
    p = canon.lease_payload(lease_id, issuer, subject, aud or GWID,
                            ["http.request"], "*", exp, now, 0)
    sig = key(issuer).sign(p)
    return {"lease_id": lease_id, "issuer": issuer, "subject": subject,
            "allowed_actions": ["http.request"], "resource_scope": "*",
            "expiry": rfc(exp), "delegation_depth": 0,
            "issued_at": rfc(now), "audience": aud or GWID,
            "signature": base64.b64encode(sig).decode()}

def unrestrict(prin):
    http("POST", f"{GW}/v1/shield/unrestrict/{prin}", TOKS["operator"])

def status(prin):
    http("POST", f"{GW}/v1/identities/status", TOKS["operator"],
         {"identity_id": prin, "action": "suspend"})

def transition(prin, action):
    return http("POST", f"{GW}/v1/identities/status", TOKS["operator"],
                {"identity_id": prin, "action": action})

def continuations():
    s, r = http("GET", f"{GW}/v1/continuations", TOKS["operator"])
    items = r.get("continuations") or r.get("items") or []
    return items

def marker_path(name): return f"{WORK}/exec/{name}"

def approve_flow(tok, marker):
    """escalate → create → approve → returns (approval_id, continuation_id)."""
    os.makedirs(f"{WORK}/exec", exist_ok=True)
    if os.path.exists(marker): os.remove(marker)
    s, d = check(PRIN, tok, action="shell",
                 resource=f"shell:echo ran > {marker}")
    if d.get("decision") != "escalate":
        return None, None, f"expected escalate got {d.get('decision')} ({s})"
    s, ap = http("POST", f"{GW}/v1/approval/create", tok,
                 {"decision_id": d.get("decision_id")})
    if s != 201:
        return None, None, f"approval create {s}"
    return ap.get("approval_id"), None, None

def find_continuation(approval_id):
    for c in continuations():
        if c.get("approval_id") == approval_id:
            return c.get("continuation_id") or c.get("id")
    return None

# ------------------------------------------------------------------- run
def main():
    global KEYS, TOKS, PRIN, GWID
    print(f"P2.2 AUTHORITY GATE e2e — clean-room {WORK}")
    KEYS, TOKS = setup()
    PRIN = TOKS["principal"]
    signal.signal(signal.SIGINT, teardown)
    launch()
    GWID = json.load(open(f"{WORK}/var/data/enrollment.json"))["id"]
    print(f"identity={PRIN} gateway={GWID}")

    OP = TOKS["operator"]
    C1 = TOKS["agent"]

    # ── Phase A: two credentials for ID-A (rotating grace = dual validity)
    s, r = http("POST", f"{GW}/v1/identities/rotate", OP,
                {"identity_id": PRIN, "grace_seconds": 3600})
    C2 = r.get("new_token")
    s, r = whoami(C1)
    rec("A1 rotating cred authenticates in grace", PRIN, r.get("principal_id"),
        s == 200 and r.get("principal_id") == PRIN)
    s, r = whoami(C2)
    rec("A2 new cred → same identity", PRIN, r.get("principal_id"),
        s == 200 and r.get("principal_id") == PRIN)

    # ── Phase B: attacker (C1) builds identity-bound authorization objects
    D1 = chain(PRIN, "d1-" + uuid.uuid4().hex[:8])
    s, d = check(PRIN, C1, chain_obj=D1)
    rec("B1 C1 + delegation D1 → allow", "allow", d.get("decision"),
        d.get("decision") == "allow")
    L1 = lease(PRIN, "lease-gate-1")
    s, d = check(PRIN, C1, lease_obj=L1)
    rec("B2 C1 + lease L1 → allow", "allow", d.get("decision"),
        d.get("decision") == "allow")
    m1 = marker_path("m1")
    AP1, _, err = approve_flow(C1, m1)
    rec("B3 C1 creates approval AP1 (escalation pending)", "201",
        err or "201", AP1 is not None)

    # ── Phase C: operator revokes the stolen credential C1
    s, r = http("POST", f"{GW}/v1/credentials/revoke", OP, {"token": C1})
    rec("C0 revoke C1 → 200", "200", s, s == 200)
    s, r = whoami(C1)
    rec("C1 revoked cred → 401", "401", s, s == 401)
    s, d = check(PRIN, C1, chain_obj=D1)
    rec("C2 revoked C1 + D1 → 401", "401", s, s == 401)
    s, r = whoami(C2)
    rec("C3 C2 still authenticates", PRIN, r.get("principal_id"),
        s == 200 and r.get("principal_id") == PRIN)

    # Identity-level objects: usable by OTHER live credential of ID-A.
    # (Re-presenting the SAME signed D1 is consumed by P2.1 replay —
    # assert that explicitly, then use a fresh presentation D2.)
    s, d = check(PRIN, C2, chain_obj=D1, nonce=uuid.uuid4().hex)
    rec("C4a C2 re-presenting consumed D1 → deny (P2.1 replay)", "deny",
        d.get("decision"), d.get("decision") == "deny")
    D2 = chain(PRIN, "d2-" + uuid.uuid4().hex[:8])
    s, d = check(PRIN, C2, chain_obj=D2)
    rec("C4b C2 + fresh delegation D2 → allow", "allow", d.get("decision"),
        d.get("decision") == "allow")
    s, d = check(PRIN, C2, lease_obj=L1)
    rec("C5 C2 + same L1 → allow", "allow", d.get("decision"),
        d.get("decision") == "allow")
    s, _ = http("POST", f"{GW}/v1/approval/{AP1}/approve", OP, {})
    time.sleep(3.5)  # orchestrator poll → executes for ID-A
    ran = os.path.exists(m1)
    rec("C6 approval AP1 executes under live identity",
        "marker", "exists" if ran else "absent", ran)

    # ── Phase D: suspension kills the identity (all creds, all objects)
    transition(PRIN, "suspend")
    s, r = whoami(C1); s2, r2 = whoami(C2)
    rec("D1 suspended: C1 401 + C2 401", "401+401", f"{s}+{s2}",
        s == 401 and s2 == 401)
    s, d = check(PRIN, C2, chain_obj=chain(PRIN, "d2-" + uuid.uuid4().hex[:8]))
    rec("D2 suspended: fresh delegation unusable", "401", s, s == 401)
    s, d = check(PRIN, C2, lease_obj=L1)
    rec("D3 suspended: lease unusable", "401", s, s == 401)

    # Queue work while suspended: C2 can't auth → use pre-suspension path?
    # An operator-approved continuation created NOW queues for ID-A and
    # must sit unexecuted while ID-A is suspended.
    s, d = check(PRIN, C2, action="shell",
                 resource=f"shell:echo ran > {marker_path('m2')}")
    rec("D4 suspended: escalation request → 401 (auth boundary)", "401",
        s, s == 401)

    # Create the queued work BEFORE suspend is impossible here — instead:
    # resume briefly to mint a pending approval, re-suspend, approve it.
    transition(PRIN, "resume")
    m2 = marker_path("m2")
    AP2, _, err = approve_flow(C2, m2)
    rec("D5 resumed: C2 creates approval AP2", "201", err or "201",
        AP2 is not None)
    transition(PRIN, "suspend")
    s, _ = http("POST", f"{GW}/v1/approval/{AP2}/approve", OP, {})
    time.sleep(3.5)
    ran = os.path.exists(m2)
    rec("D6 suspended: approved continuation does NOT execute",
        "no marker", "exists" if ran else "absent", not ran)
    cid2 = find_continuation(AP2)
    if cid2:
        s, r = http("POST", f"{GW}/v1/continuations/{cid2}/execute", OP, {})
        rec("D7 suspended: direct execute endpoint → 409 requeue", "409",
            s, s == 409)
    else:
        rec("D7 suspended: direct execute endpoint → 409 requeue",
            "409", "no continuation found", False)
    time.sleep(3.5)
    ran = os.path.exists(m2)
    rec("D8 suspended: still not executed after execute attempt",
        "no marker", "exists" if ran else "absent", not ran)

    # Resume → queued work becomes claimable again.
    transition(PRIN, "resume")
    s, r = whoami(C2)
    rec("D9 resumed: C2 authenticates", "200", s, s == 200)
    for _ in range(12):
        if os.path.exists(m2): break
        time.sleep(0.5)
    ran = os.path.exists(m2)
    rec("D10 resumed: queued continuation executes", "marker",
        "exists" if ran else "absent", ran)

    # ── Phase E: retirement tombstone
    m3 = marker_path("m3")
    AP3, _, err = approve_flow(C2, m3)
    transition(PRIN, "retire")
    s, _ = http("POST", f"{GW}/v1/approval/{AP3}/approve", OP, {})
    time.sleep(3.5)
    ran = os.path.exists(m3)
    rec("E1 retired: approved work never executes", "no marker",
        "exists" if ran else "absent", not ran)
    s, r = whoami(C2)
    rec("E2 retired: C2 → 401", "401", s, s == 401)
    s, r = http("POST", f"{GW}/v1/identities/rotate", OP,
                {"identity_id": PRIN})
    rec("E3 retired: rotation refused", "400", s, s == 400)
    s, r = http("POST", f"{GW}/v1/identities/register", OP,
                {"role": "agent", "identity_id": PRIN})
    rec("E4 retired: re-registration refused", "400", s, s == 400)
    # Direct-execute attempt while the in-memory continuation exists
    # (pre-restart) — must requeue, not run.
    cid3 = find_continuation(AP3)
    if cid3:
        s, r = http("POST", f"{GW}/v1/continuations/{cid3}/execute", OP, {})
        rec("E5a retired: direct execute → 409 requeue", "409", s, s == 409)
    else:
        rec("E5a retired: direct execute → 409 requeue", "409",
            "no continuation", False)
    kill(); launch()  # SIGKILL — tombstone must survive
    GWID = json.load(open(f"{WORK}/var/data/enrollment.json"))["id"]
    s, r = whoami(C2)
    rec("E5b retired survives SIGKILL restart: 401", "401", s, s == 401)
    # Continuation store is in-memory (RC1 default): queued work is gone
    # after restart — the tombstone property is what must persist.
    time.sleep(3.5)
    ran = os.path.exists(m3)
    rec("E6 retired: work permanently non-executable", "no marker",
        "exists" if ran else "absent", not ran)

    # ── Phase F: rotation + revocation combinations on fresh identity
    s, r = http("POST", f"{GW}/v1/identities/register", OP,
                {"role": "agent"})
    B_ID, B_C1 = r.get("identity_id"), r.get("token")
    s, r = http("POST", f"{GW}/v1/identities/rotate", OP,
                {"identity_id": B_ID, "grace_seconds": 3600})
    B_C2 = r.get("new_token")
    s, r = http("POST", f"{GW}/v1/credentials/revoke", OP, {"token": B_C1})
    s, r = whoami(B_C1)
    rec("F1 revoke rotating cred in grace → immediate 401", "401", s, s == 401)
    s, r = whoami(B_C2)
    rec("F2 new cred unaffected by old revoke", "200", s, s == 200)
    s, r = http("POST", f"{GW}/v1/credentials/revoke", OP, {"token": B_C2})
    s, r = whoami(B_C1); s2, r2 = whoami(B_C2)
    rec("F3 both creds revoked → 401+401", "401+401", f"{s}+{s2}",
        s == 401 and s2 == 401)
    # Identity still ACTIVE with zero live creds: objects would be usable
    # only if a cred existed — operator recovery = rotate in a new cred.
    s, r = http("POST", f"{GW}/v1/identities/rotate", OP,
                {"identity_id": B_ID, "grace_seconds": 0})
    B_C3 = r.get("new_token")
    s, r = whoami(B_C3)
    rec("F4 rotate dead-cred identity → recovery cred works", "200",
        s, s == 200 and B_C3 is not None)

    # ── Phase G: revocation/suspension survive restarts
    kill(); launch()
    s, r = whoami(B_C2)
    rec("G1 revoked cred still 401 after SIGKILL restart", "401", s, s == 401)
    s, r = whoami(B_C3)
    rec("G2 post-restart recovery cred authenticates", "200", s, s == 200)
    transition(B_ID, "suspend")
    kill(); launch()
    s, r = whoami(B_C3)
    rec("G3 suspension survives SIGKILL restart", "401", s, s == 401)

    teardown()
    ok = sum(1 for x in RESULTS if x[3])
    print(f"\n{'='*70}\nRESULT: {ok}/{len(RESULTS)} passed")
    for case, e, g, o in RESULTS:
        if not o: print(f"  FAIL {case}: want={e} got={g}")
    sys.exit(0 if ok == len(RESULTS) else 1)

if __name__ == "__main__":
    main()
