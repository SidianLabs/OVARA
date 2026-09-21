#!/usr/bin/env python3
"""P2.3.4 revocation boundary — clean-room e2e.

Real binaries: ovara-gateway + ovara-gwctl. Real signed artifacts:
capability leases and delegation chains minted with ed25519 over the
canonical lp() payloads (sdk canon.py ⇔ internal/identity/canon.go).

Covers the required adversarial matrix:

  issuer      active→allow, revoked→deny (lease + chain paths),
              multi-hop descendant kill, unrelated issuer survives
  delegation  presentation-key revoke → deny; sibling survives;
              revoked-unconsumed → deny
  lease       active→allow, revoked→deny at eval AND at claim-time;
              never-tracked lease is still killable
  claim-time  approval→approve→revoke→claim → denied, no execution
              record, terminal state; positive claim executes
  epoch       durable + monotonic; min_epoch gate; receipt trust_epoch
  storage     corrupt journal → gateway refuses boot; SIGKILL →
              revocation survives; unanchored rollback = file is
              authority (documented bound: anchor required to detect)
  authority   agent token cannot revoke (403, both routes); gwctl is
              the operator file path

usage: python3 tests/e2e/p234_harness.py [workdir]
"""
import base64, hashlib, importlib.util, json, os, secrets, shutil, signal
import socket, subprocess, sys, time, urllib.request, urllib.error, uuid

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p234-e2e"
REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
GO = os.environ.get("GO") or shutil.which("go") or "/usr/local/go/bin/go"
AGENT = "p234-agent-" + secrets.token_hex(8)
OP = "p234-op-" + secrets.token_hex(8)
PRIN = "ag_" + hashlib.sha256(AGENT.encode()).hexdigest()[:16]
BASE_PORT = 19750

spec = importlib.util.spec_from_file_location(
    "canon", f"{REPO}/sdk/python/src/ovara_sdk/canon.py")
canon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canon)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

RESULTS = []
def rec(case, expected, got, ok):
    RESULTS.append((case, expected, got, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {case:<62} want={expected} got={got}")

def rfc(u): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(u))

def gen_key():
    k = Ed25519PrivateKey.generate()
    return (k.private_bytes(serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption()).hex(),
            k.public_key().public_bytes(serialization.Encoding.Raw,
                serialization.PublicFormat.Raw).hex())

def sign(seed_hex, payload):
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return base64.b64encode(k.sign(payload)).decode()

def pkey(issuer, nonce):
    return hashlib.sha256(canon._lp(issuer) + canon._lp(nonce)).hexdigest()

def mint_lease(seed, issuer, subject, lease_id, aud):
    """aud must be the gateway's enrollment id — the validator binds
    lease.audience to THIS gateway unconditionally."""
    now = int(time.time())
    payload = canon.lease_payload(lease_id, issuer, subject, aud,
        ["shell", "git.push"], "*", now + 3600, now, 0)
    return {"lease_id": lease_id, "issuer": issuer, "subject": subject,
            "allowed_actions": ["shell", "git.push"], "resource_scope": "*",
            "expiry": rfc(now + 3600), "issued_at": rfc(now),
            "audience": aud,
            "delegation_depth": 0, "signature": sign(seed, payload)}

def mint_chain(seeds, hops):
    """hops: [(issuer, subject, nonce)] → chain dict (b64 sigs)."""
    auths, prev = [], ""
    for iss, sub, nonce in hops:
        now = int(time.time())
        payload = canon.hop_payload(iss, sub, "", "*",
            ["shell", "git.push"], now + 3600, now, nonce, prev)
        sig = sign(seeds[iss], payload)
        auths.append({"issuer": iss, "subject_id": sub, "audience": "",
            "actions": ["shell", "git.push"], "resource_scope": "*",
            "expires_at": rfc(now + 3600), "delegated_at": rfc(now),
            "nonce": nonce, "signature": sig})
        prev = "".join(f"{b:02x}" for b in base64.b64decode(sig))
    return {"authorities": auths, "depth": len(auths)}

# ── infra ────────────────────────────────────────────────────────────
def build():
    os.makedirs(WORK, exist_ok=True)
    for out, pkg in (("ovara-gateway", "./cmd/server/"),
                     ("ovara-gwctl", "./cmd/gwctl/")):
        subprocess.run([GO, "build", "-o", f"{WORK}/{out}", pkg],
                       cwd=f"{REPO}/runtime/gateway", check=True,
                       capture_output=True)

def write_config(d, port, trusted):
    os.makedirs(f"{d}/var/data", exist_ok=True)
    json.dump({
        "agent_tokens": [AGENT], "operator_tokens": [OP],
        "auth_enabled": True, "fail_closed": True,
        "listen_addr": "127.0.0.1", "server_port": str(port),
        "log_level": "info", "policy_file": "policy.json",
        "enrollment_file": "var/data/enrollment.json",
        "identity_registry_file": "var/data/identity.json",
        "replay_file": "var/data/replay.jsonl",
        "gateway_registry_file": "var/data/gwreg.jsonl",
        "gateway_key_file": "var/data/gateway_key",
        "gateway_require_admission": True,
        "enable_host_executors": True,
        "trusted_issuers": trusted,
        "continuations_file": "var/data/continuations.jsonl",
        "approvals_file": "var/data/approvals.jsonl",
        "execution_file": "var/data/executions.jsonl",
    }, open(f"{d}/config.json", "w"), indent=1)
    json.dump({"version": "v1", "rules": [
        {"action_type": "shell", "environment": "local", "allow": True},
        {"action_type": "*", "environment": "*", "escalate": True},
    ]}, open(f"{d}/policy.json", "w"))

PROCS = []
def kill_all():
    for p in PROCS:
        try: p.kill(); p.wait()
        except Exception: pass

def launch(d, expect_fail=False):
    port = int(json.load(open(f"{d}/config.json"))["server_port"])
    proc = subprocess.Popen(["../ovara-gateway"], cwd=d,
        env={**os.environ, "OVARA_CONFIG": "config.json"},
        stdout=open(f"{d}/gw.log", "a"), stderr=subprocess.STDOUT)
    if expect_fail:
        try: proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait(); return proc, False
        return proc, True
    for _ in range(60):
        if proc.poll() is not None: return proc, False
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return proc, True
        except OSError: time.sleep(0.2)
    proc.kill(); proc.wait(); return proc, False

def gwctl(d, *args):
    return subprocess.run([f"{WORK}/ovara-gwctl", *args, "--registry",
        os.path.abspath(f"{d}/var/data/gwreg.jsonl")],
        capture_output=True, text=True)

def gw_id(d):
    return json.load(open(f"{d}/var/data/enrollment.json"))["id"]

def req(port, method, path, body=None, token=OP):
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b"{}")
        except Exception: return e.code, {}

def check(port, body, token=AGENT):
    # Shield auto-restricts a principal after 3 non-allow decisions —
    # intentional denies in this harness would poison every later check.
    unrestrict(port)
    body.setdefault("nonce", uuid.uuid4().hex)
    body.setdefault("issued_at", rfc(time.time()))
    body.setdefault("environment", "local")
    body["agent_identity"] = {"issuer": "ovara", "subject_id": PRIN}
    return req(port, "POST", "/v1/runtime/check", body, token)

def reg_path(d): return f"{d}/var/data/gwreg.jsonl"
def reg_lines(d):
    if not os.path.exists(reg_path(d)): return []
    return [l for l in open(reg_path(d)).read().splitlines() if l.strip()]

def epoch(d):
    r = gwctl(d, "epoch")
    return int(r.stdout.split("epoch:")[1].split()[0])

def unrestrict(port):
    req(port, "POST", f"/v1/shield/unrestrict/{PRIN}")

def main():
    print(f"P2.3.4 revocation boundary e2e — clean-room {WORK}")
    signal.signal(signal.SIGINT, lambda *_: (kill_all(), sys.exit(1)))
    build()
    port = BASE_PORT

    seeds, trusted = {}, {}
    for name in ("lease-iss", "root", "mid", "x-iss", "y-iss"):
        seeds[name], trusted[name] = gen_key()

    d = f"{WORK}/a"
    write_config(d, port, trusted)
    P = port; port += 1

    launch(d, expect_fail=True)               # enrollment probe
    gwctl(d, "grant", "--gateway-id", gw_id(d))
    p, ok = launch(d); PROCS.append(p)
    unrestrict(P)
    GWA = gw_id(d)   # lease audience binds to this gateway id
    rec("gateway boots (registry + revocation boundary)", "running",
        "running" if ok else "dead", ok)
    ep0 = epoch(d)
    rec("revocation epoch live", ">0", ep0, ep0 > 0)

    # ── LEASE boundary ───────────────────────────────────────────────
    lease1 = mint_lease(seeds["lease-iss"], "lease-iss", PRIN, "lse-1", GWA)
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "capability_lease": lease1})
    rec("L1: valid lease → allow", "allow", b.get("decision"),
        st == 200 and b.get("decision") == "allow")
    rec("  receipt carries trust_epoch", ep0,
        (b.get("receipt_stub") or {}).get("trust_epoch"),
        (b.get("receipt_stub") or {}).get("trust_epoch") == ep0)

    st, b = req(P, "POST", "/v1/revocations",
                {"class": "lease", "target": "lse-1", "reason": "x"})
    rec("operator lease revoke (HTTP)", "200+epoch",
        f"{st} ep={b.get('epoch')}", st == 200 and b.get("epoch", 0) > 0)
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "capability_lease": lease1})
    rec("L2: revoked lease → deny at eval", "deny", b.get("decision"),
        b.get("decision") == "deny")

    # never-tracked lease is still killable
    lease2 = mint_lease(seeds["lease-iss"], "lease-iss", PRIN, "lse-2", GWA)
    req(P, "POST", "/v1/revocations", {"class": "lease", "target": "lse-2"})
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "capability_lease": lease2})
    rec("L3: revoked-never-tracked lease → deny", "deny",
        b.get("decision"), b.get("decision") == "deny")

    # ── ISSUER revocation via gwctl (operator file path) ─────────────
    lease3 = mint_lease(seeds["lease-iss"], "lease-iss", PRIN, "lse-3", GWA)
    r = gwctl(d, "revoke", "--class", "issuer", "--target", "lease-iss",
              "--reason", "key-compromise")
    rec("gwctl issuer revoke", "rc=0", r.returncode, r.returncode == 0)
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "capability_lease": lease3})
    rec("I1: lease from revoked issuer → deny", "deny",
        b.get("decision"), b.get("decision") == "deny")
    lease4 = mint_lease(seeds["lease-iss"], "lease-iss", PRIN, "lse-4", GWA)
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "capability_lease": lease4})
    rec("I2: fresh lease from revoked issuer → deny", "deny",
        b.get("decision"), b.get("decision") == "deny")

    # ── DELEGATION granularity + multi-hop ───────────────────────────
    chainC = mint_chain(seeds, [("root", "mid", "nAB2"), ("mid", PRIN, "nC")])
    req(P, "POST", "/v1/revocations",
        {"class": "delegation", "target": pkey("mid", "nC")})
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "delegation_chain": chainC})
    rec("D1: revoked presentation hop → chain deny", "deny",
        b.get("decision"), b.get("decision") == "deny")
    chainC2 = mint_chain(seeds, [("root", "mid", "nAB3"), ("mid", PRIN, "nC2")])
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "delegation_chain": chainC2})
    rec("D2: sibling presentation survives", "allow", b.get("decision"),
        b.get("decision") == "allow")
    req(P, "POST", "/v1/revocations", {"class": "issuer", "target": "mid"})
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "delegation_chain": chainC2})
    rec("D3: mid issuer revoked → descendants deny", "deny",
        b.get("decision"), b.get("decision") == "deny")
    chainR = mint_chain(seeds, [("root", PRIN, "nR1")])
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "delegation_chain": chainR})
    rec("D4: unrelated path (no mid) survives", "allow",
        b.get("decision"), b.get("decision") == "allow")
    req(P, "POST", "/v1/revocations", {"class": "issuer", "target": "root"})
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "delegation_chain": chainR})
    rec("D5: root issuer revoked → deny", "deny", b.get("decision"),
        b.get("decision") == "deny")
    # revoked-unconsumed presentation → deny (revocation ≠ replay)
    req(P, "POST", "/v1/revocations",
        {"class": "delegation", "target": pkey("x-iss", "nF1")})
    chainF = mint_chain(seeds, [("x-iss", PRIN, "nF1")])
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "delegation_chain": chainF})
    rec("R1: revoked-unconsumed presentation → deny", "deny",
        b.get("decision"), b.get("decision") == "deny")

    # ── EPOCH ────────────────────────────────────────────────────────
    ep1 = epoch(d)
    rec("epoch advanced across revocations", f">{ep0}", ep1, ep1 > ep0)
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "min_epoch": ep1 + 100})
    rec("E1: min_epoch above view → deny", "deny+revocation_epoch_stale",
        f"{b.get('decision')} {b.get('reason_codes')}",
        b.get("decision") == "deny" and
        "revocation_epoch_stale" in str(b.get("reason_codes")))
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "min_epoch": ep1})
    rec("E2: min_epoch satisfied → allow", "allow", b.get("decision"),
        b.get("decision") == "allow")

    # ── CLAIM-TIME boundary ──────────────────────────────────────────
    req(P, "POST", "/v1/continuations/queue/pause")   # deterministic
    leaseX = mint_lease(seeds["x-iss"], "x-iss", PRIN, "lse-X", GWA)
    st, b = check(P, {"action_type": "git.push", "resource": "repo:x",
                      "capability_lease": leaseX})
    rec("A1: escalate decision w/ lease", "escalate", b.get("decision"),
        b.get("decision") == "escalate")
    st, b = req(P, "POST", "/v1/approval/create",
                {"decision_id": b.get("decision_id"),
                 # ATTACK: caller forges authority ids — must be ignored
                 # in favor of the server-recorded decision.
                 "lease_id": "forged-lease",
                 "delegation_keys": ["deadbeef"*8],
                 "issuers": ["forged-issuer"]}, AGENT)
    rec("A2: approval created", "201", st, st == 201)
    apid = b.get("approval_id")
    st, b = req(P, "GET", f"/v1/continuations?approval_id={apid}")
    cnt1 = (b.get("continuations") or [{}])[0]
    rec("  continuation carries authority ids", "lse-X",
        cnt1.get("lease_id"), cnt1.get("lease_id") == "lse-X")
    rec("  forged caller ids ignored", "no forged-lease",
        "ignored" if "forged" not in json.dumps(cnt1) else "LEAKED",
        "forged" not in json.dumps(cnt1))
    req(P, "POST", f"/v1/approval/{apid}/approve", {})
    # revoke the lease BEFORE any claim
    req(P, "POST", "/v1/revocations", {"class": "lease", "target": "lse-X"})
    st, b = req(P, "POST", f"/v1/continuations/{cnt1['continuation_id']}/execute")
    rec("A3: claim after lease revoke → 409 deny (RVI-06/07)", "409",
        st, st == 409)
    st, b = req(P, "GET", f"/v1/continuations/{cnt1['continuation_id']}")
    state = (b.get("continuation") or b).get("state")
    rec("  denied continuation is terminal", "denied", state,
        state == "denied")
    st, b = req(P, "GET", "/v1/executions")
    rec("  no execution record created", "0",
        len(b.get("executions", [])), len(b.get("executions", [])) == 0)
    st, b = req(P, "POST", f"/v1/approval/{apid}/resume", {})
    rec("A4: resume on dead authority → 409", "409", st, st == 409)

    # positive control — valid authority claims and executes
    leaseY = mint_lease(seeds["x-iss"], "x-iss", PRIN, "lse-Y", GWA)
    st, b = check(P, {"action_type": "git.push", "resource": "repo:y",
                      "capability_lease": leaseY})
    st, b = req(P, "POST", "/v1/approval/create",
                {"decision_id": b.get("decision_id")}, AGENT)
    apid2 = b.get("approval_id")
    req(P, "POST", f"/v1/approval/{apid2}/approve", {})
    st, b = req(P, "GET", f"/v1/continuations?approval_id={apid2}")
    cnt2 = b["continuations"][0]["continuation_id"]
    st, b = req(P, "POST", f"/v1/continuations/{cnt2}/execute")
    st, b = req(P, "GET", "/v1/executions")
    rec("A5: valid claim → execution record exists (control)", "≥1",
        len(b.get("executions", [])), len(b.get("executions", [])) >= 1)

    # F1 regression: 2-hop chain-derived continuation, NON-terminal
    # hop presentation revoked post-approve → claim must deny. Issuers
    # x-iss/y-iss stay live; only the hop0 presentation key dies —
    # the bug this catches recorded only the terminal key.
    chainQ = mint_chain(seeds, [("x-iss", "y-iss", "nXY"), ("y-iss", PRIN, "nY")])
    st, b = check(P, {"action_type": "git.push", "resource": "repo:q",
                      "delegation_chain": chainQ})
    rec("F1a: 2-hop chain escalates", "escalate", b.get("decision"),
        b.get("decision") == "escalate")
    st, b = req(P, "POST", "/v1/approval/create",
                {"decision_id": b.get("decision_id")}, AGENT)
    apid3 = b.get("approval_id")
    req(P, "POST", f"/v1/approval/{apid3}/approve", {})
    st, b = req(P, "GET", f"/v1/continuations?approval_id={apid3}")
    cnt3 = b["continuations"][0]["continuation_id"]
    req(P, "POST", "/v1/revocations",
        {"class": "delegation", "target": pkey("x-iss", "nXY")})
    st, b = req(P, "POST", f"/v1/continuations/{cnt3}/execute")
    rec("F1: mid-hop key revoke → claim deny", "409", st, st == 409)

    # Orchestrator-drain path: same CheckClaimAuthority must gate it.
    # Approve under valid lease → revoke → resume queue → orchestrator
    # must deny, never invoke an executor.
    leaseQ = mint_lease(seeds["x-iss"], "x-iss", PRIN, "lse-Q", GWA)
    st, b = check(P, {"action_type": "git.push", "resource": "repo:z",
                      "capability_lease": leaseQ})
    st, b = req(P, "POST", "/v1/approval/create",
                {"decision_id": b.get("decision_id")}, AGENT)
    apid4 = b.get("approval_id")
    req(P, "POST", f"/v1/approval/{apid4}/approve", {})
    st, b = req(P, "GET", f"/v1/continuations?approval_id={apid4}")
    cnt4 = b["continuations"][0]["continuation_id"]
    req(P, "POST", "/v1/revocations", {"class": "lease", "target": "lse-Q"})
    st, b = req(P, "GET", "/v1/executions")
    nexec = len(b.get("executions", []))
    req(P, "POST", "/v1/continuations/queue/resume")
    time.sleep(3.5)                     # orchestrator drains every 2s
    req(P, "POST", "/v1/continuations/queue/pause")
    st, b = req(P, "GET", f"/v1/continuations/{cnt4}")
    state = (b.get("continuation") or b).get("state")
    rec("O1: orchestrator drain → revoked → denied", "denied", state,
        state == "denied")
    st, b = req(P, "GET", "/v1/executions")
    rec("O2: orchestrator created no execution record", str(nexec),
        len(b.get("executions", [])), len(b.get("executions", [])) == nexec)

    # ── SIGKILL durability ───────────────────────────────────────────
    req(P, "POST", "/v1/revocations", {"class": "lease", "target": "lse-K"})
    p.send_signal(signal.SIGKILL); p.wait(); PROCS.remove(p)
    p, ok = launch(d); PROCS.append(p)
    rec("SIGKILL → gateway reboots", "running", "running" if ok else "dead", ok)
    st, b = req(P, "GET", "/v1/revocations")
    targets = [r["target"] for r in b.get("revocations", [])]
    rec("SIGKILL: revocation durable", "lse-K present",
        "present" if "lse-K" in targets else targets, "lse-K" in targets)
    st, b = check(P, {"action_type": "shell", "resource": "true",
                      "capability_lease": lease1})
    rec("SIGKILL: earlier lease revocation still enforced", "deny",
        b.get("decision"), b.get("decision") == "deny")

    # ── corruption: flip a byte inside a journal record → refuse ─────
    p.send_signal(signal.SIGKILL); p.wait(); PROCS.remove(p)
    data = open(reg_path(d), "rb").read()
    i = data.index(b'"target"')
    data = data[:i+10] + b"X" + data[i+11:]
    open(reg_path(d), "wb").write(data)
    p, refused = launch(d, expect_fail=True)
    rec("S1: corrupted journal → gateway refuses boot", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # ── unanchored rollback: file IS the authority (documented) ──────
    d2 = f"{WORK}/b"
    write_config(d2, port, {"x-iss": trusted["x-iss"]})
    P2 = port
    launch(d2, expect_fail=True)
    gwctl(d2, "grant", "--gateway-id", gw_id(d2))
    p2, ok = launch(d2); PROCS.append(p2)
    rec("b: second domain boots", "running", "running" if ok else "dead", ok)
    lines = reg_lines(d2)
    req(P2, "POST", "/v1/revocations", {"class": "issuer", "target": "ghost"})
    ep_b = epoch(d2)
    p2.send_signal(signal.SIGKILL); p2.wait(); PROCS.remove(p2)
    open(reg_path(d2), "w").write("\n".join(lines) + "\n")
    p2, ok = launch(d2); PROCS.append(p2)
    rec("b: rolled-back journal boots (unanchored = file is authority)",
        "running", "running" if ok else "dead", ok)
    st, b = req(P2, "GET", "/v1/revocations")
    rec("b: ghost revocation absent after rollback",
        "absent", "absent" if all(r["target"] != "ghost"
        for r in b.get("revocations", [])) else "present",
        all(r["target"] != "ghost" for r in b.get("revocations", [])))
    rec("b: epoch regressed with file (anchor bounds this — P2.3.3)",
        f"<{ep_b}", epoch(d2), epoch(d2) < ep_b)

    # ── authority surfaces ───────────────────────────────────────────
    st, _ = req(P2, "POST", "/v1/revocations",
                {"class": "lease", "target": "x"}, token=AGENT)
    rec("agent token cannot revoke (RVI-12)", "403", st, st == 403)
    st, _ = req(P2, "POST", "/v1/capabilities/revoke",
                {"lease_id": "x"}, token=AGENT)
    rec("agent cannot revoke via capabilities route", "403", st, st == 403)
    r = gwctl(d2, "revoke", "--class", "bogus", "--target", "x")
    rec("gwctl rejects bad class", "rc!=0", r.returncode, r.returncode != 0)
    r = gwctl(d2, "revoke", "--class", "issuer")
    rec("gwctl rejects missing target", "rc!=0", r.returncode, r.returncode != 0)

    kill_all()
    n_ok = sum(1 for *_, ok in RESULTS if ok)
    print(f"\n{'='*70}\nP2.3.4 e2e: {n_ok}/{len(RESULTS)}")
    for case, e, g, ok in RESULTS:
        if not ok: print(f"  FAIL: {case} — want {e} got {g}")
    sys.exit(0 if n_ok == len(RESULTS) else 1)

if __name__ == "__main__":
    main()
