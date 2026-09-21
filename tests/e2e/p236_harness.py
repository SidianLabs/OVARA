#!/usr/bin/env python3
"""P2.3.6 integration + security closure — clean-room e2e.

One fresh domain exercises the ENTIRE P2.3 security chain end to end:

  gateway identity → agent credential → delegation → lease → policy
  → approval → continuation → claim → execution → signed receipt
  → independent verification

  A   valid full chain executes + produces an independently
      verifiable signed receipt bound to the authoritative decision
  B   denial matrix — every layer fails → zero execution
  C   revocation at each approval stage (pre-claim deny, both paths)
  D   identity lifecycle × claim: rotate → dual creds; revoke C1 →
      C1 dead, C2 alive; suspend → queued work frozen; retire → tombstone
  E   receipt composition — approval binding, offline verify, tamper
  F   SIGKILL durability — revoke persists, receipts still verify
  G   cross-domain — wrong-audience lease + foreign-issuer chain deny
  H   performance sanity — coarse latency figures, no pathologies

usage: python3 tests/e2e/p236_harness.py [workdir]
"""
import base64, copy, importlib.util, json, os, secrets, signal
import subprocess, sys, time, urllib.request, urllib.error, hashlib

REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

spec = importlib.util.spec_from_file_location(
    "p234", f"{REPO}/tests/e2e/p234_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p236-e2e"
H.WORK = WORK
BASE_PORT = 19770


def req(port, method, path, body=None, token=None):
    return H.req(port, method, path, body, token or H.OP)


def check2(port, body, token, prin):
    """H.check with a caller-specified authenticated principal —
    subject_id must equal the credential's derived identity."""
    req(port, "POST", f"/v1/shield/unrestrict/{prin}")
    import uuid
    body.setdefault("nonce", uuid.uuid4().hex)
    body.setdefault("issued_at", H.rfc(time.time()))
    body.setdefault("environment", "local")
    body["agent_identity"] = {"issuer": "ovara", "subject_id": prin}
    return req(port, "POST", "/v1/runtime/check", body, token)


def get_receipt(port, decision_id):
    st, b = req(port, "GET", f"/v1/receipts/decision/{decision_id}")
    rs = b.get("receipts", [])
    return rs[0] if rs else None


def executions(port):
    st, b = req(port, "GET", "/v1/executions")
    return b.get("executions", [])


def verify_gwctl(d, rcpt):
    f = f"{WORK}/rcpt.json"
    json.dump(rcpt, open(f, "w"))
    return H.gwctl(d, "verify-receipt", "--receipt", os.path.abspath(f))


def approve_flow(P, body, token):
    """check → escalate → approval create+approve → continuation_id."""
    st, b = H.check(P, body, token)
    if b.get("decision") != "escalate":
        return None, f"decision={b.get('decision')} reasons={b.get('reasons')}"
    st, b = req(P, "POST", "/v1/approval/create",
                {"decision_id": b["decision_id"]}, token)
    apid = b.get("approval_id")
    if not apid:
        return None, f"approval_create st={st} {json.dumps(b)[:100]}"
    req(P, "POST", f"/v1/approval/{apid}/approve", {})
    st, b = req(P, "GET", f"/v1/continuations?approval_id={apid}")
    cs = b.get("continuations") or []
    if not cs:
        return None, "no continuation"
    return cs[0]["continuation_id"], apid


def main():
    print(f"P2.3.6 integration e2e — clean-room {WORK}")
    signal.signal(signal.SIGINT, lambda *_: (H.kill_all(), sys.exit(1)))
    H.build()
    port = BASE_PORT

    seeds, trusted = {}, {}
    for name in ("iss-a", "iss-b", "iss-c", "iss-d", "lease-iss"):
        seeds[name], trusted[name] = H.gen_key()

    d = f"{WORK}/a"
    H.write_config(d, port, trusted)
    pol = json.load(open(f"{d}/policy.json"))
    pol["rules"].insert(0, {"action_type": "forbidden",
                            "environment": "*", "deny": True})
    json.dump(pol, open(f"{d}/policy.json", "w"))
    P = port

    H.launch(d, expect_fail=True)
    H.gwctl(d, "grant", "--gateway-id", H.gw_id(d))
    p, ok = H.launch(d); H.PROCS.append(p)
    H.rec("A0: gateway boots", "running", "running" if ok else "dead", ok)
    GWA = H.gw_id(d)
    req(P, "POST", "/v1/continuations/queue/pause")

    # ═══ A. VALID FULL CHAIN ════════════════════════════════════════
    # P2.1: every presentation consumes hop nonces durably — each
    # request needs a freshly minted chain (fresh nonces).
    def mkchain4(tag):
        return H.mint_chain(seeds, [("iss-a", "iss-b", f"{tag}a"),
                                    ("iss-b", "iss-c", f"{tag}b"),
                                    ("iss-c", "iss-d", f"{tag}c"),
                                    ("iss-d", H.PRIN, f"{tag}d")])
    lease1 = H.mint_lease(seeds["lease-iss"], "lease-iss", H.PRIN,
                          "lse-1", GWA)
    st, b = H.check(P, {"action_type": "shell", "resource": "true",
                        "capability_lease": lease1,
                        "delegation_chain": mkchain4("a1")})
    H.rec("A1: full chain → allow", "allow", b.get("decision"),
          b.get("decision") == "allow")
    rcpt = get_receipt(P, b["decision_id"])
    ok = (rcpt and rcpt.get("gateway_id") == GWA and
          rcpt.get("gateway_key_id", "").startswith("gwk_") and
          rcpt.get("gateway_sig", "").startswith("edsig_v1:") and
          isinstance(rcpt.get("trust_epoch"), int) and
          rcpt.get("signature", "").startswith("sig_v1:") and
          rcpt.get("decision") == "allow" and
          rcpt.get("resource") == "true" and
          rcpt.get("action_type") == "shell" and
          rcpt.get("agent_id") == H.PRIN and
          rcpt.get("capability_lease_id") == "lse-1")
    H.rec("A2: receipt bound to authoritative fields", "all",
          "all" if ok else json.dumps(rcpt)[:120], bool(ok))
    r = verify_gwctl(d, rcpt)
    H.rec("A3: gwctl offline verify (no secrets)", "VALID",
          r.stdout.strip().split()[0] if r.stdout else "",
          r.returncode == 0 and "VALID" in r.stdout)

    cntA, apidA = approve_flow(P, {"action_type": "git.push",
                                   "resource": "repo:i",
                                   "capability_lease": lease1,
                                   "delegation_chain": mkchain4("a4")},
                               H.AGENT)
    H.rec("A4: escalate→approval→continuation", "id",
          cntA or f"none({apidA})", cntA is not None)
    n0 = len(executions(P))
    st, b = req(P, "POST", f"/v1/continuations/{cntA}/execute")
    H.rec("A5: claim+execute under full authority", "2xx", st,
          st in (200, 201, 202))
    H.rec("A6: execution record exists", f">{n0}", len(executions(P)),
          len(executions(P)) > n0)
    # receipt for the escalated decision carries approval binding
    # (receipt is minted at decision time — approval_id lands when the
    # approval record exists; the continuation carries the binding)
    st, b = req(P, "GET", f"/v1/continuations/{cntA}")
    cnt_obj = b.get("continuation") or b
    H.rec("A7: continuation carries approval+authority binding",
          "approval+lease+keys",
          (cnt_obj.get("approval_id") == apidA and
           cnt_obj.get("lease_id") == "lse-1" and
           len(cnt_obj.get("delegation_keys") or []) == 4 and
           len(cnt_obj.get("issuers") or []) == 4),
          cnt_obj.get("approval_id") == apidA and
          cnt_obj.get("lease_id") == "lse-1" and
          len(cnt_obj.get("delegation_keys") or []) == 4 and
          len(cnt_obj.get("issuers") or []) == 4)

    # ═══ B. DENIAL MATRIX ═══════════════════════════════════════════
    n_exec = len(executions(P))
    st, b = req(P, "POST", "/v1/runtime/check",
                {"action_type": "shell", "resource": "x"},
                token="forged-token")
    H.rec("B01: bad credential → 401", "401", st, st == 401)
    st, b = H.check(P, {"action_type": "forbidden", "resource": "x"})
    H.rec("B02: policy deny", "deny", b.get("decision"),
          b.get("decision") == "deny")
    badl = copy.deepcopy(lease1); badl["resource_scope"] = "evil"
    st, b = H.check(P, {"action_type": "shell", "resource": "x",
                        "capability_lease": badl})
    H.rec("B03: tampered lease sig → deny", "deny", b.get("decision"),
          b.get("decision") == "deny")
    badc = mkchain4("b4")
    badc["authorities"][0]["actions"] = ["*"]
    st, b = H.check(P, {"action_type": "shell", "resource": "x",
                        "delegation_chain": badc})
    H.rec("B04: tampered chain sig → deny", "deny", b.get("decision"),
          b.get("decision") == "deny")
    req(P, "POST", "/v1/revocations", {"class": "lease", "target": "lse-1"})
    st, b = H.check(P, {"action_type": "shell", "resource": "x",
                        "capability_lease": lease1})
    H.rec("B05: revoked lease → deny", "deny", b.get("decision"),
          b.get("decision") == "deny")
    req(P, "POST", "/v1/revocations",
        {"class": "delegation", "target": H.pkey("iss-c", "b6c")})
    st, b = H.check(P, {"action_type": "shell", "resource": "x",
                        "delegation_chain": mkchain4("b6")})
    H.rec("B06: revoked mid-hop presentation → deny", "deny",
          b.get("decision"), b.get("decision") == "deny")
    req(P, "POST", "/v1/revocations", {"class": "issuer", "target": "iss-b"})
    st, b = H.check(P, {"action_type": "shell", "resource": "x",
                        "delegation_chain": mkchain4("b7")})
    H.rec("B07: revoked mid-chain issuer → deny", "deny",
          b.get("decision"), b.get("decision") == "deny")
    eseed, _ = H.gen_key()
    forged_chain = H.mint_chain({"att": eseed}, [("att", H.PRIN, "nx")])
    st, b = H.check(P, {"action_type": "shell", "resource": "x",
                        "delegation_chain": forged_chain})
    H.rec("B08: untrusted-issuer chain → deny", "deny",
          b.get("decision"), b.get("decision") == "deny")
    alien = H.mint_lease(seeds["lease-iss"], "lease-iss", H.PRIN,
                         "lse-alien", "gw_DIFFERENTDOMAIN")
    st, b = H.check(P, {"action_type": "shell", "resource": "x",
                        "capability_lease": alien})
    H.rec("B09: wrong-audience lease → deny", "deny", b.get("decision"),
          b.get("decision") == "deny")
    st, b = req(P, "POST", "/v1/continuations/cnt_nonexistent/execute")
    H.rec("B10: claim nonexistent → rejected", "4xx", st,
          st in (404, 409))
    st, b = req(P, "POST", "/v1/revocations",
                {"class": "lease", "target": "x"}, token=H.AGENT)
    H.rec("B11: agent revoke → 403", "403", st, st == 403)
    st, b = req(P, "POST", "/v1/identities/register",
                {"role": "agent"}, token=H.AGENT)
    H.rec("B12: agent register → 403", "403", st, st == 403)
    H.rec("B13: zero executions across denial matrix", str(n_exec),
          len(executions(P)), len(executions(P)) == n_exec)

    # ═══ C. REVOCATION AT EACH APPROVAL STAGE ════════════════════════
    chain2 = H.mint_chain(seeds, [("lease-iss", "iss-d", "m1"),
                                  ("iss-d", H.PRIN, "m2")])
    leaseC = H.mint_lease(seeds["lease-iss"], "lease-iss", H.PRIN,
                          "lse-C", GWA)
    cntC, _ = approve_flow(P, {"action_type": "git.push",
                               "resource": "repo:c",
                               "capability_lease": leaseC,
                               "delegation_chain": chain2}, H.AGENT)
    req(P, "POST", "/v1/revocations",
        {"class": "delegation", "target": H.pkey("lease-iss", "m1")})
    st, b = req(P, "POST", f"/v1/continuations/{cntC}/execute")
    H.rec("C1: mid-hop revoke post-approve → sync claim deny", "409",
          st, st == 409)
    H.rec("C2: no execution record", str(n_exec), len(executions(P)),
          len(executions(P)) == n_exec)

    leaseD = H.mint_lease(seeds["lease-iss"], "lease-iss", H.PRIN,
                          "lse-D", GWA)
    cntD, _ = approve_flow(P, {"action_type": "git.push",
                               "resource": "repo:d",
                               "capability_lease": leaseD}, H.AGENT)
    req(P, "POST", "/v1/revocations", {"class": "lease", "target": "lse-D"})
    req(P, "POST", "/v1/continuations/queue/resume")
    time.sleep(3.5)
    req(P, "POST", "/v1/continuations/queue/pause")
    st, b = req(P, "GET", f"/v1/continuations/{cntD}")
    state = (b.get("continuation") or b).get("state")
    H.rec("C3: orchestrator drain → revoked → denied", "denied", state,
          state == "denied")
    H.rec("C4: orchestrator made no execution", str(n_exec),
          len(executions(P)), len(executions(P)) == n_exec)

    # ═══ D. IDENTITY LIFECYCLE × CLAIM ═══════════════════════════════
    st, b = req(P, "GET", "/v1/whoami", token=H.AGENT)
    ident = b.get("principal_id")
    tok2 = "c2-" + secrets.token_hex(8)
    st, b = req(P, "POST", "/v1/identities/rotate",
                {"identity_id": ident, "new_token": tok2})
    st, b = req(P, "GET", "/v1/whoami", token=tok2)
    H.rec("D1: rotated credential authenticates same identity", ident,
          b.get("principal_id"), b.get("principal_id") == ident)
    leaseE = H.mint_lease(seeds["lease-iss"], "lease-iss", H.PRIN,
                          "lse-E", GWA)
    cntE, _ = approve_flow(P, {"action_type": "git.push",
                               "resource": "repo:e",
                               "capability_lease": leaseE}, H.AGENT)
    req(P, "POST", "/v1/identities/status",
        {"identity_id": ident, "action": "suspend"})
    st, b = req(P, "GET", "/v1/whoami", token=H.AGENT)
    H.rec("D2: suspended identity → cred denied", "401/403", st,
          st in (401, 403))
    st, b = req(P, "POST", f"/v1/continuations/{cntE}/execute")
    H.rec("D3: suspended subject → sync claim denied", "4xx", st,
          st in (403, 409))
    req(P, "POST", "/v1/continuations/queue/resume")
    time.sleep(3.5)
    req(P, "POST", "/v1/continuations/queue/pause")
    st, b = req(P, "GET", f"/v1/continuations/{cntE}")
    state = (b.get("continuation") or b).get("state")
    H.rec("D4: orchestrator skips suspended subject (stays queued)",
          "queued", state, state == "queued")
    H.rec("D5: suspended → zero executions", str(n_exec),
          len(executions(P)), len(executions(P)) == n_exec)
    req(P, "POST", "/v1/identities/status",
        {"identity_id": ident, "action": "resume"})
    st, b = req(P, "GET", "/v1/whoami", token=H.AGENT)
    H.rec("D6: resumed identity authenticates", "200", st, st == 200)
    req(P, "POST", "/v1/credentials/revoke", {"token": H.AGENT})
    st, b = req(P, "GET", "/v1/whoami", token=H.AGENT)
    H.rec("D7: revoked credential → denied", "401/403", st,
          st in (401, 403))
    st, b = req(P, "GET", "/v1/whoami", token=tok2)
    H.rec("D8: sibling credential unaffected", "200", st, st == 200)
    req(P, "POST", "/v1/identities/status",
        {"identity_id": ident, "action": "retire"})
    st, b = req(P, "GET", "/v1/whoami", token=tok2)
    H.rec("D9: retired identity → all creds denied", "401/403", st,
          st in (401, 403))
    st, b = req(P, "POST", f"/v1/continuations/{cntE}/execute")
    H.rec("D10: retired subject → claim denied", "4xx", st,
          st in (403, 409))
    H.rec("D11: retired → zero executions", str(n_exec),
          len(executions(P)), len(executions(P)) == n_exec)

    # ═══ E. RECEIPT COMPOSITION (fresh agent — old identity retired) ═
    AG2 = "ag2-" + secrets.token_hex(8)
    req(P, "POST", "/v1/identities/register",
        {"role": "agent", "token": AG2})
    st, b = req(P, "GET", "/v1/whoami", token=AG2)
    PRIN2 = b.get("principal_id")
    H.rec("E0: registered credential authenticates", "ag_*", PRIN2,
          bool(PRIN2 and PRIN2.startswith("ag_")))
    leaseF = H.mint_lease(seeds["lease-iss"], "lease-iss", PRIN2,
                          "lse-F", GWA)
    st, b = check2(P, {"action_type": "shell", "resource": "true",
                       "capability_lease": leaseF}, AG2, PRIN2)
    H.rec("E1: new identity → allow", "allow", b.get("decision"),
          b.get("decision") == "allow")
    rcpt2 = get_receipt(P, b["decision_id"])
    ok = (rcpt2 and rcpt2.get("agent_id") == PRIN2 and
          rcpt2.get("gateway_sig", "").startswith("edsig_v1:"))
    H.rec("E2: receipt bound to the ACTUAL authenticated principal",
          PRIN2, rcpt2.get("agent_id") if rcpt2 else None, bool(ok))
    r = verify_gwctl(d, rcpt2)
    H.rec("E3: offline verify", "VALID rc=0", f"rc={r.returncode}",
          r.returncode == 0)
    bad = copy.deepcopy(rcpt2); bad["decision"] = "deny"
    r = verify_gwctl(d, bad)
    H.rec("E4: decision flip allow→deny → INVALID", "rc!=0",
          r.returncode, r.returncode != 0)
    bad = copy.deepcopy(rcpt2); bad["agent_id"] = "ag_evil"
    r = verify_gwctl(d, bad)
    H.rec("E5: subject swap → INVALID", "rc!=0", r.returncode,
          r.returncode != 0)
    bad = copy.deepcopy(rcpt2); bad["trust_epoch"] = 999
    r = verify_gwctl(d, bad)
    H.rec("E6: trust_epoch tamper → INVALID", "rc!=0", r.returncode,
          r.returncode != 0)

    # ═══ F. SIGKILL DURABILITY ═══════════════════════════════════════
    req(P, "POST", "/v1/revocations", {"class": "lease", "target": "lse-F"})
    p.send_signal(signal.SIGKILL); p.wait(); H.PROCS.remove(p)
    p, ok = H.launch(d); H.PROCS.append(p)
    H.rec("F1: SIGKILL → reboot", "running", "running" if ok else "dead",
          ok)
    st, b = check2(P, {"action_type": "shell", "resource": "true",
                       "capability_lease": leaseF}, AG2, PRIN2)
    H.rec("F2: revoked lease still denied post-crash", "deny",
          f"st={st} {b.get('decision')}", b.get("decision") == "deny")
    st, b = req(P, "GET", "/v1/whoami", token=tok2)
    H.rec("F3: retired identity tombstone durable", "401/403", st,
          st in (401, 403))
    r = verify_gwctl(d, rcpt2)
    H.rec("F4: pre-crash receipt still verifies", "VALID rc=0",
          f"rc={r.returncode}", r.returncode == 0)
    st, b = req(P, "GET", f"/v1/continuations/{cntE}")
    state = (b.get("continuation") or b).get("state")
    H.rec("F5: suspended-era continuation never executed", "queued",
          state, state == "queued")

    # ═══ G. CROSS-DOMAIN ═════════════════════════════════════════════
    # domain b: its own gateway id, its own trusted issuer
    seeds2, trusted2 = {}, {}
    seeds2["b-iss"], trusted2["b-iss"] = H.gen_key()
    d2 = f"{WORK}/b"
    H.write_config(d2, port + 1, trusted2)
    H.launch(d2, expect_fail=True)
    H.gwctl(d2, "grant", "--gateway-id", H.gw_id(d2))
    p2, ok2 = H.launch(d2); H.PROCS.append(p2)
    GWB = H.gw_id(d2)
    H.rec("G0: domain b boots", "running", "running" if ok2 else "dead",
          ok2)
    # lease minted for domain b presented to domain a → audience deny
    ble = H.mint_lease(seeds2["b-iss"], "b-iss", PRIN2, "lse-b", GWB)
    st, b = check2(P, {"action_type": "shell", "resource": "x",
                       "capability_lease": ble}, AG2, PRIN2)
    H.rec("G1: foreign-domain lease → deny in a", "deny",
          b.get("decision"), b.get("decision") == "deny")
    # foreign-issuer chain in domain a → deny (b-iss untrusted here)
    bchain = H.mint_chain(seeds2, [("b-iss", PRIN2, "bn")])
    st, b = check2(P, {"action_type": "shell", "resource": "x",
                       "delegation_chain": bchain}, AG2, PRIN2)
    H.rec("G2: foreign-issuer chain → deny in a", "deny",
          b.get("decision"), b.get("decision") == "deny")
    # domain a's receipt cannot verify against domain b's registry
    rf = f"{WORK}/rcpt-cross.json"
    json.dump(rcpt2, open(rf, "w"))
    r = subprocess.run([f"{WORK}/ovara-gwctl", "verify-receipt",
                        "--receipt", os.path.abspath(rf), "--registry",
                        os.path.abspath(f"{d2}/var/data/gwreg.jsonl")],
                       capture_output=True, text=True)
    H.rec("G3: cross-domain receipt verify → INVALID", "rc!=0",
          r.returncode, r.returncode != 0)
    # sanity: a b-domain lease for b's own agent works in b
    ble_b = H.mint_lease(seeds2["b-iss"], "b-iss", H.PRIN, "lse-b2", GWB)
    st, b = H.check(port + 1, {"action_type": "shell", "resource": "true",
                             "capability_lease": ble_b})
    H.rec("G4: b-domain lease VALID in its own domain", "allow",
          b.get("decision"), b.get("decision") == "allow")

    # ═══ H. PERFORMANCE SANITY ═══════════════════════════════════════
    t0 = time.time()
    N = 40
    for i in range(N):
        check2(P, {"action_type": "shell", "resource": "true",
                   "capability_lease": H.mint_lease(
                       seeds["lease-iss"], "lease-iss", PRIN2,
                       f"lse-p{i}", GWA)}, AG2, PRIN2)
    eval_ms = (time.time() - t0) / N * 1000
    H.rec("H1: eval+revocation+receipt-sign latency", "<250ms/op",
          f"{eval_ms:.1f}ms", eval_ms < 250)
    t0 = time.time()
    for i in range(N):
        req(P, "POST", "/v1/receipts/verify", rcpt2)
    vfy_ms = (time.time() - t0) / N * 1000
    H.rec("H2: receipt verify latency", "<100ms/op", f"{vfy_ms:.1f}ms",
          vfy_ms < 100)
    regsz = os.path.getsize(f"{d}/var/data/gwreg.jsonl")
    H.rec("H3: journal size bounded", "<1MB", f"{regsz//1024}KB",
          regsz < 1024*1024)

    H.kill_all()
    n_ok = sum(1 for *_, ok in H.RESULTS if ok)
    print(f"\n{'='*70}\nP2.3.6 e2e: {n_ok}/{len(H.RESULTS)}")
    for case, e, g, ok in H.RESULTS:
        if not ok: print(f"  FAIL: {case} — want {e} got {g}")
    sys.exit(0 if n_ok == len(H.RESULTS) else 1)


if __name__ == "__main__":
    main()
