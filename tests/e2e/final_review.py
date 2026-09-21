#!/usr/bin/env python3
"""FINAL REVIEW — independent adversarial harness (not part of the
frozen suites). Attacks chosen for what the milestone harnesses do
NOT cover:

  FR-A  planted continuation record → claim → execution (file-write
        attacker inside the trust domain: does the queue honor a
        fabricated record?)
  FR-B  offline tamper of a queued continuation's resource → restart
        → does the tampered resource execute?
  FR-C  planted continuation carrying a REVOKED lease → claim-time
        boundary must still fire (positive control for FR-A/B)
  FR-D  credential revocation vs queued work: continuation created
        under credential C, C revoked (identity stays active),
        approve → drain → does it still execute? (documents the
        credential-vs-authority boundary)
  FR-E  agent token on operator execution surfaces → 403
  FR-F  forged + foreign receipt verification → invalid/error
  FR-G  gwreg.jsonl tail-truncation + middle-line tamper → restart
        detection/fail-closed
  FR-H  min_epoch poisoning: deny must not consume the request nonce
  FR-I  batch-check identity binding per item
  FR-J  deleted replay journal → restart → consumed nonce re-presented
        (documents the journal-deletion residual)
  FR-K  sync execute path on a planted record (operator endpoint)

usage: python3 tests/e2e/final_review.py [workdir]
"""
import base64, copy, importlib.util, json, os, secrets, signal
import subprocess, sys, time, urllib.request, urllib.error, hashlib, uuid

REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
spec = importlib.util.spec_from_file_location(
    "p234", f"{REPO}/tests/e2e/p234_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/finalreview-e2e"
H.WORK = WORK
PORT = 19850
MARK = f"{WORK}/marker"
CNT = lambda d: f"{d}/var/data/continuations.jsonl"


def req(port, method, path, body=None, token=None):
    return H.req(port, method, path, body, token or H.OP)


def planted(action, resource, state="queued", **kw):
    c = {"continuation_id": "cnt_" + secrets.token_hex(8),
         "decision_id": "dec_forged", "approval_id": "ap_forged",
         "agent_id": H.PRIN, "action_type": action,
         "resource": resource, "environment": "local",
         "state": state, "created_at": H.rfc(time.time()),
         "expires_at": H.rfc(time.time() + 3600)}
    c.update(kw)
    return c


def marker_execs(port):
    st, b = req(port, "GET", "/v1/executions")
    return b.get("executions", [])


def restart(d, port):
    for p in list(H.PROCS):
        p.kill(); p.wait()
    H.PROCS.clear()
    time.sleep(0.4)
    p, ok = H.launch(d); H.PROCS.append(p)
    return ok


def main():
    print(f"FINAL REVIEW adversarial e2e — clean-room {WORK}")
    signal.signal(signal.SIGINT, lambda *_: (H.kill_all(), sys.exit(1)))
    H.build()
    seeds, trusted = {}, {}
    for name in ("iss-a", "lease-iss"):
        seeds[name], trusted[name] = H.gen_key()

    d = f"{WORK}/a"
    H.write_config(d, PORT, trusted)
    P = PORT
    p, ok = H.launch(d, expect_fail=True)
    H.gwctl(d, "grant", "--gateway-id", H.gw_id(d))
    p, ok = H.launch(d); H.PROCS.append(p)
    H.rec("BOOT: enrolled gateway serves", True, ok, ok)
    GWA = H.gw_id(d)

    # ── FR-A: planted continuation executes? ────────────────────────
    # File-write attacker inside the trust domain appends a fabricated
    # queued record carrying NO authority material.
    fake = planted("shell", f"shell:touch {MARK}-a")
    with open(CNT(d), "a") as f:
        f.write(json.dumps(fake) + "\n")
    # appends are invisible to the RUNNING gateway (journal loads once
    # at Open) — the plant takes effect after a restart, exactly like a
    # real snapshot/persistence attacker would need.
    ok = restart(d, P)
    time.sleep(3)  # orchestrator drains every 2s
    ran = os.path.exists(f"{MARK}-a")
    H.rec("FR-A1: planted queued record executes (trust-domain boundary)",
          True, ran, ran)  # expected per filesystem=trust-domain; records the bound
    exes = marker_execs(P)
    H.rec("FR-A2: planted execution produces execution record",
          True, len(exes) > 0, len(exes) > 0)

    # ── FR-B: offline tamper of a real queued record ────────────────
    st, b = H.check(P, {"action_type": "git.push", "resource": "repo:tamper"})
    apid = None
    if b.get("decision") == "escalate":
        st, ab = req(P, "POST", "/v1/approval/create", {"decision_id": b["decision_id"]})
        apid = ab.get("approval_id")
        req(P, "POST", f"/v1/approval/{apid}/approve", {})
    req(P, "POST", "/v1/continuations/queue/pause")
    st, cb = req(P, "GET", f"/v1/continuations?approval_id={apid}")
    real = (cb.get("continuations") or [None])[0]
    ok = real is not None
    H.rec("FR-B0: control continuation queued", True, ok, ok)
    if ok:
        # stop gateway, rewrite the record's resource in the journal,
        # restart — the store replays the tampered line as truth.
        for p in list(H.PROCS): p.kill(); p.wait()
        H.PROCS.clear(); time.sleep(0.4)
        lines = open(CNT(d)).read().splitlines()
        for i, l in enumerate(lines):
            if real["continuation_id"] in l and '"state":"queued"' in l:
                c = json.loads(l)
                c["resource"] = f"shell:touch {MARK}-b"
                c["action_type"] = "shell"
                lines[i] = json.dumps(c)
        open(CNT(d), "w").write("\n".join(lines) + "\n")
        p, ok = H.launch(d); H.PROCS.append(p)
        req(P, "POST", "/v1/continuations/queue/resume")
        time.sleep(3)
        ran = os.path.exists(f"{MARK}-b")
        H.rec("FR-B1: offline resource tamper executes after restart",
              True, ran, ran)  # same boundary: file IS authority

    # ── FR-C: planted record with REVOKED lease → claim-time deny ───
    lease = H.mint_lease(seeds["lease-iss"], "lease-iss", H.PRIN, "lse-fc", GWA)
    st, b = H.check(P, {"action_type": "shell", "resource": "true",
                        "capability_lease": lease})
    req(P, "POST", "/v1/revocations", {"class": "lease", "target": "lse-fc",
                                     "reason": "test"})
    fake2 = planted("shell", f"shell:touch {MARK}-c",
                    lease_id="lse-fc")
    req(P, "POST", "/v1/continuations/queue/pause")
    with open(CNT(d), "a") as f:
        f.write(json.dumps(fake2) + "\n")
    for p in list(H.PROCS): p.kill(); p.wait()
    H.PROCS.clear(); time.sleep(0.4)
    p, ok = H.launch(d); H.PROCS.append(p)
    req(P, "POST", "/v1/continuations/queue/resume")
    time.sleep(3)
    ran = os.path.exists(f"{MARK}-c")
    H.rec("FR-C1: planted record w/ revoked lease is denied at claim",
          False, ran, not ran)

    # ── FR-D: credential revoke vs queued work ───────────────────────
    # New agent credential → escalate→approve→queued; revoke the
    # CREDENTIAL (identity remains active) → resume → claim.
    agd_tok = "agd-tok-" + secrets.token_hex(12)
    st, rb = req(P, "POST", "/v1/identities/register",
                 {"role": "agent", "token": agd_tok})
    agd_id = rb.get("identity_id") or rb.get("id") or rb.get("identity", {}).get("id")
    def check_d(body):
        req(P, "POST", f"/v1/shield/unrestrict/{agd_id}")
        body.setdefault("nonce", uuid.uuid4().hex)
        body.setdefault("issued_at", H.rfc(time.time()))
        body.setdefault("environment", "local")
        body["agent_identity"] = {"issuer": "ovara", "subject_id": agd_id}
        return req(P, "POST", "/v1/runtime/check", body, agd_tok)
    st, b = check_d({"action_type": "git.push", "resource": "repo:d"})
    cntD = None
    if b.get("decision") == "escalate":
        st, ab = req(P, "POST", "/v1/approval/create", {"decision_id": b["decision_id"]})
        ap = ab.get("approval_id")
        if ap:
            req(P, "POST", f"/v1/approval/{ap}/approve", {})
            st, cb = req(P, "GET", f"/v1/continuations?approval_id={ap}")
            cs = cb.get("continuations") or []
            cntD = cs[0]["continuation_id"] if cs else None
    H.rec("FR-D0: continuation queued under credential", True, cntD is not None, cntD is not None)
    if cntD:
        req(P, "POST", "/v1/continuations/queue/pause")
        req(P, "POST", "/v1/credentials/revoke", {"token": agd_tok})
        # credential dead for new auth
        st, b2 = check_d({"action_type": "shell", "resource": "true"})
        H.rec("FR-D1: revoked credential fails new auth",
              401, st, st == 401)
        req(P, "POST", "/v1/continuations/queue/resume")
        time.sleep(3)
        st, cb = req(P, "GET", f"/v1/continuations/{cntD}")
        stt = (cb.get("state") or "")
        H.rec("FR-D2: queued work still executes after credential revoke "
              "(credential not in claim-time pairs — documented semantics)",
              "executed", stt, stt == "executed")

    # ── FR-E: agent token on operator surfaces ──────────────────────
    for path, meth in [("/v1/continuations", "GET"),
                       ("/v1/revocations", "GET"),
                       ("/v1/identities", "GET"),
                       ("/v1/executions", "GET"),
                       ("/v1/events", "GET"),
                       ("/v1/receipts", "GET"),
                       ("/v1/runtime/status", "GET"),
                       ("/v1/admin/compact", "POST")]:
        st, _ = req(P, meth, path, token=H.AGENT)
        H.rec(f"FR-E: agent→{meth} {path} = 403", 403, st, st == 403)

    # ── FR-F: forged / foreign receipts ─────────────────────────────
    st, b = req(P, "GET", "/v1/receipts")
    rc = (b.get("receipts") or [None])[0]
    if rc:
        forged = copy.deepcopy(rc); forged["decision"] = "deny"
        st, v = req(P, "POST", "/v1/receipts/verify", forged)
        H.rec("FR-F1: tampered receipt fails verify",
              False, v.get("valid"), v.get("valid") is False)
        forged2 = copy.deepcopy(rc); forged2["gateway_id"] = "gw_foreign"
        st, v = req(P, "POST", "/v1/receipts/verify", forged2)
        H.rec("FR-F2: foreign-gateway receipt → unverifiable",
              False, v.get("valid"), v.get("valid") is False)
        forged3 = copy.deepcopy(rc); forged3["gateway_sig"] = "edsig_v1:" + "00"*64
        st, v = req(P, "POST", "/v1/receipts/verify", forged3)
        H.rec("FR-F3: zeroed signature fails verify",
              False, v.get("valid"), v.get("valid") is False)

    # ── FR-G: gwreg tamper ──────────────────────────────────────────
    for p in list(H.PROCS): p.kill(); p.wait()
    H.PROCS.clear(); time.sleep(0.4)
    lines = H.reg_lines(d)
    # G1: middle-line content tamper (same length-ish) → chain detect
    mid = json.loads(lines[2]) if len(lines) > 2 else None
    if mid is not None:
        for k in ("state", "public_key", "key_id"):
            if k in mid: mid[k] = "tampered" if k != "public_key" else "ab"*32
        lines[2] = json.dumps(mid)
        open(H.reg_path(d), "w").write("\n".join(lines) + "\n")
        p, ok = H.launch(d, expect_fail=True)
        alive = ok and p.poll() is None
        H.rec("FR-G1: mid-chain tamper → gateway refuses to serve",
              False, alive, not alive)
    # G2: restore then tail-truncate → epoch/seq regression detect
    H.write_config(d, PORT, trusted)
    os.makedirs(f"{d}/var/data", exist_ok=True)
    # rebuild fresh registry: delete + re-enroll
    for f in ("enrollment.json", "gwreg.jsonl", "gateway_key"):
        try: os.remove(f"{d}/var/data/{f}")
        except OSError: pass
    p, ok = H.launch(d, expect_fail=True)
    H.gwctl(d, "grant", "--gateway-id", H.gw_id(d))
    p, ok = H.launch(d); H.PROCS.append(p)
    lines = H.reg_lines(d)
    for p in list(H.PROCS): p.kill(); p.wait()
    H.PROCS.clear(); time.sleep(0.4)
    open(H.reg_path(d), "w").write("\n".join(lines[:-1]) + "\n")
    p, ok = H.launch(d, expect_fail=True)
    alive = ok and p.poll() is None
    H.rec("FR-G2: tail-truncated registry → refuses/anchors-detect",
          False, alive, not alive)

    # ── FR-H: min_epoch deny must not consume nonce ─────────────────
    if not alive:
        # gateway refused on tampered registry — rebuild clean state
        for f in ("enrollment.json", "gwreg.jsonl", "gateway_key"):
            try: os.remove(f"{d}/var/data/{f}")
            except OSError: pass
        p, ok = H.launch(d, expect_fail=True)
        H.gwctl(d, "grant", "--gateway-id", H.gw_id(d))
        p, ok = H.launch(d); H.PROCS.append(p)
    n = uuid.uuid4().hex
    st, b = H.check(P, {"action_type": "shell", "resource": "true",
                        "nonce": n, "min_epoch": 999999})
    H.rec("FR-H1: absurd min_epoch → deny (revocation_epoch)",
          "deny", b.get("decision"), b.get("decision") == "deny")
    st, b = H.check(P, {"action_type": "shell", "resource": "true", "nonce": n})
    H.rec("FR-H2: same nonce after epoch deny → not poisoned",
          "allow", b.get("decision"), b.get("decision") == "allow")

    # ── FR-I: batch identity binding ────────────────────────────────
    st, b = req(P, "POST", "/v1/runtime/batch-check",
                {"requests": [{"action_type": "shell", "resource": "true",
                               "nonce": uuid.uuid4().hex,
                               "issued_at": H.rfc(time.time()),
                               "environment": "local",
                               "agent_identity": {"issuer": "ovara",
                                                  "subject_id": "ag_evil"}}]},
                token=H.AGENT)
    decs = b.get("decisions") or b.get("results") or []
    bad = decs[0] if decs else b
    H.rec("FR-I1: batch item w/ foreign subject_id → rejected/denied",
          "deny-or-400",
          bad.get("decision") if isinstance(bad, dict) else bad,
          (isinstance(bad, dict) and bad.get("decision") == "deny") or st == 400)

    # ── FR-J: replay journal deletion → re-presentation ─────────────
    n2 = uuid.uuid4().hex
    st, b = H.check(P, {"action_type": "shell", "resource": "true", "nonce": n2})
    H.rec("FR-J0: first presentation", "allow", b.get("decision"),
          b.get("decision") == "allow")
    st, b = H.check(P, {"action_type": "shell", "resource": "true", "nonce": n2})
    H.rec("FR-J1: same nonce replay → deny", "deny", b.get("decision"),
          b.get("decision") == "deny")
    for p in list(H.PROCS): p.kill(); p.wait()
    H.PROCS.clear(); time.sleep(0.4)
    try: os.remove(f"{d}/var/data/replay.jsonl")
    except OSError: pass
    p, ok = H.launch(d); H.PROCS.append(p)
    st, b = H.check(P, {"action_type": "shell", "resource": "true", "nonce": n2})
    H.rec("FR-J2: nonce re-presented after journal deletion → allowed "
          "(journal=state residual)", "allow", b.get("decision"),
          b.get("decision") == "allow")

    # ── FR-K: sync execute on planted record (operator path) ────────
    fake3 = planted("shell", f"shell:touch {MARK}-k")
    with open(CNT(d), "a") as f:
        f.write(json.dumps(fake3) + "\n")
    for p in list(H.PROCS): p.kill(); p.wait()
    H.PROCS.clear(); time.sleep(0.4)
    p, ok = H.launch(d); H.PROCS.append(p)
    st, b = req(P, "POST", f"/v1/continuations/{fake3['continuation_id']}/execute")
    ran = os.path.exists(f"{MARK}-k")
    H.rec("FR-K1: operator sync-execute on planted record executes",
          True, ran, ran)

    # summary
    fails = [r for r in H.RESULTS if not r[3]]
    print(f"\nFINAL REVIEW e2e: {len(H.RESULTS)-len(fails)}/{len(H.RESULTS)}")
    if fails:
        for c, e, g, _ in fails: print(f"  FAIL {c} want={e} got={g}")
    H.kill_all()
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
