#!/usr/bin/env python3
"""P2.3.5 receipt signing — clean-room e2e.

Real binaries: ovara-gateway + ovara-gwctl. Verifies the additive
Ed25519 gateway signature (edsig_v1) on receipts:

  presence    every decision receipt carries gateway_id,
              gateway_key_id, trust_epoch, gateway_sig — alongside
              the untouched HMAC signature field
  verify      POST /v1/receipts/verify (operator) → valid
  offline     gwctl verify-receipt — third-party verification with
              ONLY the registry file + receipt JSON (no secrets)
  tamper      every signed field mutated → INVALID
  identity    cross-gateway id, wrong key_id, attacker-signed,
              unregistered key_id, PoP-sig substitution → INVALID
  rotation    force_rekey → new key_id signs new receipts; receipts
              signed by the superseded key still verify
  epoch       trust_epoch is bound — mutating it → INVALID; a receipt
              signed pre-revocation stays valid after the epoch moves
  authority   agent token cannot reach the verify endpoint (403)

usage: python3 tests/e2e/p235_harness.py [workdir]
"""
import base64, copy, importlib.util, json, os, secrets, signal
import subprocess, sys, time, urllib.request, urllib.error

REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

# Reuse the P2.3.4 harness infra — same binaries, config, launch,
# gwctl, request and record helpers.
spec = importlib.util.spec_from_file_location(
    "p234", f"{REPO}/tests/e2e/p234_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p235-e2e"
H.WORK = WORK  # tokens/PRIN stay the module's — internally consistent
BASE_PORT = 19760

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def get_receipt(port, decision_id):
    st, b = H.req(port, "GET", f"/v1/receipts/decision/{decision_id}", token=H.OP)
    rs = b.get("receipts", [])
    return rs[0] if rs else None


def verify_http(port, rcpt, token=None):
    return H.req(port, "POST", "/v1/receipts/verify", rcpt,
                 token or H.OP)


def verify_gwctl(d, rcpt):
    f = f"{WORK}/rcpt.json"
    json.dump(rcpt, open(f, "w"))
    return H.gwctl(d, "verify-receipt", "--receipt", os.path.abspath(f))


def main():
    print(f"P2.3.5 receipt signing e2e — clean-room {WORK}")
    signal.signal(signal.SIGINT, lambda *_: (H.kill_all(), sys.exit(1)))
    H.build()
    port = BASE_PORT

    seeds, trusted = {}, {}
    for name in ("lease-iss",):
        seeds[name], trusted[name] = H.gen_key()

    d = f"{WORK}/a"
    H.write_config(d, port, trusted)
    # add an explicit deny rule so a denied decision still reaches the
    # receipt path (early rejects produce no receipt — preserved).
    pol = json.load(open(f"{d}/policy.json"))
    pol["rules"].insert(0, {"action_type": "forbidden",
                            "environment": "*", "deny": True})
    json.dump(pol, open(f"{d}/policy.json", "w"))
    P = port

    H.launch(d, expect_fail=True)               # enrollment probe
    H.gwctl(d, "grant", "--gateway-id", H.gw_id(d))
    p, ok = H.launch(d); H.PROCS.append(p)
    H.rec("gateway boots with gateway trust", "running",
          "running" if ok else "dead", ok)
    GWA = H.gw_id(d)

    # ── R1: every decision receipt carries the signed identity ───────
    st, b = H.check(P, {"action_type": "shell", "resource": "true"})
    H.rec("R1: allow decision", "allow", b.get("decision"),
          b.get("decision") == "allow")
    rcpt = get_receipt(P, b["decision_id"])
    H.rec("R2: receipt exists", "yes", bool(rcpt), rcpt is not None)
    H.rec("R3: gateway_id stamped", GWA, rcpt.get("gateway_id"),
          rcpt.get("gateway_id") == GWA)
    H.rec("R4: gateway_key_id stamped", "gwk_*",
          rcpt.get("gateway_key_id", "")[:4],
          rcpt.get("gateway_key_id", "").startswith("gwk_"))
    H.rec("R5: gateway_sig edsig_v1", "edsig_v1:*",
          rcpt.get("gateway_sig", "")[:9],
          rcpt.get("gateway_sig", "").startswith("edsig_v1:"))
    H.rec("R6: trust_epoch present", "int>0", rcpt.get("trust_epoch"),
          isinstance(rcpt.get("trust_epoch"), int))
    H.rec("R7: HMAC signature preserved", "sig_v1:*",
          rcpt.get("signature", "")[:7],
          rcpt.get("signature", "").startswith("sig_v1:"))
    H.rec("R8: no private material in receipt", "absent",
          "absent" if "private" not in json.dumps(rcpt) else "LEAK",
          "private" not in json.dumps(rcpt))

    # ── R9: server-side verify endpoint ──────────────────────────────
    st, b = verify_http(P, rcpt)
    H.rec("R9: HTTP verify → valid", "true", b.get("valid"),
          b.get("valid") is True)

    # ── R10: offline third-party verification (gwctl, no secrets) ────
    r = verify_gwctl(d, rcpt)
    H.rec("R10: gwctl verify-receipt → VALID", "VALID rc=0",
          f"{r.stdout.strip().split()[0] if r.stdout else ''} rc={r.returncode}",
          r.returncode == 0 and "VALID" in r.stdout)
    bad = copy.deepcopy(rcpt); bad["resource"] = "prod-evil"
    r = verify_gwctl(d, bad)
    H.rec("R10b: gwctl tampered → INVALID rc!=0", "rc!=0",
          r.returncode, r.returncode != 0)
    nosig = copy.deepcopy(rcpt); nosig["gateway_sig"] = ""
    st, vb = verify_http(P, nosig)
    H.rec("R10c: unsigned receipt → invalid (never assumed)", "invalid",
          vb.get("valid"), vb.get("valid") is not True)

    # ── R11: tamper every signed field → INVALID ─────────────────────
    tampered = {
        "receipt_id": "rcpt_evil", "decision_id": "dec_evil",
        "action_type": "git.push", "resource": "prod",
        "agent_id": "ag_evil", "decision": "deny",
        "policy_version": "v99", "trust_score": 0.0,
        "trust_epoch": 999, "capability_lease_id": "lse_x",
        "approval_id": "ap_x", "issued_at": "2001-01-01T00:00:00Z",
        "signature": "sig_v1:forged",   # HMAC field is Ed-bound too
        "gateway_id": "gw_other", "gateway_key_id": "gwk_" + "0"*24,
    }
    allok = True
    for field, val in tampered.items():
        bad = copy.deepcopy(rcpt); bad[field] = val
        st, vb = verify_http(P, bad)
        ok = vb.get("valid") is not True
        allok = allok and ok
        H.rec(f"R11: tamper {field} → INVALID", "invalid",
              vb.get("valid"), ok)

    # ── R12: identity substitution attacks ───────────────────────────
    bad = copy.deepcopy(rcpt); bad["gateway_id"] = "gw_other"
    st, vb = verify_http(P, bad)
    H.rec("R12: cross-gateway id → INVALID", "invalid", vb.get("valid"),
          vb.get("valid") is not True)

    bad = copy.deepcopy(rcpt); bad["gateway_key_id"] = "gwk_" + "0"*24
    st, vb = verify_http(P, bad)
    H.rec("R12: unregistered key_id → INVALID", "invalid",
          vb.get("valid"), vb.get("valid") is not True)

    # Attacker-signed receipt claiming the victim's identity.
    aseed, _ = H.gen_key()
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(aseed))
    forged = copy.deepcopy(rcpt)
    forged["gateway_sig"] = "edsig_v1:" + base64.b64encode(
        k.sign(b"forged")).decode()
    st, vb = verify_http(P, forged)
    H.rec("R12: attacker-signed → INVALID", "invalid", vb.get("valid"),
          vb.get("valid") is not True)

    # PoP-domain signature cannot pass as a receipt signature.
    forged2 = copy.deepcopy(rcpt)
    forged2["gateway_sig"] = "edsig_v1:" + base64.b64encode(
        k.sign(b"OVARA-GATEWAY-POP-V1")).decode()
    st, vb = verify_http(P, forged2)
    H.rec("R12: PoP-domain sig → INVALID", "invalid", vb.get("valid"),
          vb.get("valid") is not True)

    # ── R13: receipts exist for decisions that reach evaluation —
    # including deny/escalate. (Pre-eval rejects — bad nonce, stale
    # epoch, replay — produce no receipt; existing semantics preserved.)
    st, b = H.check(P, {"action_type": "forbidden", "resource": "x"})
    H.rec("R13: policy-deny decision", "deny", b.get("decision"),
          b.get("decision") == "deny")
    drcpt = get_receipt(P, b["decision_id"])
    ok = drcpt and drcpt.get("gateway_sig", "").startswith("edsig_v1:")
    H.rec("R13: denied receipt signed", "edsig_v1",
          drcpt.get("gateway_sig", "")[:9] if drcpt else None,
          bool(ok))
    if drcpt:
        st, vb = verify_http(P, drcpt)
        H.rec("R13: denied receipt verifies", "true", vb.get("valid"),
              vb.get("valid") is True)

    # ── R14: agent token cannot reach verify ─────────────────────────
    st, vb = verify_http(P, rcpt, token=H.AGENT)
    H.rec("R14: agent verify → 403", "403", st, st == 403)

    # ── R15: trust_epoch binds revocation view — receipt stays valid
    # after the epoch moves (signature proves what was observed THEN).
    ep0 = rcpt["trust_epoch"]
    H.gwctl(d, "revoke", "--class", "lease", "--target", "lse-phantom")
    ep1 = H.epoch(d)
    st, vb = verify_http(P, rcpt)
    H.rec("R15: epoch advanced", f">{ep0}", ep1, ep1 > ep0)
    H.rec("R15: pre-revocation receipt still valid", "true",
          vb.get("valid"), vb.get("valid") is True)

    # ── R16: key rotation — new key signs, old receipts still verify ──
    p.send_signal(signal.SIGKILL); p.wait(); H.PROCS.remove(p)
    # fresh key file + force_rekey → Rotate (old → rotating/superseded).
    # Go ed25519 private key file = hex(seed‖pub) — 64 bytes.
    nk, npub = H.gen_key()
    open(f"{d}/var/data/gateway_key", "w").write(nk + npub)
    cfg = json.load(open(f"{d}/config.json"))
    cfg["gateway_force_rekey"] = True
    json.dump(cfg, open(f"{d}/config.json", "w"))
    p, ok = H.launch(d); H.PROCS.append(p)
    H.rec("R16: rekey restart", "running", "running" if ok else "dead", ok)

    st, b = H.check(P, {"action_type": "shell", "resource": "true"})
    rcpt2 = get_receipt(P, b["decision_id"])
    H.rec("R16: new receipt carries new key_id", "different",
          rcpt2.get("gateway_key_id") != rcpt.get("gateway_key_id"),
          rcpt2.get("gateway_key_id") != rcpt.get("gateway_key_id"))
    st, vb = verify_http(P, rcpt2)
    H.rec("R16: new-key receipt verifies", "true", vb.get("valid"),
          vb.get("valid") is True)
    st, vb = verify_http(P, rcpt)
    H.rec("R16: pre-rotation receipt still verifies (historical)",
          "true", vb.get("valid"), vb.get("valid") is True)
    r = verify_gwctl(d, rcpt)
    H.rec("R16: offline verify of superseded-key receipt", "VALID",
          r.stdout.strip().split()[0] if r.stdout else "",
          r.returncode == 0 and "VALID" in r.stdout)

    H.kill_all()
    n_ok = sum(1 for *_, ok in H.RESULTS if ok)
    print(f"\n{'='*70}\nP2.3.5 e2e: {n_ok}/{len(H.RESULTS)}")
    for case, e, g, ok in H.RESULTS:
        if not ok: print(f"  FAIL: {case} — want {e} got {g}")
    sys.exit(0 if n_ok == len(H.RESULTS) else 1)


if __name__ == "__main__":
    main()
