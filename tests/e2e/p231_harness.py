#!/usr/bin/env python3
"""P2.3.1 cryptographic gateway identity — clean-room e2e.

Real gateway binaries, real persisted registry + key files, SIGKILL
restarts, and a live clone-detection scenario:

  first boot generates + registers identity
  restart/SIGKILL → same gw_id + same key (idempotent rejoin)
  clone with same gw_id + DIFFERENT key on the same registry → refused
  clone in reverse order → refused
  full clone (key file copied) → joins (DOCUMENTED RESIDUAL — software
    keys are copyable; detection, not prevention)
  TOFU pin mismatch → refused
  corrupt registry → refused
  unsafe key-file permissions → refused
  force_rekey → rotation, old key rotating in registry
  private key material never in logs/registry/API

usage: python3 tests/e2e/p231_harness.py [workdir]
"""
import json, os, secrets, shutil, signal, socket, subprocess, sys, time

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p231-e2e"
GW_PORT = 18582
REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
GO = os.environ.get("GO") or shutil.which("go") or "/usr/local/go/bin/go"

RESULTS = []
def rec(case, expected, got, ok):
    RESULTS.append((case, expected, got, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {case:<58} want={expected} got={got}")

def build():
    os.makedirs(WORK, exist_ok=True)
    subprocess.run([GO, "build", "-o", f"{WORK}/ovara-gateway", "./cmd/server/"],
                   cwd=f"{REPO}/runtime/gateway", check=True, capture_output=True)

def write_config(d, extra=None, port=GW_PORT):
    os.makedirs(f"{d}/var/data", exist_ok=True)
    cfg = {
        "agent_tokens": ["p231-agent"], "operator_tokens": ["p231-op"],
        "auth_enabled": True, "fail_closed": True,
        "listen_addr": "127.0.0.1", "server_port": str(port),
        "log_level": "info", "policy_file": "policy.json",
        "enrollment_file": "var/data/enrollment.json",
        "gateway_registry_file": "var/data/gwreg.jsonl",
        "gateway_key_file": "var/data/gateway_key",
    }
    cfg.update(extra or {})
    json.dump(cfg, open(f"{d}/config.json", "w"), indent=1)
    json.dump({"version": "v1", "rules": [
        {"action_type": "http.request", "environment": "local", "allow": True},
    ]}, open(f"{d}/policy.json", "w"))

def launch(d, expect_fail=False, timeout=10):
    """Start the gateway in dir d. Returns (proc, started/refused)."""
    port = int(json.load(open(f"{d}/config.json"))["server_port"])
    proc = subprocess.Popen(["../ovara-gateway"], cwd=d,
        env={**os.environ, "OVARA_CONFIG": "config.json"},
        stdout=open(f"{d}/gw.log", "a"), stderr=subprocess.STDOUT)
    if expect_fail:
        try:
            proc.wait(timeout=timeout)
            return proc, True   # exited = refused to serve
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
            return proc, False  # still running = did NOT refuse
    for _ in range(60):
        if proc.poll() is not None:
            return proc, False
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return proc, True
        except OSError:
            time.sleep(0.2)
    proc.kill(); proc.wait()
    return proc, False

def registry_records(d):
    p = f"{d}/var/data/gwreg.jsonl"
    if not os.path.exists(p):
        return []
    return [json.loads(l) for l in open(p) if l.strip()]

def gw_id(d):
    return json.load(open(f"{d}/var/data/enrollment.json"))["id"]

def log_text(d):
    return open(f"{d}/gw.log").read() if os.path.exists(f"{d}/gw.log") else ""

PROCS = []
def kill_all():
    for p in PROCS:
        try: p.kill(); p.wait()
        except Exception: pass

def main():
    print(f"P2.3.1 gateway identity e2e — clean-room {WORK}")
    signal.signal(signal.SIGINT, lambda *_: (kill_all(), sys.exit(1)))
    build()
    G = f"{WORK}/g1"
    write_config(G)

    # 1. First boot: identity + key registered, gateway serves.
    p, ok = launch(G); PROCS.append(p)
    rec("first boot: gateway serves", "running", "running" if ok else "dead", ok)
    recs = registry_records(G)
    rec("first boot: one ACTIVE key registered", "1 active",
        sum(1 for r in recs if r["state"] == "active"),
        len(recs) == 1 and recs[0]["state"] == "active")
    gid = gw_id(G)
    rec("registry binds enrollment gw_id", gid, recs[0]["gateway_id"],
        recs[0]["gateway_id"] == gid)
    st = os.stat(f"{G}/var/data/gateway_key")
    rec("key file mode 0600", "0600", oct(st.st_mode & 0o777),
        (st.st_mode & 0o777) == 0o600)
    rec("auth log line present", "authenticated",
        "authenticated" if "gateway identity authenticated" in log_text(G) else "missing",
        "gateway identity authenticated" in log_text(G))

    # 2. Graceful restart → idempotent rejoin (same key_id).
    key1 = open(f"{G}/var/data/gateway_key").read()
    kid1 = recs[0]["key_id"]
    p.kill(); p.wait(); PROCS.remove(p)
    p, ok = launch(G); PROCS.append(p)
    recs2 = registry_records(G)
    rec("restart: same key_id rejoins", kid1,
        recs2[0]["key_id"] if recs2 else "none",
        ok and len(recs2) == 1 and recs2[0]["key_id"] == kid1)
    rec("restart: private key unchanged", "same",
        "same" if open(f"{G}/var/data/gateway_key").read() == key1 else "diff",
        open(f"{G}/var/data/gateway_key").read() == key1)

    # 3. SIGKILL restart → still same identity.
    p.send_signal(signal.SIGKILL); p.wait(); PROCS.remove(p)
    p, ok = launch(G); PROCS.append(p)
    recs3 = registry_records(G)
    rec("SIGKILL restart: identity + key persist", kid1,
        recs3[0]["key_id"] if recs3 else "none",
        ok and recs3 and recs3[0]["key_id"] == kid1)
    p.kill(); p.wait(); PROCS.remove(p)

    # 4. CLONE: same enrollment.json + same registry, different key.
    CL = f"{WORK}/clone"
    shutil.copytree(G, CL)
    os.remove(f"{CL}/var/data/gateway_key")  # clone lacks the key file
    # Clone uses a different port — registry path must stay SHARED:
    cfg = json.load(open(f"{CL}/config.json"))
    cfg["server_port"] = str(GW_PORT + 1)
    json.dump(cfg, open(f"{CL}/config.json", "w"))
    p, refused = launch(CL, expect_fail=True)
    log = log_text(CL)
    rec("clone w/ different key: startup refused", "exit+conflict",
        "refused" if refused and "refused" in log else f"rc={p.returncode} log-tail={log.strip()[-90:]}",
        refused and "refused" in log)
    clone_keyed = os.path.exists(f"{CL}/var/data/gateway_key")
    rec("clone generated fresh key, then refused", "key-created+refused",
        f"key={clone_keyed} refused={refused}", clone_keyed and refused)
    recs_cl = registry_records(CL)
    rec("clone conflict: registry still has only original key", kid1,
        [r["key_id"] for r in recs_cl],
        len(recs_cl) == 1 and recs_cl[0]["key_id"] == kid1)

    # 5. Reverse order: clone's key registers FIRST on fresh registry,
    #    then original gateway key conflicts.
    CL2 = f"{WORK}/clone2"
    shutil.copytree(CL, CL2)
    for f in ("gwreg.jsonl",):
        try: os.remove(f"{CL2}/var/data/{f}")
        except OSError: pass
    cfg = json.load(open(f"{CL2}/config.json"))
    cfg["server_port"] = str(GW_PORT + 2)
    json.dump(cfg, open(f"{CL2}/config.json", "w"))
    p, ok = launch(CL2)  # clone key registers first — works
    if ok:
        # Now original gateway (same gw_id, different key) must refuse.
        G2 = f"{WORK}/g2"
        shutil.copytree(G, G2)
        cfg = json.load(open(f"{G2}/config.json"))
        cfg["server_port"] = str(GW_PORT + 3)
        cfg["gateway_registry_file"] = f"{CL2}/var/data/gwreg.jsonl"  # shared domain
        json.dump(cfg, open(f"{G2}/config.json", "w"))
        p2, refused = launch(G2, expect_fail=True)
        rec("reverse-order clone: original refused on clone's registry",
            "exit", "refused" if refused else f"rc={p2.returncode}", refused)
    else:
        rec("reverse-order clone: original refused on clone's registry",
            "exit", "clone2 failed to boot", False)
    p.kill(); p.wait()

    # 6. FULL clone (key file copied too) — DOCUMENTED RESIDUAL:
    #    identical key = idempotent rejoin. Detection, not prevention.
    FC = f"{WORK}/fullclone"
    shutil.copytree(G, FC)
    cfg = json.load(open(f"{FC}/config.json"))
    cfg["server_port"] = str(GW_PORT + 4)
    json.dump(cfg, open(f"{FC}/config.json", "w"))
    p, ok = launch(FC); PROCS.append(p)
    rec("full clone (key copied): joins — documented residual",
        "idempotent rejoin", "joined" if ok else "refused", ok)
    p.kill(); p.wait(); PROCS.remove(p)

    # 7. TOFU pins: correct → boots; wrong pubkey → refused; wrong id → refused.
    TP = f"{WORK}/tofu"
    write_config(TP)
    p, ok = launch(TP)  # first boot to learn the key
    pubkey = registry_records(TP)[0]["public_key"]
    gid_tp = gw_id(TP)
    p.kill(); p.wait()
    cfg = json.load(open(f"{TP}/config.json"))
    cfg.update({"gateway_expected_id": gid_tp,
                "gateway_expected_pubkey": pubkey,
                "server_port": str(GW_PORT)})
    json.dump(cfg, open(f"{TP}/config.json", "w"))
    p, ok = launch(TP); PROCS.append(p)
    rec("TOFU pin match: boots", "running", "running" if ok else "dead", ok)
    p.kill(); p.wait(); PROCS.remove(p)
    cfg["gateway_expected_pubkey"] = "00" * 32
    json.dump(cfg, open(f"{TP}/config.json", "w"))
    p, refused = launch(TP, expect_fail=True)
    rec("TOFU wrong pubkey: refused", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    cfg["gateway_expected_pubkey"] = pubkey
    cfg["gateway_expected_id"] = "gw_wrong"
    json.dump(cfg, open(f"{TP}/config.json", "w"))
    p, refused = launch(TP, expect_fail=True)
    rec("TOFU wrong gw_id: refused", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # 8. Corrupt registry → refused.
    CG = f"{WORK}/corrupt"
    write_config(CG)
    p, ok = launch(CG)
    p.kill(); p.wait()
    data = open(f"{CG}/var/data/gwreg.jsonl").read()
    open(f"{CG}/var/data/gwreg.jsonl", "w").write('{corrupt\n' + data)
    p, refused = launch(CG, expect_fail=True)
    rec("corrupt registry: startup refused", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # 9. Unsafe key-file permissions → refused.
    UP = f"{WORK}/uperms"
    write_config(UP)
    p, ok = launch(UP)
    p.kill(); p.wait()
    os.chmod(f"{UP}/var/data/gateway_key", 0o644)
    p, refused = launch(UP, expect_fail=True)
    rec("unsafe key perms (0644): refused", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # 10. force_rekey with a NEW key → rotation in the registry.
    RK = f"{WORK}/rekey"
    write_config(RK)
    p, ok = launch(RK)
    kid_old = registry_records(RK)[0]["key_id"]
    p.kill(); p.wait()
    os.remove(f"{RK}/var/data/gateway_key")  # new key material
    cfg = json.load(open(f"{RK}/config.json"))
    cfg["gateway_force_rekey"] = True
    cfg["gateway_key_grace_seconds"] = 600
    json.dump(cfg, open(f"{RK}/config.json", "w"))
    p, ok = launch(RK); PROCS.append(p)
    recs_rk = registry_records(RK)
    states = {r["key_id"]: r["state"] for r in recs_rk}
    new_active = [k for k, s in states.items() if s == "active"]
    rec("force_rekey: gateway serves", "running", "running" if ok else "dead", ok)
    rec("force_rekey: old key ROTATING + new ACTIVE", "rotating+active",
        states, states.get(kid_old) == "rotating" and len(new_active) == 1
        and new_active[0] != kid_old)
    p.kill(); p.wait(); PROCS.remove(p)
    # Rekey flag left set + same key file → idempotent (restart-safe).
    p, ok = launch(RK); PROCS.append(p)
    rec("force_rekey idempotent on restart", "running",
        "running" if ok else "dead", ok)
    p.kill(); p.wait(); PROCS.remove(p)

    # 11. Private key never in logs or registry.
    keymat = key1.strip()
    leak = keymat in log_text(G) or keymat in json.dumps(registry_records(G))
    rec("private key absent from logs + registry", "absent",
        "leaked" if leak else "absent", not leak)

    kill_all()
    ok = sum(1 for x in RESULTS if x[3])
    print(f"\n{'='*70}\nRESULT: {ok}/{len(RESULTS)} passed")
    for case, e, g, o in RESULTS:
        if not o: print(f"  FAIL {case}: want={e} got={g}")
    sys.exit(0 if ok == len(RESULTS) else 1)

if __name__ == "__main__":
    main()
