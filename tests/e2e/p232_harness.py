#!/usr/bin/env python3
"""P2.3.2 enrollment/admission — clean-room e2e.

Real gateway + gwctl binaries, shared durable registry, SIGKILL
restarts. Covers the §24 matrix + removal attacks A–E:

  require_admission + no grant        → refuse (self-generated ≠ admitted)
  grant (unpinned/pinned)             → ACTIVE, consumed atomically
  denied / expired / wrong-gw grant   → refuse
  consumed grant + new key            → refuse (single-use)
  TOFU pin + require_admission        → allow (pin IS authorization)
  retire → SIGKILL → restart          → refuse (tombstone durable)
  retire + old enrollment/key restore → refuse
  retire + fresh key, same gw_id      → refuse
  fresh gw_id                         → new identity, needs own grant
  concurrent same-gw admits           → one winner
  in-memory + require_admission       → pin only, else refuse
  auto-admit default                  → compat preserved

usage: python3 tests/e2e/p232_harness.py [workdir]
"""
import datetime, json, os, secrets, shutil, signal, socket, subprocess, sys, time

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p232-e2e"
REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
GO = os.environ.get("GO") or shutil.which("go") or "/usr/local/go/bin/go"
BASE_PORT = 18600

RESULTS = []
def rec(case, expected, got, ok):
    RESULTS.append((case, expected, got, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {case:<62} want={expected} got={got}")

def build():
    os.makedirs(WORK, exist_ok=True)
    subprocess.run([GO, "build", "-o", f"{WORK}/ovara-gateway", "./cmd/server/"],
                   cwd=f"{REPO}/runtime/gateway", check=True, capture_output=True)
    subprocess.run([GO, "build", "-o", f"{WORK}/ovara-gwctl", "./cmd/gwctl/"],
                   cwd=f"{REPO}/runtime/gateway", check=True, capture_output=True)

def write_config(d, port, extra=None):
    os.makedirs(f"{d}/var/data", exist_ok=True)
    cfg = {
        "agent_tokens": ["p232-agent"], "operator_tokens": ["p232-op"],
        "auth_enabled": True, "fail_closed": True,
        "listen_addr": "127.0.0.1", "server_port": str(port),
        "log_level": "info", "policy_file": "policy.json",
        "enrollment_file": "var/data/enrollment.json",
        "gateway_registry_file": "var/data/gwreg.jsonl",
        "gateway_key_file": "var/data/gateway_key",
        "gateway_require_admission": True,
    }
    cfg.update(extra or {})
    json.dump(cfg, open(f"{d}/config.json", "w"), indent=1)
    json.dump({"version": "v1", "rules": [
        {"action_type": "http.request", "environment": "local", "allow": True},
    ]}, open(f"{d}/policy.json", "w"))

def launch(d, expect_fail=False, timeout=10):
    port = int(json.load(open(f"{d}/config.json"))["server_port"])
    proc = subprocess.Popen(["../ovara-gateway"], cwd=d,
        env={**os.environ, "OVARA_CONFIG": "config.json"},
        stdout=open(f"{d}/gw.log", "a"), stderr=subprocess.STDOUT)
    if expect_fail:
        try:
            proc.wait(timeout=timeout)
            return proc, True
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
            return proc, False
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

def gwctl(d, *args):
    """Run gwctl with --registry pointed at d's registry."""
    reg = os.path.abspath(f"{d}/var/data/gwreg.jsonl")
    r = subprocess.run([f"{WORK}/ovara-gwctl", *args, "--registry", reg],
                       capture_output=True, text=True)
    return r

def records(d, kind=None):
    p = f"{d}/var/data/gwreg.jsonl"
    if not os.path.exists(p):
        return []
    out = [json.loads(l) for l in open(p) if l.strip()]
    return [r for r in out if kind is None or r.get("kind") == kind]

def gw_id(d):
    return json.load(open(f"{d}/var/data/enrollment.json"))["id"]

def probe(d):
    """First boot under require_admission: refused, but enrollment.json
    is written — the operator learns the gw_id, then grants. This IS
    the enrollment workflow."""
    p, refused = launch(d, expect_fail=True)
    return refused

def grant_state(d, grant_id):
    """Fold grant lines by grant_id → latest state (append-only file)."""
    st = None
    for r in records(d, "grant"):
        if r["grant_id"] == grant_id:
            st = r["state"]
    return st

PROCS = []
def kill_all():
    for p in PROCS:
        try: p.kill(); p.wait()
        except Exception: pass

def main():
    print(f"P2.3.2 enrollment/admission e2e — clean-room {WORK}")
    signal.signal(signal.SIGINT, lambda *_: (kill_all(), sys.exit(1)))
    build()
    port = BASE_PORT

    def mk(name, extra=None):
        nonlocal port
        d = f"{WORK}/{name}"
        write_config(d, port, extra)
        port += 1
        return d

    # 1. require_admission + no grant/pin → REFUSE.
    A = mk("a")
    p, refused = launch(A, expect_fail=True)
    rec("no grant + require_admission → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    rec("refusal names admission", "admission",
        "admission" if "admission" in open(f"{A}/gw.log").read() else "other",
        "admission" in open(f"{A}/gw.log").read())

    # 2. Operator grant (unpinned) → boot → ACTIVE + grant consumed.
    r = gwctl(A, "grant", "--gateway-id", gw_id(A))
    rec("gwctl grant", "rc=0", r.returncode, r.returncode == 0)
    gidA = r.stdout.split("grant_id=")[1].split()[0]
    p, ok = launch(A); PROCS.append(p)
    rec("grant present → ACTIVE", "running", "running" if ok else "dead", ok)
    rec("grant consumed atomically", "consumed", grant_state(A, gidA),
        grant_state(A, gidA) == "consumed")
    rec("key record active", "active",
        records(A, "key")[0]["state"], records(A, "key")[0]["state"] == "active")
    rec("log shows admission=required", "required",
        "required" if "admission=required" in open(f"{A}/gw.log").read() else "?",
        "admission=required" in open(f"{A}/gw.log").read())

    # 3. Restart → adopt (consumed grant does not re-demand).
    p.kill(); p.wait(); PROCS.remove(p)
    p, ok = launch(A); PROCS.append(p)
    rec("restart adopts existing binding", "running",
        "running" if ok else "dead", ok)

    # 4. Consumed grant cannot re-admit a NEW key.
    kid = records(A, "key")[0]["key_id"]
    p.send_signal(signal.SIGKILL); p.wait(); PROCS.remove(p)
    os.remove(f"{A}/var/data/gateway_key")  # fresh key, same gw_id
    p, refused = launch(A, expect_fail=True)
    rec("consumed grant + new key → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    rec("registry kept original binding", kid,
        [k["key_id"] for k in records(A, "key")],
        len(records(A, "key")) == 1 and records(A, "key")[0]["key_id"] == kid)

    # 5. Denied grant → refuse.
    B = mk("b")
    probe(B)
    r = gwctl(B, "grant", "--gateway-id", gw_id(B))
    gid = r.stdout.split("grant_id=")[1].split()[0]
    gwctl(B, "deny", "--grant-id", gid)
    p, refused = launch(B, expect_fail=True)
    rec("denied grant → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # 6. Expired grant → refuse.
    C = mk("c")
    probe(C)
    gwctl(C, "grant", "--gateway-id", gw_id(C), "--ttl", "1s")
    time.sleep(2)
    p, refused = launch(C, expect_fail=True)
    rec("expired grant → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # 7. Grant for another gateway → refuse.
    D = mk("d")
    probe(D)
    gwctl(D, "grant", "--gateway-id", "gw_someoneelse")
    p, refused = launch(D, expect_fail=True)
    rec("grant for other gw → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # 8. Pinned grant: matching pub → allow.
    E = mk("e")
    # First learn the key by pre-generating via a throwaway boot? Simpler:
    # generate key material through gwctl? Keys are made by the gateway.
    # Use a temporary auto-admit boot to create the key file, then pin.
    cfg = json.load(open(f"{E}/config.json"))
    cfg["gateway_require_admission"] = False
    json.dump(cfg, open(f"{E}/config.json", "w"))
    p, ok = launch(E)  # auto-admit creates key + registers
    p.kill(); p.wait()
    pub = records(E, "key")[0]["public_key"]
    # Fresh registry for the pinned scenario:
    os.remove(f"{E}/var/data/gwreg.jsonl")
    cfg["gateway_require_admission"] = True
    json.dump(cfg, open(f"{E}/config.json", "w"))
    gwctl(E, "grant", "--gateway-id", gw_id(E), "--pubkey", pub)
    p, ok = launch(E); PROCS.append(p)
    rec("pinned grant + matching key → ACTIVE", "running",
        "running" if ok else "dead", ok)
    p.kill(); p.wait(); PROCS.remove(p)
    # 9. Pinned grant for a DIFFERENT pub → refuse.
    os.remove(f"{E}/var/data/gwreg.jsonl")
    gwctl(E, "grant", "--gateway-id", gw_id(E), "--pubkey", "00" * 32)
    p, refused = launch(E, expect_fail=True)
    rec("pinned grant + wrong key → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # 10. TOFU pin = admission authorization (require_admission, no grant).
    F = mk("f")
    cfg = json.load(open(f"{F}/config.json"))
    cfg["gateway_require_admission"] = False
    json.dump(cfg, open(f"{F}/config.json", "w"))
    p, ok = launch(F)  # learn key via auto-admit
    p.kill(); p.wait()
    pubF = records(F, "key")[0]["public_key"]
    gidF = gw_id(F)
    os.remove(f"{F}/var/data/gwreg.jsonl")
    cfg.update({"gateway_require_admission": True,
                "gateway_expected_id": gidF,
                "gateway_expected_pubkey": pubF})
    json.dump(cfg, open(f"{F}/config.json", "w"))
    p, ok = launch(F); PROCS.append(p)
    rec("TOFU pin + require_admission → ACTIVE", "running",
        "running" if ok else "dead", ok)
    p.kill(); p.wait(); PROCS.remove(p)
    cfg["gateway_expected_pubkey"] = "11" * 32
    json.dump(cfg, open(f"{F}/config.json", "w"))
    p, refused = launch(F, expect_fail=True)
    rec("TOFU mismatch + require_admission → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # 11. Retirement: retire → SIGKILL → restart → refuse. Attacks A–D.
    G = mk("g")
    probe(G)
    gwctl(G, "grant", "--gateway-id", gw_id(G))
    p, ok = launch(G)
    gwctl(G, "retire", "--gateway-id", gw_id(G))
    p.send_signal(signal.SIGKILL); p.wait()
    p, refused = launch(G, expect_fail=True)
    rec("retired + SIGKILL restart → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    # Attack B: restore old enrollment — tombstone is in registry, not
    # the file, so even a byte-identical enrollment can't help.
    p, refused = launch(G, expect_fail=True)
    rec("retired + old enrollment/key → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    # Attack D: fresh key, same gw_id → still tombstoned.
    os.remove(f"{G}/var/data/gateway_key")
    p, refused = launch(G, expect_fail=True)
    rec("retired + fresh key same gw_id → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    # Pending grant for retired gw → still dead.
    gwctl(G, "grant", "--gateway-id", gw_id(G))
    p, refused = launch(G, expect_fail=True)
    rec("retired + outstanding grant → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    # Rotation cannot resurrect.
    cfg = json.load(open(f"{G}/config.json"))
    cfg["gateway_force_rekey"] = True
    json.dump(cfg, open(f"{G}/config.json", "w"))
    p, refused = launch(G, expect_fail=True)
    rec("force_rekey on retired → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # 12. Attack E: fresh enrollment → new identity needs own grant.
    H = mk("h")
    probe(H)
    gwctl(H, "grant", "--gateway-id", gw_id(H))
    p, ok = launch(H)
    p.kill(); p.wait()
    os.remove(f"{H}/var/data/enrollment.json")  # new gw_id next boot
    os.remove(f"{H}/var/data/gateway_key")
    p, refused = launch(H, expect_fail=True)
    rec("new gw_id (no grant) → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # 13. Concurrent admits: two dirs, shared registry, same gw_id,
    #     different keys, two grants → one wins.
    I1, I2 = mk("i1"), mk("i2")
    probe(I1)
    # Share: point both at I1's registry; copy enrollment so gw_id matches.
    shutil.copy(f"{I1}/var/data/enrollment.json", f"{I2}/var/data/enrollment.json")
    cfg2 = json.load(open(f"{I2}/config.json"))
    cfg2["gateway_registry_file"] = os.path.abspath(f"{I1}/var/data/gwreg.jsonl")
    json.dump(cfg2, open(f"{I2}/config.json", "w"))
    gwctl(I1, "grant", "--gateway-id", gw_id(I1))
    gwctl(I1, "grant", "--gateway-id", gw_id(I1))  # second grant available
    procs = [subprocess.Popen(["../ovara-gateway"], cwd=d,
             env={**os.environ, "OVARA_CONFIG": "config.json"},
             stdout=open(f"{d}/gw.log", "a"), stderr=subprocess.STDOUT)
             for d in (I1, I2)]
    time.sleep(4)
    alive = sum(1 for x in procs if x.poll() is None)
    rec("concurrent same-gw admits → exactly one serves", "1", alive, alive == 1)
    for x in procs:
        try: x.kill(); x.wait()
        except Exception: pass

    # 14. Corrupt registry → refuse.
    J = mk("j")
    probe(J)
    gwctl(J, "grant", "--gateway-id", gw_id(J))
    data = open(f"{J}/var/data/gwreg.jsonl").read()
    open(f"{J}/var/data/gwreg.jsonl", "w").write('{corrupt\n' + data)
    p, refused = launch(J, expect_fail=True)
    rec("corrupt registry → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # 15. In-memory + require_admission: no pin → refuse; pin → allow.
    K = mk("k")
    cfg = json.load(open(f"{K}/config.json"))
    del cfg["gateway_registry_file"]  # in-memory registry
    json.dump(cfg, open(f"{K}/config.json", "w"))
    p, refused = launch(K, expect_fail=True)
    rec("in-memory + require_admission + no pin → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    # learn the pubkey from the key file's derived pub: boot once in
    # open mode to mint the key file, then pin.
    cfg["gateway_require_admission"] = False
    json.dump(cfg, open(f"{K}/config.json", "w"))
    p, ok = launch(K)
    p.kill(); p.wait()
    # registry was in-memory — read pub via a throwaway durable run? The
    # key file exists; derive pub by booting with registry+no-admission.
    cfg["gateway_registry_file"] = "var/data/gwreg.jsonl"
    json.dump(cfg, open(f"{K}/config.json", "w"))
    p, ok = launch(K)
    p.kill(); p.wait()
    pubK = records(K, "key")[0]["public_key"]
    cfg.update({"gateway_require_admission": True,
                "gateway_expected_id": gw_id(K),
                "gateway_expected_pubkey": pubK})
    del cfg["gateway_registry_file"]
    json.dump(cfg, open(f"{K}/config.json", "w"))
    p, ok = launch(K); PROCS.append(p)
    rec("in-memory + require_admission + pin → ACTIVE", "running",
        "running" if ok else "dead", ok)
    p.kill(); p.wait(); PROCS.remove(p)

    # 16. Compat default: no require_admission → open first-binding.
    L = mk("l")
    cfg = json.load(open(f"{L}/config.json"))
    del cfg["gateway_require_admission"]
    json.dump(cfg, open(f"{L}/config.json", "w"))
    p, ok = launch(L); PROCS.append(p)
    rec("unset require_admission → compat auto-admit", "running",
        "running" if ok else "dead", ok)
    rec("compat log says NOT admission", "compat",
        "compat" if "compat" in open(f"{L}/gw.log").read() else "?",
        "compat" in open(f"{L}/gw.log").read())
    p.kill(); p.wait(); PROCS.remove(p)

    # 17. P2.3.2.1 F1: pre-existing loose-perms registry → refuse, and
    # a forged grant written through those perms never takes effect.
    M = mk("m")
    probe(M)
    reg_m = os.path.abspath(f"{M}/var/data/gwreg.jsonl")
    os.chmod(reg_m, 0o666)
    now = datetime.datetime.now(datetime.timezone.utc) \
        .strftime("%Y-%m-%dT%H:%M:%S.000000000Z")
    with open(reg_m, "a") as f:
        f.write('{"kind":"grant","grant_id":"gwg_attacker","gateway_id":"%s",'
                '"state":"authorized","created_at":"%s"}\n' % (gw_id(M), now))
    p, refused = launch(M, expect_fail=True)
    rec("F1: 0666 registry + forged grant → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    rec("F1: refusal names unsafe permissions", "unsafe permissions",
        "named" if "unsafe permissions" in open(f"{M}/gw.log").read() else "?",
        "unsafe permissions" in open(f"{M}/gw.log").read())

    # 18. P2.3.2.1 F6: read-side gwctl on a missing registry must not
    # create it; grant still initializes.
    missing = f"{WORK}/no-such/reg.jsonl"
    for cmd, extra in (("list", ()),
                       ("deny", ("--grant-id", "gwg_x")),
                       ("retire", ("--gateway-id", "gw_x"))):
        r = subprocess.run([f"{WORK}/ovara-gwctl", cmd, *extra,
                            "--registry", missing],
                           capture_output=True, text=True)
        rec(f"F6: gwctl {cmd} on missing → err, no file", "rc!=0 + absent",
            f"rc={r.returncode} exists={os.path.exists(missing)}",
            r.returncode != 0 and not os.path.exists(missing))
    r = subprocess.run([f"{WORK}/ovara-gwctl", "grant", "--registry",
                        missing, "--gateway-id", "gw_x"],
                       capture_output=True, text=True)
    rec("F6: gwctl grant on missing → creates", "rc=0 + file",
        f"rc={r.returncode} exists={os.path.exists(missing)}",
        r.returncode == 0 and os.path.exists(missing))

    kill_all()
    ok = sum(1 for x in RESULTS if x[3])
    print(f"\n{'='*72}\nRESULT: {ok}/{len(RESULTS)} passed")
    for case, e, g, o in RESULTS:
        if not o: print(f"  FAIL {case}: want={e} got={g}")
    sys.exit(0 if ok == len(RESULTS) else 1)

if __name__ == "__main__":
    main()
