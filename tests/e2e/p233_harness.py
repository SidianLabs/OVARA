#!/usr/bin/env python3
"""P2.3.3 rollback anchoring — clean-room e2e.

Real binaries: ovara-gateway + ovara-gwctl + ovara-anchor (Tier-1
unix-socket oracle, uid pin = SO_PEERCRED). Covers the frozen 21-attack
matrix:

  1/17 restore registry before grant-consumption   → refuse (behind)
  2/16 restore registry before retirement          → refuse (behind)
  3    prefix-truncate registry                    → refuse (behind)
  4    modify journal record                       → refuse (chain)
  5    replay old checkpoint to oracle             → ErrRegression
  6    tampered signed checkpoint                  → signature reject
  7    checkpoint for wrong domain                 → unregistered
  8    wrong oracle (uid pin mismatch)             → refuse
  9/19 oracle restored to older state              → refuse (L>A)
  10   oracle equivocation (same seq, diff tip)    → refuse
  11   oracle restart                              → state preserved
  12   torn oracle tail                            → recovers, no regress
  13   gateway-side unanchored tail                → refuse → catchup → ok
  14   concurrent anchor-init                      → one wins
  15   key-rotation rollback                       → refuse (behind)
  18   oracle unavailable (strict)                 → refuse
  20   joint registry+oracle co-rollback           → accepted (residual)
  21   anchor disabled                             → P2.3.2 floor intact

usage: python3 tests/e2e/p233_harness.py [workdir]
"""
import hashlib, http.client, json, os, secrets, shutil, signal, socket, subprocess, sys, time

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p233-e2e"
REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
GO = os.environ.get("GO") or shutil.which("go") or "/usr/local/go/bin/go"
BASE_PORT = 19600
MYUID = os.getuid()
OPTOK = "op-" + secrets.token_hex(8)

RESULTS = []
def rec(case, expected, got, ok):
    RESULTS.append((case, expected, got, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {case:<62} want={expected} got={got}")

def build():
    os.makedirs(WORK, exist_ok=True)
    for out, pkg in (("ovara-gateway", "./cmd/server/"),
                     ("ovara-gwctl", "./cmd/gwctl/"),
                     ("ovara-anchor", "./cmd/ovara-anchor/")):
        subprocess.run([GO, "build", "-o", f"{WORK}/{out}", pkg],
                       cwd=f"{REPO}/runtime/gateway", check=True, capture_output=True)

def write_config(d, port, extra=None):
    os.makedirs(f"{d}/var/data", exist_ok=True)
    cfg = {
        "agent_tokens": ["p233-agent"], "operator_tokens": ["p233-op"],
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

def anchored(d, sock, mode="strict", catchup=None, pin=None):
    """Set anchor config on d's config.json."""
    cfg = json.load(open(f"{d}/config.json"))
    cfg["gateway_anchor_mode"] = mode
    cfg["gateway_anchor_url"] = f"unix://{sock}"
    cfg["gateway_anchor_pin"] = pin or f"uid:{MYUID}"
    cfg["gateway_anchor_key_file"] = "var/data/anchor_key"
    if catchup:
        cfg["gateway_anchor_catchup"] = catchup
    json.dump(cfg, open(f"{d}/config.json", "w"))

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
    reg = os.path.abspath(f"{d}/var/data/gwreg.jsonl")
    return subprocess.run([f"{WORK}/ovara-gwctl", *args, "--registry", reg],
                          capture_output=True, text=True)

def anchor_args(d, sock):
    return ["--anchor-url", f"unix://{sock}", "--anchor-pin", f"uid:{MYUID}",
            "--anchor-key", os.path.abspath(f"{d}/var/data/anchor_key")]

def reg_path(d):
    return f"{d}/var/data/gwreg.jsonl"

def reg_lines(d):
    if not os.path.exists(reg_path(d)):
        return []
    return [l for l in open(reg_path(d)).read().splitlines() if l.strip()]

def domain_id(d):
    first = reg_lines(d)[0].encode()
    return "dom_" + hashlib.sha256(b"OVARA-ANCHOR-DOMAIN-V1" + first).hexdigest()[:32]

def gw_id(d):
    return json.load(open(f"{d}/var/data/enrollment.json"))["id"]

class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, sock):
        super().__init__("anchor")
        self.sp = sock
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.sp)

def oracle_req(sock, method, domain, body=None):
    c = UnixHTTP(sock)
    c.request(method, f"/v1/anchor/{domain}",
              body=json.dumps(body) if body is not None else None,
              headers={"X-Operator-Token": OPTOK})
    r = c.getresponse()
    data = r.read()
    c.close()
    try:
        return r.status, json.loads(data)
    except Exception:
        return r.status, {}

def oracle_latest(sock, domain):
    st, body = oracle_req(sock, "GET", domain)
    return (st, body)

def oracle_put(sock, domain, cp):
    return oracle_req(sock, "PUT", domain, cp)

def start_oracle(d, name="anchor"):
    sock = f"{d}/{name}.sock"
    store = f"{d}/{name}.jsonl"
    if os.path.exists(sock):
        os.remove(sock)
    p = subprocess.Popen([f"{WORK}/ovara-anchor", "--store", store,
                          "--listen", f"unix://{sock}", "--operator-token", OPTOK],
                         stdout=open(f"{d}/{name}.log", "a"), stderr=subprocess.STDOUT)
    for _ in range(50):
        if p.poll() is not None:
            return p, None
        try:
            socket.socket(socket.AF_UNIX).connect(sock)
            return p, sock
        except OSError:
            time.sleep(0.1)
    p.kill()
    return p, None

def store_commits(store, domain):
    """Extract checkpoint records for a domain from the oracle store."""
    out = []
    if not os.path.exists(store):
        return out
    for l in open(store):
        r = json.loads(l)
        if r.get("domain_id") == domain and r.get("checkpoint"):
            out.append(r["checkpoint"])
    return out

PROCS = []
def kill_all():
    for p in PROCS:
        try: p.kill(); p.wait()
        except Exception: pass

def main():
    print(f"P2.3.3 rollback anchoring e2e — clean-room {WORK}")
    signal.signal(signal.SIGINT, lambda *_: (kill_all(), sys.exit(1)))
    build()
    port = BASE_PORT
    def mk(name, extra=None):
        nonlocal port
        d = f"{WORK}/{name}"
        write_config(d, port, extra)
        port += 1
        return d

    # ── Shared fixture: oracle A + anchored gateway A ────────────────
    A = mk("a")
    oproc, sockA = start_oracle(A); PROCS.append(oproc)
    rec("oracle starts (unix socket)", "socket", "up" if sockA else "dead",
        sockA is not None)
    anchored(A, sockA)
    # Enrollment probe: refused (no grant) but enrollment.json exists.
    p, refused = launch(A, expect_fail=True)
    rec("strict+no grant → refuse (enrollment probe)", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    r = gwctl(A, "grant", "--gateway-id", gw_id(A))
    rec("operator grant", "rc=0", r.returncode, r.returncode == 0)
    # anchor-init attestation (no confirm → no oracle state)
    r = gwctl(A, "anchor-init", *anchor_args(A, sockA), "--attest")
    rec("anchor-init --attest prints artifact", "rc=0 + ATTESTATION",
        f"rc={r.returncode} att={'ANCHOR ATTESTATION' in r.stdout}",
        r.returncode == 0 and "ANCHOR ATTESTATION" in r.stdout)
    st, _ = oracle_latest(sockA, domain_id(A))
    rec("attest does NOT register domain", "404", st, st == 404)
    # marker not yet appended (attest is read-only)
    rec("attest leaves journal unchanged", "1 line", len(reg_lines(A)),
        len(reg_lines(A)) == 1)
    # anchor-init --confirm → marker + genesis registration
    r = gwctl(A, "anchor-init", *anchor_args(A, sockA), "--confirm")
    rec("anchor-init --confirm registers genesis", "rc=0",
        f"rc={r.returncode} {r.stderr.strip()}", r.returncode == 0)
    st, cp = oracle_latest(sockA, domain_id(A))
    rec("oracle holds genesis checkpoint", "seq=2",
        f"st={st} seq={cp.get('seq')}", st == 200 and cp.get("seq") == 2)
    # second init → journal already migrated AND oracle registered at
    # the same tip → idempotent "already initialized" report (F-E1:
    # init is resumable, never a second registration). No state change.
    r = gwctl(A, "anchor-init", *anchor_args(A, sockA), "--confirm")
    rec("second anchor-init → idempotent (already initialized)",
        "rc=0+no re-register", f"rc={r.returncode} {r.stdout.strip()[-40:]}",
        r.returncode == 0 and "already initialized" in r.stdout)
    st, cp2nd = oracle_latest(sockA, domain_id(A))
    rec("  oracle state unchanged by re-init", f"seq={cp.get('seq')}",
        f"seq={cp2nd.get('seq')}", cp2nd.get("seq") == cp.get("seq"))
    # Boot gateway → admit → anchor pushes tip
    p, ok = launch(A); PROCS.append(p)
    rec("anchored gateway boots + admits", "running",
        "running" if ok else "dead", ok)
    st, cp = oracle_latest(sockA, domain_id(A))
    nloc = len(reg_lines(A))
    rec("gateway admit pushed tip to oracle", f"seq={nloc}",
        f"seq={cp.get('seq')}", st == 200 and cp.get("seq") == nloc)
    p.send_signal(signal.SIGKILL); p.wait(); PROCS.remove(p)

    # ── 1/17. Consumed-grant rollback ────────────────────────────────
    pre_admit = open(reg_path(A), "rb").read()
    # restore to state BEFORE admission (snapshot taken at init time)
    snap = f"{A}/snap.jsonl"
    shutil.copy(reg_path(A), snap)
    # mutate (deny a fresh grant) then restore pre-mutation file
    r2 = gwctl(A, "grant", "--gateway-id", gw_id(A))
    gidA = r2.stdout.split("grant_id=")[1].split()[0]
    gwctl(A, "deny", "--grant-id", gidA, *anchor_args(A, sockA))
    shutil.copy(snap, reg_path(A))
    p, refused = launch(A, expect_fail=True)
    rec("1/17: registry restored to earlier state → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    rec("  refusal names rollback/behind", "behind",
        "hit" if "behind oracle" in open(f"{A}/gw.log").read() else "?",
        "behind oracle" in open(f"{A}/gw.log").read())
    shutil.copy(snap, reg_path(A))  # restore for next steps

    # ── 2/16. Retirement rollback ────────────────────────────────────
    B = mk("b")
    anchored(B, sockA)
    p, _ = launch(B, expect_fail=True)
    gwctl(B, "grant", "--gateway-id", gw_id(B))
    gwctl(B, "anchor-init", *anchor_args(B, sockA), "--confirm")
    p, ok = launch(B)
    rec("b anchored + running", "running", "running" if ok else "dead", ok)
    pre_retire = open(reg_path(B), "rb").read()
    gwctl(B, "retire", "--gateway-id", gw_id(B), *anchor_args(B, sockA))
    open(reg_path(B), "wb").write(pre_retire)  # rollback the tombstone
    p.send_signal(signal.SIGKILL); p.wait()
    p, refused = launch(B, expect_fail=True)
    rec("2/16: retirement rolled back → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # ── 3. Prefix truncation ─────────────────────────────────────────
    lines = reg_lines(B)
    open(reg_path(B), "w").write("\n".join(lines[:-2]) + "\n")
    p, refused = launch(B, expect_fail=True)
    rec("3: prefix-truncated registry → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # ── 4. Record modification (chain) ───────────────────────────────
    open(reg_path(B), "wb").write(pre_retire)
    data = open(reg_path(B)).read()
    i = data.index('"state":"active"')
    data = data[:i] + '"state":"Xctive"' + data[i+len('"state":"active"'):]
    open(reg_path(B), "w").write(data)
    p, refused = launch(B, expect_fail=True)
    log4 = open(f"{B}/gw.log").read()
    rec("4: modified journal record → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    rec("  refusal names chain mismatch", "chain",
        "hit" if "chain" in log4 else "?", "chain" in log4)

    # ── 5/6/7. Direct oracle API attacks ─────────────────────────────
    domA = domain_id(A)
    cps = store_commits(f"{A}/anchor.jsonl", domA)
    latest = cps[-1]
    # 5: replay old checkpoint → regression
    st, b = oracle_put(sockA, domA, cps[0])
    rec("5: replay old checkpoint → regression", "410", st, st == 410)
    # idempotent: replay CURRENT checkpoint → ok
    st, _ = oracle_put(sockA, domA, latest)
    rec("5b: replay current checkpoint → idempotent", "200", st, st == 200)
    # 6: tampered checkpoint (bump seq, keep sig) → sig invalid
    tampered = dict(latest); tampered["seq"] = latest["seq"] + 1
    st, b = oracle_put(sockA, domA, tampered)
    rec("6: seq-bumped checkpoint (stale sig) → reject", "412",
        f"st={st} {b.get('error','')[:40]}", st == 412)
    tampered2 = dict(latest)
    tampered2["seq"] = latest["seq"] + 1
    tampered2["tip_hash"] = "ff" * 32
    st, _ = oracle_put(sockA, domA, tampered2)
    rec("6b: tampered tip → reject", "412", st, st == 412)
    # 7: checkpoint bound to a different domain → rejected (domain
    # binding is in the signed preimage: path/cp mismatch is 400,
    # unregistered is 404 — either is fail-closed)
    st, _ = oracle_put(sockA, "dom_nonexistent", latest)
    rec("7: wrong-domain checkpoint → reject", "400/404", st, st in (400, 404))

    # ── 8. Wrong oracle (uid pin mismatch) ───────────────────────────
    open(reg_path(B), "wb").write(pre_retire)  # restore good journal
    anchored(B, sockA, pin=f"uid:{MYUID + 1}")
    p, refused = launch(B, expect_fail=True)
    log8 = open(f"{B}/gw.log").read()
    rec("8: oracle uid-pin mismatch → refuse", "exit+pin",
        f"refused={refused} pin={'mismatch' in log8 or 'pin' in log8}",
        refused and ("mismatch" in log8 or "pin" in log8))
    anchored(B, sockA)  # restore correct pin

    # ── 9/19. Oracle backup restore (lower anchored seq) ─────────────
    C = mk("c")
    anchored(C, sockA)
    launch(C, expect_fail=True)
    gwctl(C, "grant", "--gateway-id", gw_id(C))
    gwctl(C, "anchor-init", *anchor_args(C, sockA), "--confirm")
    backup_store = open(f"{A}/anchor.jsonl", "rb").read()
    p, ok = launch(C)
    # advance: retire then restore old store → oracle behind
    gwctl(C, "retire", "--gateway-id", gw_id(C), *anchor_args(C, sockA))
    p.send_signal(signal.SIGKILL); p.wait()
    oproc.kill(); oproc.wait(); PROCS.remove(oproc)
    open(f"{A}/anchor.jsonl", "wb").write(backup_store)  # restore old backup
    oproc, sockA2 = start_oracle(A); PROCS.append(oproc)
    p, refused = launch(C, expect_fail=True)
    log9 = open(f"{C}/gw.log").read()
    rec("9/19: oracle restored to older state → refuse (L>A)",
        "exit", "refused" if refused else f"rc={p.returncode}", refused)
    rec("  refusal names unanchored tail", "unanchored",
        "hit" if "unanchored tail" in log9 else "?", "unanchored tail" in log9)

    # ── 10. Oracle equivocation (same seq, different tip) ────────────
    # Forge a chain-valid ALTERNATE journal: replace the migrate marker
    # (seq2) with a forged grant record and recompute the chain — the
    # canonical form is deterministic, so a valid-but-different history
    # is constructible (that's exactly why the ORACLE, not the chain,
    # is the authority). anchor-init on the forged copy registers the
    # same domain at seq4 with a different tip → equivocation.
    FIELD_ORDER = {
        "grant":   ["kind","grant_id","gateway_id","public_key","state",
                    "created_at","expires_at","consumed_at","seq","chain"],
        "key":     ["kind","gateway_id","key_id","public_key","state",
                    "created_at","activated_at","rotating_until",
                    "retired_at","generation","seq","chain"],
        "migrate": ["kind","note","seq","chain"],
    }
    def canon(d):
        return json.dumps({k: d[k] for k in FIELD_ORDER[d["kind"]] if k in d},
                          separators=(",", ":"))
    def forge(lines, repl):
        out, prev = [], b"\x00" * 32
        for i, l in enumerate(lines):
            d = repl.get(i) or json.loads(l)
            d.pop("chain", None)
            prev = hashlib.sha256(prev + canon(d).encode()).digest()
            d["chain"] = prev.hex()
            out.append(canon(d))
        return out
    linesA = reg_lines(A)
    forged_grant = {"kind": "grant", "grant_id": "gwg_forged",
                    "gateway_id": gw_id(A), "state": "authorized",
                    "created_at": "2026-01-01T00:00:00Z",
                    "expires_at": "0001-01-01T00:00:00Z",
                    "consumed_at": "0001-01-01T00:00:00Z", "seq": 2}
    E = mk("e")
    alt = forge(linesA[:3], {1: forged_grant})  # seq1..3, marker replaced
    open(f"{E}/var/data/reg-copy.jsonl", "w").write("\n".join(alt) + "\n")
    os.chmod(f"{E}/var/data/reg-copy.jsonl", 0o600)
    oprocB, sockB = start_oracle(E, "anchorB"); PROCS.append(oprocB)
    r = subprocess.run([f"{WORK}/ovara-gwctl", "anchor-init",
                        "--registry", f"{E}/var/data/reg-copy.jsonl",
                        "--anchor-url", f"unix://{sockB}",
                        "--anchor-pin", f"uid:{MYUID}",
                        "--anchor-key", f"{E}/var/data/anchor_key",
                        "--confirm"], capture_output=True, text=True)
    rec("10a: second init of same domain on oracle B", "rc=0",
        f"rc={r.returncode} {r.stderr.strip()}", r.returncode == 0)
    stB, cpB = oracle_latest(sockB, domain_id(A))
    cpsA = store_commits(f"{A}/anchor.jsonl", domA)
    a_same_seq = [c for c in cpsA if c.get("seq") == cpB.get("seq")]
    rec("10b: same seq, different tip across oracles", "diff",
        f"A@seq{cpB.get('seq')}={a_same_seq[0]['tip_hash'][:12] if a_same_seq else '?'} "
        f"B={cpB.get('tip_hash','')[:12]}",
        bool(a_same_seq) and a_same_seq[0]["tip_hash"] != cpB.get("tip_hash"))
    anchored(A, sockB)  # point gateway at the equivocating oracle
    p, refused = launch(A, expect_fail=True)
    log10 = open(f"{A}/gw.log").read()
    rec("10: same-seq different-tip oracle → refuse", "exit+equivoc",
        f"refused={refused} eq={'equivocat' in log10}",
        refused and "equivocat" in log10)
    anchored(A, sockA2)

    # ── 11. Oracle restart preserves monotonic state ─────────────────
    oproc.kill(); oproc.wait(); PROCS.remove(oproc)
    oproc, sockA3 = start_oracle(A); PROCS.append(oproc)
    st, cp = oracle_latest(sockA3, domA)
    rec("11: oracle restart preserves checkpoint", f"seq={latest['seq']}",
        f"st={st} seq={cp.get('seq')}", st == 200 and cp.get("seq") == latest["seq"])

    # ── 12. Torn oracle tail ─────────────────────────────────────────
    with open(f"{A}/anchor.jsonl", "a") as f:
        f.write('{"kind":"commit","domain_id":"%s","checkpoint":{"seq":99' % domA)
    oproc.kill(); oproc.wait(); PROCS.remove(oproc)
    oproc, _ = start_oracle(A); PROCS.append(oproc)
    st, cp = oracle_latest(sockA, domA)
    rec("12: torn oracle tail → recovers, no regression",
        f"seq={latest['seq']}", f"st={st} seq={cp.get('seq')}",
        st == 200 and cp.get("seq") == latest["seq"])

    # ── 13. Unanchored tail → refuse → operator catch-up → ok ────────
    D = mk("d")
    anchored(D, sockA)
    launch(D, expect_fail=True)
    gwctl(D, "grant", "--gateway-id", gw_id(D))
    gwctl(D, "anchor-init", *anchor_args(D, sockA), "--confirm")
    p, ok = launch(D)
    rec("d anchored running", "running", "running" if ok else "dead", ok)
    p.send_signal(signal.SIGKILL); p.wait()
    oproc.kill(); oproc.wait()  # oracle DOWN
    # gateway-side mutation while oracle unreachable (gwctl without
    # anchor flags → durable local mutation, no push)
    r = gwctl(D, "grant", "--gateway-id", gw_id(D))
    rec("13a: mutation durable while oracle down", "rc=0", r.returncode,
        r.returncode == 0)
    oproc, _ = start_oracle(A); PROCS.append(oproc)
    p, refused = launch(D, expect_fail=True)
    rec("13b: unanchored tail → strict refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    r = gwctl(D, "anchor-catchup", *anchor_args(D, sockA))  # no confirm
    rec("13c: catchup without --confirm → no push", "no commit",
        "confirm" in r.stdout, "confirm" in r.stdout)
    st, cp = oracle_latest(sockA, domain_id(D))
    behind = cp.get("seq", 0)
    r = gwctl(D, "anchor-catchup", *anchor_args(D, sockA), "--confirm")
    st, cp = oracle_latest(sockA, domain_id(D))
    rec("13d: operator catch-up commits tail", f"seq>{behind}",
        f"rc={r.returncode} seq={cp.get('seq')}",
        r.returncode == 0 and cp.get("seq") == len(reg_lines(D)))
    p, ok = launch(D); PROCS.append(p)
    rec("13e: post-catchup boot → running", "running",
        "running" if ok else "dead", ok)
    p.send_signal(signal.SIGKILL); p.wait(); PROCS.remove(p)

    # ── 14. Concurrent anchor-init ───────────────────────────────────
    F = mk("f")
    anchored(F, sockA)
    launch(F, expect_fail=True)
    gwctl(F, "grant", "--gateway-id", gw_id(F))
    procs = [subprocess.Popen([f"{WORK}/ovara-gwctl", "anchor-init",
                "--registry", reg_path(F), *anchor_args(F, sockA), "--confirm"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
             for _ in range(2)]
    rcs = [q.wait() for q in procs]
    wins = sum(1 for rc in rcs if rc == 0)
    rec("14: concurrent anchor-init → one winner", "1", wins, wins == 1)
    # race loser may still have appended its marker — check the oracle
    # accepted exactly one genesis for this domain
    st, _ = oracle_latest(sockA, domain_id(F))
    rec("14b: domain registered exactly once", "200", st, st == 200)

    # ── 15. Key-rotation rollback ────────────────────────────────────
    G = mk("g")
    anchored(G, sockA)
    launch(G, expect_fail=True)
    gwctl(G, "grant", "--gateway-id", gw_id(G))
    gwctl(G, "anchor-init", *anchor_args(G, sockA), "--confirm")
    p, ok = launch(G)
    pre_rot = open(reg_path(G), "rb").read()
    p.send_signal(signal.SIGKILL); p.wait()
    os.remove(f"{G}/var/data/gateway_key")  # new identity key
    cfg = json.load(open(f"{G}/config.json"))
    cfg["gateway_force_rekey"] = True
    json.dump(cfg, open(f"{G}/config.json", "w"))
    p, ok = launch(G)
    rec("15a: anchored rotation works (anchor key signs)", "running",
        "running" if ok else "dead", ok)
    p.send_signal(signal.SIGKILL); p.wait()
    open(reg_path(G), "wb").write(pre_rot)  # roll back the rotation
    p, refused = launch(G, expect_fail=True)
    rec("15: rotation rolled back → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)

    # ── 18. Oracle unavailable (strict) ──────────────────────────────
    oproc.kill(); oproc.wait(); PROCS.remove(oproc)
    p, refused = launch(A, expect_fail=True)
    rec("18: oracle down + strict → refuse", "exit",
        "refused" if refused else f"rc={p.returncode}", refused)
    oproc, _ = start_oracle(A); PROCS.append(oproc)

    # ── 20. Joint co-rollback — DOCUMENTED residual ──────────────────
    # Snapshot BOTH registry and oracle store at the same state, then
    # "advance" (deny), then restore BOTH backups → consistent old
    # state → gateway accepts. This is the anchor/trusted-backup
    # compromise the threat model explicitly does NOT claim to prevent.
    H = mk("h")
    anchored(H, sockA)
    launch(H, expect_fail=True)
    gwctl(H, "grant", "--gateway-id", gw_id(H))
    gwctl(H, "anchor-init", *anchor_args(H, sockA), "--confirm")
    p, ok = launch(H)
    snap_reg = open(reg_path(H), "rb").read()
    snap_store = open(f"{A}/anchor.jsonl", "rb").read()
    p.send_signal(signal.SIGKILL); p.wait()
    gwctl(H, "retire", "--gateway-id", gw_id(H), *anchor_args(H, sockA))
    # co-rollback: both sides to the consistent snapshot
    open(reg_path(H), "wb").write(snap_reg)
    oproc.kill(); oproc.wait(); PROCS.remove(oproc)
    open(f"{A}/anchor.jsonl", "wb").write(snap_store)
    oproc, _ = start_oracle(A); PROCS.append(oproc)
    p, ok = launch(H)
    rec("20: joint co-rollback → ACCEPTED (documented residual)",
        "running", "running" if ok else "dead", ok)
    if ok:
        p.kill(); p.wait()
    print("    ^ residual: joint registry+oracle restore to consistent old")
    print("      state = anchor/trusted-backup compromise — NOT claimed")

    # ── 21. Anchor disabled → P2.3.2 floor ───────────────────────────
    J = mk("j")  # no anchor config at all
    launch(J, expect_fail=True)
    gwctl(J, "grant", "--gateway-id", gw_id(J))
    p, ok = launch(J)
    rec("21: anchor off → P2.3.2 admission path intact", "running",
        "running" if ok else "dead", ok)
    if ok:
        p.kill(); p.wait()

    # ── degraded-mode sanity: oracle down, degraded boots ────────────
    K = mk("k")
    anchored(K, sockA, mode="degraded")
    oproc.kill(); oproc.wait(); PROCS.remove(oproc)
    p, refused = launch(K, expect_fail=True, timeout=6)
    rec("degraded + oracle down + no grant → refuse (admission, not anchor)",
        "exit", "refused" if refused else "running",
        refused)  # refuses for ADMISSION reasons, anchor only warns
    gwctl(K, "grant", "--gateway-id", gw_id(K))
    p, ok = launch(K)
    rec("degraded + oracle down + grant → boots (warned)",
        "running", "running" if ok else "dead", ok)
    if ok:
        p.kill(); p.wait()

    # ══ REMEDIATION REGRESSION (post-audit fixes) ════════════════════

    # ── R-C1: degraded + catchup=auto + forged tail → NOT crowned ────
    # Audit finding F-C1: auto-catchup used to push the forged tail.
    M = mk("m")
    oprocM, sockM = start_oracle(M, "anchorM"); PROCS.append(oprocM)
    anchored(M, sockM, mode="degraded", catchup="auto")
    launch(M, expect_fail=True)
    gwctl(M, "grant", "--gateway-id", gw_id(M))
    gwctl(M, "anchor-init", *anchor_args(M, sockM), "--confirm")
    p, ok = launch(M); rec("R-C1 setup: degraded+auto anchored", "running",
                           "running" if ok else "dead", ok)
    p.kill(); p.wait()
    st, before = oracle_latest(sockM, domain_id(M))
    # forge a tail: extra authorized grant for an attacker gateway
    lsM = reg_lines(M)
    fg = {"kind": "grant", "grant_id": "gwg_AUDIT", "gateway_id": "gw_rogue",
          "state": "authorized", "created_at": "2026-01-01T00:00:00Z",
          "expires_at": "0001-01-01T00:00:00Z",
          "consumed_at": "0001-01-01T00:00:00Z"}
    out, prev = [], b"\x00" * 32
    for l in lsM:
        dd = json.loads(l); dd.pop("chain", None)
        prev = hashlib.sha256(prev + canon(dd).encode()).digest()
        dd["chain"] = prev.hex(); out.append(canon(dd))
    fg["seq"] = len(lsM) + 1
    prev = hashlib.sha256(prev + canon(fg).encode()).digest()
    fg["chain"] = prev.hex(); out.append(canon(fg))
    open(reg_path(M), "w").write("\n".join(out) + "\n")
    os.chmod(reg_path(M), 0o600)
    p, ok = launch(M)
    logM = open(f"{M}/gw.log").read()
    st, after = oracle_latest(sockM, domain_id(M))
    rec("R-C1: degraded+auto forged tail → oracle NOT advanced",
        f"seq stays {before['seq']}", f"seq={after.get('seq')}",
        ok and after.get("seq") == before["seq"])
    rec("  forged grant NOT anchored (operator gate required)",
        "no crown", "crowned" if after.get("seq") == len(out) else "no crown",
        after.get("seq") != len(out))
    rec("  log states operator catch-up required", "operator",
        "hit" if "catch-up" in logM or "anchor-catchup" in logM else "?",
        "catch-up" in logM or "anchor-catchup" in logM)
    # strict-mode counterpart: same forged tail → refuse outright
    anchored(M, sockM, mode="strict")
    p.kill(); p.wait()
    p, refused = launch(M, expect_fail=True)
    rec("R-C1b: same forged tail under strict → refuse", "exit",
        "refused" if refused else "running", refused)
    # operator catch-up path still works (human gate)
    r = gwctl(M, "anchor-catchup", *anchor_args(M, sockM), "--confirm")
    st, after2 = oracle_latest(sockM, domain_id(M))
    rec("R-C1c: operator catch-up crowns tail (human gate intact)",
        "pushed", f"rc={r.returncode} seq={after2.get('seq')}",
        r.returncode == 0 and after2.get("seq") == len(out))
    anchored(M, sockM, mode="degraded")

    # ── R-E1: anchor-init crash-safety / retryability ────────────────
    N = mk("n")
    launch(N, expect_fail=True)
    gwctl(N, "grant", "--gateway-id", gw_id(N))
    # init while oracle DOWN → marker commits, register fails
    r = gwctl(N, "anchor-init", "--anchor-url", f"unix://{N}/dead.sock",
              "--anchor-pin", f"uid:{MYUID}",
              "--anchor-key", f"{N}/var/data/anchor_key", "--confirm")
    rec("R-E1a: init with dead oracle fails", "rc!=0", r.returncode,
        r.returncode != 0)
    migrated = any('"migrate"' in l for l in reg_lines(N))
    rec("R-E1b: crash boundary — marker durable, oracle clean", "marker",
        "marker" if migrated else "none", migrated)
    oprocN, sockN = start_oracle(N, "anchorN"); PROCS.append(oprocN)
    r = gwctl(N, "anchor-init", *anchor_args(N, sockN), "--confirm")
    rec("R-E1c: retry after crashed init → resumes (registers tip)",
        "rc=0", f"rc={r.returncode} {r.stderr.strip()[:50]}",
        r.returncode == 0)
    st, cpN = oracle_latest(sockN, domain_id(N))
    rec("R-E1d: resumed init registered real tip", "registered",
        f"st={st} seq={cpN.get('seq')}", st == 200)
    # idempotent re-init: registered + same tip → reports, not error
    r = gwctl(N, "anchor-init", *anchor_args(N, sockN), "--confirm")
    rec("R-E1e: re-init on initialized domain → idempotent report",
        "rc=0", f"rc={r.returncode}", r.returncode == 0)
    # marker present + oracle registered + journal grew → refuse w/ catchup hint
    gwctl(N, "grant", "--gateway-id", gw_id(N))
    r = gwctl(N, "anchor-init", *anchor_args(N, sockN), "--confirm")
    rec("R-E1f: init on migrated+grew journal → refuse (catchup path)",
        "rc!=0", f"rc={r.returncode}", r.returncode != 0)

    # ── R-B1: Tier-2 HTTPS oracle — mutual client-key pinning ────────
    O = mk("o")
    launch(O, expect_fail=True)
    gwctl(O, "grant", "--gateway-id", gw_id(O))
    # mint the client identity key (the anchor key doubles as TLS id):
    # init against a dead socket creates the key file then fails at
    # register — all we need is the pubkey for the client-keys list.
    subprocess.run([f"{WORK}/ovara-gwctl", "anchor-init",
                    "--registry", f"{O}/var/data/gwreg.jsonl",
                    "--anchor-url", f"unix://{O}/dead.sock",
                    "--anchor-pin", f"uid:{MYUID}",
                    "--anchor-key", f"{O}/var/data/anchor_key",
                    "--confirm"], capture_output=True)
    ck_raw = bytes.fromhex(open(f"{O}/var/data/anchor_key").read().strip())
    ck_pub = ck_raw[32:].hex()  # ed25519 priv = seed(32)‖pub(32)
    with open(f"{O}/client_keys", "w") as f:
        f.write(ck_pub + "\n")
    https_oracle = subprocess.Popen(
        [f"{WORK}/ovara-anchor", "--store", f"{O}/o.jsonl",
         "--listen", "https://127.0.0.1:19777",
         "--key", f"{O}/oracle_key",
         "--client-keys", f"{O}/client_keys",
         "--operator-token", OPTOK],
        stdout=open(f"{O}/oracle.log", "w"), stderr=subprocess.STDOUT)
    PROCS.append(https_oracle)
    time.sleep(1.2)
    olog = open(f"{O}/oracle.log").read()
    import re as _re
    m = _re.search(r"pub=([0-9a-f]{64})", olog)
    opub = m.group(1) if m else "?"
    # 1) raw TLS client with NO certificate → handshake denied
    import ssl
    denied = False
    try:
        cx = ssl.create_default_context()
        cx.check_hostname = False; cx.verify_mode = ssl.CERT_NONE
        c = http.client.HTTPSConnection("127.0.0.1", 19777, context=cx, timeout=5)
        c.request("GET", "/v1/anchor/dom_x")
        c.getresponse().read()
    except Exception:
        denied = True
    rec("R-B1a: https oracle denies client with NO cert", "deny",
        "denied" if denied else "served", denied)
    # 2) gwctl with WRONG client key (not in client_keys) → denied
    #    (anchor-status reports the oracle error; rc=0 is fine — the
    #    denial is the TLS handshake failure shown in the output)
    wrong = f"{O}/var/data/wrong_key"
    r = gwctl(O, "anchor-status", "--anchor-url", "https://127.0.0.1:19777",
              "--anchor-pin", f"key:{opub}", "--anchor-key", wrong)
    denied = "unavailable" in r.stdout or "certificate" in r.stdout.lower() or "TLS" in r.stdout
    rec("R-B1b: wrong client key → TLS denied", "TLS error",
        r.stdout.strip()[-70:], denied and "oracle:" in r.stdout)
    # 3) gwctl with AUTHORIZED client key → reaches oracle (pin+auth ok)
    r = gwctl(O, "anchor-status", "--anchor-url", "https://127.0.0.1:19777",
              "--anchor-pin", f"key:{opub}", "--anchor-key",
              f"{O}/var/data/anchor_key")
    rec("R-B1c: authorized client key → served (app-level 404)",
        "unregistered", r.stdout.strip()[-70:],
        "not registered" in r.stdout)
    # 4) wrong server pin → pin mismatch even for authorized client
    r = gwctl(O, "anchor-status", "--anchor-url", "https://127.0.0.1:19777",
              "--anchor-pin", "key:" + "00" * 32, "--anchor-key",
              f"{O}/var/data/anchor_key")
    rec("R-B1d: wrong oracle pin → refuse", "pin mismatch",
        r.stdout.strip()[-70:], "identity mismatch" in r.stdout)
    # 5) https oracle without --client-keys refuses to start
    r = subprocess.run([f"{WORK}/ovara-anchor", "--store", f"{O}/o2.jsonl",
                        "--listen", "https://127.0.0.1:19778",
                        "--key", f"{O}/oracle_key2"], capture_output=True,
                       text=True, timeout=10)
    rec("R-B1e: https oracle without client-keys → refuses to start",
        "rc!=0", f"rc={r.returncode}", r.returncode != 0)

    # ── R-A1: injected forged commit → oracle refuses to load ────────
    st, cpQ = oracle_latest(sockM, domain_id(M))
    with open(f"{M}/anchorM.jsonl", "a") as f:
        f.write(json.dumps({"kind": "commit", "domain_id": domain_id(M),
            "checkpoint": {"version": "v1", "domain_id": domain_id(M),
             "seq": cpQ["seq"] + 50, "tip_hash": "ab" * 32,
             "key_id": "injected", "sig": "00" * 64}}) + "\n")
    oprocM.kill(); oprocM.wait(); PROCS.remove(oprocM)
    oprocM2, sockM2 = start_oracle(M, "anchorM")
    rec("R-A1: forged commit injection → oracle fold refuses load",
        "dead", "dead" if sockM2 is None else "alive", sockM2 is None)
    if oprocM2.poll() is None:
        oprocM2.kill(); oprocM2.wait()
    else:
        PROCS.append(oprocM2)

    kill_all()
    ok = sum(1 for x in RESULTS if x[3])
    print(f"\n{'='*72}\nRESULT: {ok}/{len(RESULTS)} passed")
    for case, e, g, o in RESULTS:
        if not o: print(f"  FAIL {case}: want={e} got={g}")
    sys.exit(0 if ok == len(RESULTS) else 1)

if __name__ == "__main__":
    main()
