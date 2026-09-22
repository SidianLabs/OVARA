// ovara-gwctl — domain gateway admission tool (P2.3.2) and anchor
// ceremony operator (P2.3.3).
//
// Operator-side command that writes enrollment grants, denials, and
// retirements into the domain gateway registry, and drives the
// anti-rollback anchor ceremonies: init (migration), status, catch-up
// (operator-mediated unanchored-tail recovery), reset (authority
// recovery). The gateway server binary never invokes this path —
// admission authority is separated from the applicant: a gateway
// cannot mint its own grant, it can only consume one an operator
// wrote.
//
// Authority = write access to the domain registry file (flock-
// serialized, same trust boundary as P2.1/P2.2 stores) + the oracle
// operator channel for anchor ceremonies.
//
// usage:
//
//	gwctl grant  --registry F --gateway-id G [--pubkey HEX] [--ttl 600s]
//	             [--anchor-url U --anchor-pin P --anchor-key K]
//	gwctl deny   --registry F --grant-id ID [--anchor-* ...]
//	gwctl retire --registry F --gateway-id G [--anchor-* ...]
//	gwctl list   --registry F [--gateway-id G]
//	gwctl revoke --registry F --class issuer|delegation|lease
//	             --target T [--actor A] [--reason R] [--anchor-* ...]
//	gwctl revocations --registry F
//	gwctl epoch  --registry F
//	gwctl verify-receipt --registry F --receipt receipt.json
//	gwctl anchor-init    --registry F --anchor-url U --anchor-pin P
//	                     --anchor-key K [--attest] [--confirm]
//	gwctl anchor-status  --registry F --anchor-url U --anchor-pin P
//	gwctl anchor-catchup --registry F --anchor-url U --anchor-pin P
//	                     --anchor-key K [--confirm]
//	gwctl anchor-reset   --anchor-url U --anchor-pin P --domain D
//	                     --operator-token T --confirm
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"ovara.runtime.gateway/internal/anchor"
	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/receipt"
	"ovara.runtime.gateway/internal/record"
)

func openReg(path string, create bool) *gwidentity.Registry {
	if path == "" {
		fatal("--registry is required")
	}
	var r *gwidentity.Registry
	var err error
	if create {
		r, err = gwidentity.Open(path)
	} else {
		r, err = gwidentity.OpenExisting(path)
	}
	if err != nil {
		fatal("open registry: %v", err)
	}
	return r
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "gwctl: "+format+"\n", a...)
	os.Exit(1)
}

// anchorClient builds the pinned oracle client for anchor commands.
// For https endpoints the anchor signing key doubles as the TLS client
// identity (mutual pinning); unix endpoints ignore it.
func anchorClient(url, pin, opTok, keyPath string) *anchor.Client {
	if url == "" || pin == "" {
		fatal("--anchor-url and --anchor-pin are required")
	}
	var ck ed25519.PrivateKey
	if strings.HasPrefix(url, "https://") {
		if keyPath == "" {
			fatal("https oracle requires --anchor-key (mutual client-pin identity)")
		}
		var err error
		ck, err = gwidentity.LoadOrCreateKey(keyPath)
		if err != nil {
			fatal("anchor client key: %v", err)
		}
	}
	c, err := anchor.NewClient(url, pin, opTok, ck)
	if err != nil {
		fatal("anchor client: %v", err)
	}
	return c
}

// loadAnchorKey loads the gateway key used to sign checkpoints. The
// key_id label is resolved against the registry when a binding exists;
// for pre-admission journals (no key records yet) an "ext_" label is
// used — the oracle verifies by lineage pubkey, the label is provenance.
func loadAnchorKey(keyPath string, r *gwidentity.Registry) (ed25519.PrivateKey, string) {
	priv, err := gwidentity.LoadOrCreateKey(keyPath)
	if err != nil {
		fatal("anchor key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	keyID := "ext_" + hex.EncodeToString(pub)[:16]
	if r != nil {
		for _, gw := range r.AllGateways() {
			if k := r.FindByPub(gw, pub); k != nil {
				keyID = k.KeyID
				break
			}
		}
	}
	return priv, keyID
}

// signTip produces the checkpoint for the registry's current tip.
func signTip(r *gwidentity.Registry, priv ed25519.PrivateKey, keyID string) *anchor.Checkpoint {
	dom, seq, tip := r.ChainTip()
	if dom == "" {
		fatal("journal is empty — nothing to anchor")
	}
	cp := anchor.Checkpoint{Version: anchor.CheckpointVersion, DomainID: dom,
		Seq: seq, TipHash: hex.EncodeToString(tip[:]), KeyID: keyID}
	s, err := anchor.Sign(priv, cp)
	if err != nil {
		fatal("sign checkpoint: %v", err)
	}
	return &s
}

// printAttestation is the deterministic migration artifact — the
// operator confirms these exact bytes out-of-band. The chain tip
// binds every byte of journal history.
func printAttestation(r *gwidentity.Registry) {
	dom, seq, tip := r.ChainTip()
	fmt.Printf("ANCHOR ATTESTATION\n")
	fmt.Printf("  domain_id : %s\n", dom)
	fmt.Printf("  seq       : %d\n", seq)
	fmt.Printf("  tip_hash  : %x\n", tip)
	fmt.Printf("  gateways  : %s\n", strings.Join(r.AllGateways(), ", "))
	fmt.Printf("  markers   : %d migrate\n", r.Migrated())
}

// tailLines returns the journal records with seq > after — the
// unanchored tail shown to the operator during catch-up.
func tailLines(path string, after uint64) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		fatal("read registry: %v", err)
	}
	var out []string
	pos := uint64(0) // seq IS the line ordinal (non-empty lines)
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		pos++
		var p struct {
			Kind string `json:"kind"`
		}
		json.Unmarshal([]byte(line), &p)
		if pos > after {
			out = append(out, fmt.Sprintf("[seq %d kind %s] %s", pos, p.Kind, line))
		}
	}
	return out
}

// pushTip signs + commits the current tip; used after gwctl mutations
// when --anchor-url/--anchor-pin/--anchor-key are all present so the
// operator path keeps the oracle in step with the journal.
func pushTip(r *gwidentity.Registry, c *anchor.Client, priv ed25519.PrivateKey, keyID string) {
	cp := signTip(r, priv, keyID)
	if err := c.Commit(context.Background(), cp.DomainID, cp); err != nil {
		fatal("anchor commit failed (mutation is durable, tail is unanchored): %v", err)
	}
	fmt.Printf("anchored: seq=%d tip=%s\n", cp.Seq, cp.TipHash[:16])
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: gwctl <grant|deny|retire|list|anchor-init|anchor-status|anchor-catchup|anchor-reset> [flags]")
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	reg := fs.String("registry", "", "domain registry file")
	gw := fs.String("gateway-id", "", "gateway id")
	pub := fs.String("pubkey", "", "pinned ed25519 public key (hex, optional)")
	ttl := fs.Duration("ttl", 0, "grant lifetime (0 = no expiry)")
	grantID := fs.String("grant-id", "", "grant id")
	aURL := fs.String("anchor-url", "", "oracle endpoint (unix:///path | https://addr)")
	aPin := fs.String("anchor-pin", "", "oracle identity pin (uid:<n> | key:<hex-pub>)")
	aKey := fs.String("anchor-key", "", "anchor signing key file (checkpoint signer)")
	newKey := fs.String("new-key", "", "anchor-addkey: new lineage key file")
	opTok := fs.String("operator-token", "", "oracle operator token (reset)")
	domain := fs.String("domain", "", "anchor domain id (reset)")
	confirm := fs.Bool("confirm", false, "explicit operator confirmation for authority operations")
	attest := fs.Bool("attest", false, "anchor-init: print attestation artifact and exit")
	gwKeyFile := fs.String("gateway-key", "", "migrate: gateway private key file (ed25519 hex, 0600)")
	mStores := fs.String("stores", "", "migrate: comma list name=path — idregistry|capabilities (sealed import), receipts|replay (verified import), continuation|approval|execution|events (quarantine)")
	class := fs.String("class", "", "revocation class: issuer | delegation | lease")
	target := fs.String("target", "", "revocation target (canonical id for the class)")
	actor := fs.String("actor", "", "revocation actor identity (default: operator)")
	reason := fs.String("reason", "", "revocation reason (audit)")
	rcptFile := fs.String("receipt", "", "verify-receipt: path to receipt JSON")
	fs.Parse(args)

	ctx := context.Background()

	switch cmd {
	case "anchor-init":
		r := openReg(*reg, false)
		defer r.Close()
		dom, seq, _ := r.ChainTip()
		if dom == "" || seq == 0 {
			fatal("empty journal — nothing to migrate (fail closed)")
		}
		// Attestation first — always printed, so the operator can
		// compare out-of-band before confirming.
		printAttestation(r)
		if *attest {
			return
		}
		if !*confirm {
			fmt.Printf("re-run with --confirm to register the genesis checkpoint\n")
			return
		}
		c := anchorClient(*aURL, *aPin, "", *aKey)
		priv, keyID := loadAnchorKey(*aKey, r)
		if r.Migrated() == 0 {
			// The migrate marker is appended BEFORE the genesis
			// checkpoint so the checkpoint covers the migration event.
			if err := r.AppendMarker(); err != nil {
				fatal("append migrate marker: %v", err)
			}
		} else {
			// F-E1: a marker without oracle registration is a crashed
			// init — resume by registering the CURRENT tip instead of
			// demanding manual journal surgery. Registered+same-tip is
			// idempotent success; registered+different refuses.
			a, err := c.Latest(ctx, dom)
			switch {
			case errors.Is(err, anchor.ErrDomainUnregistered):
				fmt.Printf("journal migrated but oracle unregistered — resuming init (registering current tip)\n")
			case err != nil:
				fatal("oracle latest: %v", err)
			default:
				_, lseq, ltip := r.ChainTip()
				if a.Seq == lseq && a.TipHash == hex.EncodeToString(ltip[:]) {
					fmt.Printf("already initialized: domain=%s seq=%d\n", dom, lseq)
					return
				}
				fatal("journal migrated and oracle holds different state (oracle seq=%d local seq=%d) — refusing to re-initialize an anchored domain; use anchor-catchup for an unanchored tail", a.Seq, lseq)
			}
		}
		cp := signTip(r, priv, keyID)
		if err := c.Register(ctx, cp.DomainID, cp, priv.Public().(ed25519.PublicKey), keyID); err != nil {
			if errors.Is(err, anchor.ErrDomainRegistered) {
				fatal("domain already registered at oracle — refusing to adopt existing state (verify journal vs oracle out-of-band)")
			}
			fatal("register: %v", err)
		}
		fmt.Printf("anchor initialized: domain=%s seq=%d tip=%s\n", cp.DomainID, cp.Seq, cp.TipHash[:16])

	case "anchor-status":
		r := openReg(*reg, false)
		defer r.Close()
		dom, seq, tip := r.ChainTip()
		fmt.Printf("local : domain=%s seq=%d tip=%x markers=%d\n", dom, seq, tip, r.Migrated())
		c := anchorClient(*aURL, *aPin, "", *aKey)
		a, err := c.Latest(ctx, dom)
		if err != nil {
			fmt.Printf("oracle: %v\n", err)
			return
		}
		fmt.Printf("oracle: seq=%d tip=%s key_id=%s\n", a.Seq, a.TipHash, a.KeyID)
		switch {
		case seq < a.Seq:
			fmt.Printf("verdict: LOCAL BEHIND — rollback, refuse\n")
		case seq == a.Seq && hex.EncodeToString(tip[:]) == a.TipHash:
			fmt.Printf("verdict: IN SYNC\n")
		case seq == a.Seq:
			fmt.Printf("verdict: EQUIVOCATION — same seq, different tip\n")
		default:
			fmt.Printf("verdict: UNANCHORED TAIL (local ahead) — run anchor-catchup\n")
		}

	case "anchor-catchup":
		r := openReg(*reg, false)
		defer r.Close()
		dom, seq, tip := r.ChainTip()
		c := anchorClient(*aURL, *aPin, "", *aKey)
		a, err := c.Latest(ctx, dom)
		if err != nil {
			fatal("oracle latest: %v", err)
		}
		switch {
		case seq < a.Seq:
			fatal("local journal BEHIND oracle (seq %d < %d) — rollback; catch-up cannot fix this, restore the journal", seq, a.Seq)
		case seq == a.Seq:
			if hex.EncodeToString(tip[:]) != a.TipHash {
				fatal("equivocation at seq %d — refusing", seq)
			}
			fmt.Printf("already in sync at seq %d\n", seq)
			return
		}
		fmt.Printf("unanchored tail: local seq %d > oracle seq %d\n", seq, a.Seq)
		fmt.Printf("UNANCHORED RECORDS:\n")
		for _, l := range tailLines(*reg, a.Seq) {
			fmt.Printf("  %s\n", l)
		}
		fmt.Printf("new tip: %x\n", tip)
		if !*confirm {
			fmt.Printf("re-run with --confirm to commit this tip to the oracle\n")
			return
		}
		priv, keyID := loadAnchorKey(*aKey, r)
		cp := signTip(r, priv, keyID)
		if err := c.Commit(ctx, dom, cp); err != nil {
			fatal("commit: %v", err)
		}
		fmt.Printf("caught up: seq=%d\n", cp.Seq)

	case "anchor-addkey":
		// Lineage extension for anchor-key rotation: --anchor-key is
		// the CURRENT lineage key (introducer), --new-key the key being
		// added. Signed by the introducer — self-introduction is not
		// authorized.
		c := anchorClient(*aURL, *aPin, "", *aKey)
		introPriv, introID := loadAnchorKey(*aKey, nil)
		newPriv, _ := loadAnchorKey(*newKey, nil)
		newPub := newPriv.Public().(ed25519.PublicKey)
		if *domain == "" {
			fatal("--domain is required")
		}
		newKeyID := "ext_" + hex.EncodeToString(newPub)[:16]
		if err := c.AddKey(ctx, *domain, newPub, newKeyID, introPriv); err != nil {
			fatal("addkey (introducer %s): %v", introID, err)
		}
		fmt.Printf("anchor key added to lineage: %s\n", newKeyID)

	case "anchor-reset":
		if *domain == "" {
			fatal("--domain is required")
		}
		if !*confirm {
			fatal("anchor-reset deletes the domain's anchored authority state — requires --confirm (recovery re-runs anchor-init)")
		}
		c := anchorClient(*aURL, *aPin, *opTok, *aKey)
		if err := c.Reset(ctx, *domain); err != nil {
			fatal("reset: %v", err)
		}
		fmt.Printf("anchor domain %s reset — re-run anchor-init to re-establish\n", *domain)

	case "revocations":
		r := openReg(*reg, false)
		defer r.Close()
		recs, err := r.Revocations()
		if err != nil {
			fatal("revocations: %v", err)
		}
		_, seq, _ := r.ChainTip()
		for _, rv := range recs {
			fmt.Printf("revoke class=%s target=%s actor=%s epoch=%d reason=%q at=%s\n",
				rv.Class, rv.Target, rv.Actor, rv.Seq, rv.Reason,
				rv.RevokedAt.Format(time.RFC3339))
		}
		fmt.Printf("epoch: %d  revocations: %d\n", seq, len(recs))

	case "epoch":
		r := openReg(*reg, false)
		defer r.Close()
		_, seq, tip := r.ChainTip()
		fmt.Printf("epoch: %d  tip: %x\n", seq, tip)

	case "migrate":
		r := openReg(*reg, false)
		defer r.Close()
		runMigrate(r, *gw, *gwKeyFile, *mStores, *confirm)

	case "verify-receipt":
		// P2.3.5 independent verification: the verifier needs ONLY the
		// registry file (public material) + the receipt — never the
		// gateway's private key or HMAC secret. Key resolution is
		// authoritative-registry only; historical states still verify.
		if *rcptFile == "" {
			fatal("--receipt <receipt.json> is required")
		}
		data, err := os.ReadFile(*rcptFile)
		if err != nil {
			fatal("read receipt: %v", err)
		}
		var rcpt models.Receipt
		if err := json.Unmarshal(data, &rcpt); err != nil {
			fatal("receipt JSON: %v", err)
		}
		r := openReg(*reg, false)
		defer r.Close()
		valid, verr := receipt.VerifySignature(receipt.RegistryResolver{Reg: r}, &rcpt)
		switch {
		case valid:
			fmt.Printf("VALID  gateway_id=%s key_id=%s trust_epoch=%d\n",
				rcpt.GatewayID, rcpt.GatewayKeyID, rcpt.TrustEpoch)
		case verr != nil:
			fmt.Printf("INVALID  %v\n", verr)
			os.Exit(1)
		default:
			fmt.Printf("INVALID  signature does not verify\n")
			os.Exit(1)
		}

	default:
		// Original admission commands — registry-backed.
		r := openReg(*reg, cmd == "grant")
		defer r.Close()
		// Optional inline anchoring: when all three anchor flags are
		// present, every committed mutation pushes its tip so the
		// oracle tracks operator changes immediately.
		var ac *anchor.Client
		var apriv ed25519.PrivateKey
		var akeyID string
		if *aURL != "" || *aPin != "" || *aKey != "" {
			if *aURL == "" || *aPin == "" || *aKey == "" {
				fatal("--anchor-url, --anchor-pin, and --anchor-key must be given together")
			}
			ac = anchorClient(*aURL, *aPin, "", *aKey)
			apriv, akeyID = loadAnchorKey(*aKey, r)
		}
		push := func() {
			if ac != nil {
				pushTip(r, ac, apriv, akeyID)
			}
		}

		switch cmd {
		case "grant":
			if *gw == "" {
				fatal("--gateway-id is required")
			}
			var pk []byte
			if *pub != "" {
				var err error
				pk, err = hex.DecodeString(*pub)
				if err != nil || len(pk) != 32 {
					fatal("--pubkey must be 32-byte hex")
				}
			}
			g, err := r.Authorize(*gw, pk, *ttl)
			if err != nil {
				fatal("grant: %v", err)
			}
			fmt.Printf("grant authorized: grant_id=%s gateway_id=%s pinned=%v expires=%s\n",
				g.GrantID, g.GatewayID, g.PublicKey != "",
				g.ExpiresAt.Format(time.RFC3339))
			push()

		case "deny":
			if *grantID == "" {
				fatal("--grant-id is required")
			}
			if err := r.Deny(*grantID); err != nil {
				fatal("deny: %v", err)
			}
			fmt.Printf("grant denied: %s\n", *grantID)
			push()

		case "retire":
			if *gw == "" {
				fatal("--gateway-id is required")
			}
			if err := r.Destroy(*gw); err != nil {
				fatal("retire: %v", err)
			}
			fmt.Printf("gateway retired (tombstoned): %s\n", *gw)
			push()

		case "revoke":
			// P2.3.4 revocation authority — same boundary as grants:
			// write access to the domain journal IS the authority.
			// The kill is durable immediately; --anchor-* pushes the tip.
			if *class == "" || *target == "" {
				fatal("--class (issuer|delegation|lease) and --target are required")
			}
			rv, err := r.Revoke(*class, *target, *actor, *reason)
			if err != nil {
				fatal("revoke: %v", err)
			}
			fmt.Printf("revoked: class=%s target=%s epoch=%d\n", rv.Class, rv.Target, rv.Seq)
			push()

		case "list":
			ids := []string{*gw}
			if *gw == "" {
				ids = r.AllGateways()
			}
			for _, id := range ids {
				recs, err := r.Lookup(id)
				if err != nil {
					continue
				}
				for _, k := range recs {
					fmt.Printf("key    %s  %s  state=%s gen=%d pub=%s…\n",
						k.GatewayID, k.KeyID, k.State, k.Generation, k.PublicKey[:12])
				}
				gs, _ := r.GrantsFor(id)
				for _, g := range gs {
					fmt.Printf("grant  %s  %s  state=%s pinned=%v expires=%s\n",
						g.GatewayID, g.GrantID, g.State, g.PublicKey != "",
						g.ExpiresAt.Format(time.RFC3339))
				}
			}

		default:
			fatal("unknown command %q", cmd)
		}
	}
}

// --- migrate (P2.4) ---------------------------------------------------------

// runMigrate converts 2.0 stores to 2.1 signed form under explicit
// operator attestation (design §16, MIG-01..03):
//
//   - sealed-file stores (idregistry, capabilities): legacy payload
//     imported verbatim into a signed snapshot (file_seq=1) — the
//     operator's --confirm IS the blessing of unsigned provenance.
//   - verified-record stores (receipts, replay): individually
//     verifiable records are imported (edsig_v1 receipts; live replay
//     consume keys — dropping live nonces would reopen replay
//     windows). Receipts failing verification are skipped and reported.
//   - mutable-state stores (continuation, approval, execution,
//     events): legacy contents are NEVER imported — unsigned
//     provenance cannot be honestly vouched. The file is quarantined
//     to <path>.pre21 and a signed migration marker records the
//     quarantine hash on the fresh journal.
//
// Every write is preceded by the printed plan; --confirm executes.
func runMigrate(r *gwidentity.Registry, gwID, keyFile, stores string, confirm bool) {
	if gwID == "" || keyFile == "" {
		fatal("migrate requires --gateway-id and --gateway-key")
	}
	if stores == "" {
		fatal("migrate requires --stores name=path[,name=path...]")
	}
	priv, err := gwidentity.LoadOrCreateKey(keyFile)
	if err != nil {
		fatal("gateway key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	rec := r.FindByPub(gwID, pub)
	if rec == nil {
		fatal("no registered key matching --gateway-key for %s — refusing to sign migration with an unbound key", gwID)
	}
	signer := record.NewSigner(priv, r.DomainID(), gwID, rec.KeyID)
	resolver := receipt.RegistryResolver{Reg: r}

	type job struct{ name, path string }
	var jobs []job
	for _, kv := range strings.Split(stores, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		name, path, ok := strings.Cut(kv, "=")
		if !ok || name == "" || path == "" {
			fatal("--stores entry %q must be name=path", kv)
		}
		switch name {
		case "idregistry", "capabilities", "receipts", "replay",
			"continuation", "approval", "execution", "events":
		default:
			fatal("unknown store %q", name)
		}
		jobs = append(jobs, job{name, path})
	}

	fmt.Printf("OVARA 2.0 → 2.1 migration plan (gateway=%s domain=%s):\n", gwID, r.DomainID())
	for _, j := range jobs {
		data, err := os.ReadFile(j.path)
		switch {
		case os.IsNotExist(err):
			fmt.Printf("  %-14s %s — absent, skipped\n", j.name, j.path)
		case err != nil:
			fatal("read %s: %v", j.path, err)
		case len(data) == 0:
			fmt.Printf("  %-14s %s — empty, skipped\n", j.name, j.path)
		case alreadySigned(data):
			fmt.Printf("  %-14s %s — already signed, skipped\n", j.name, j.path)
		default:
			sum := sha256.Sum256(data)
			fmt.Printf("  %-14s %s — legacy, %d bytes sha256=%s\n", j.name, j.path, len(data), hex.EncodeToString(sum[:])[:16])
		}
	}
	if !confirm {
		fmt.Println("re-run with --confirm to execute")
		return
	}

	tips := map[string]gwidentity.Tip{}
	for _, j := range jobs {
		data, err := os.ReadFile(j.path)
		if os.IsNotExist(err) || len(data) == 0 || alreadySigned(data) {
			continue
		}
		if err != nil {
			fatal("read %s: %v", j.path, err)
		}
		sum := sha256.Sum256(data)
		switch j.name {
		case "idregistry", "capabilities":
			// Operator-blessed verbatim import under a signed snapshot.
			var probe any
			if json.Unmarshal(data, &probe) != nil {
				fatal("%s: legacy payload is not valid JSON — refusing to import", j.path)
			}
			quarantine(j.path, data)
			sealed, err := record.SealFile(j.name, signer, data, nil, 0)
			if err != nil {
				fatal("seal %s: %v", j.name, err)
			}
			if err := os.WriteFile(j.path, sealed, 0o600); err != nil {
				fatal("write sealed %s: %v", j.path, err)
			}
			tips[j.name] = gwidentity.Tip{Seq: 1, Hash: record.TipHash(sealed)}
			fmt.Printf("  %-14s sealed (file_seq=1) %s\n", j.name, j.path)
		default:
			journalMigrate(j.name, j.path, data, sum, signer, resolver, tips)
		}
	}
	if len(tips) > 0 {
		if err := r.RecordTips(gwID, tips); err != nil {
			fatal("tip-ledger commit failed (migrated files are durable): %v", err)
		}
	}
	fmt.Printf("migration complete — %d store(s) ledgered\n", len(tips))
}

// alreadySigned sniffs sealed files (_sec key) and journals (first
// non-empty line carries sig+parent+v) so re-runs are idempotent.
func alreadySigned(data []byte) bool {
	s := strings.TrimLeft(string(data), " \t\r\n")
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(line, &m) != nil {
			return false
		}
		if _, ok := m["_sec"]; ok {
			return true
		}
		_, sig := m["sig"]
		_, parent := m["parent"]
		_, v := m["v"]
		return sig && parent && v
	}
	return false
}

// quarantine moves a legacy file aside before its signed replacement
// lands. Refuses to clobber an existing quarantine — the operator
// resolves collisions by hand (MIG-01: one migration per store).
func quarantine(path string, data []byte) string {
	q := path + ".pre21"
	if _, err := os.Stat(q); err == nil {
		fatal("%s already exists — resolve manually", q)
	}
	if err := os.WriteFile(q, data, 0o600); err != nil {
		fatal("quarantine %s: %v", q, err)
	}
	if err := os.Remove(path); err != nil {
		fatal("remove legacy %s: %v", path, err)
	}
	return q
}

// journalMigrate quarantines the legacy file, opens a fresh signed
// journal in its place, imports what is honestly importable, and
// appends a migration marker binding (store, quarantine hash) into the
// chain.
func journalMigrate(store, path string, legacy []byte, sum [32]byte,
	signer *record.Signer, resolver receipt.RegistryResolver,
	tips map[string]gwidentity.Tip) {

	q := quarantine(path, legacy)
	// Fresh journal — apply never fires on an empty file; the marker
	// append then extends the genesis parent.
	j, err := record.Open(store, path, signer.Domain(), signer, resolver.ResolvePublicKey,
		record.Floor{}, func(*record.Envelope) error {
			return fmt.Errorf("unexpected record in fresh %s journal", store)
		})
	if err != nil {
		fatal("open %s journal: %v", store, err)
	}
	defer j.Close()

	imported, skipped := 0, 0
	switch store {
	case "replay":
		// Live consume keys carry over — dropping them would reopen
		// replay windows for in-flight leases.
		sc := bufio.NewScanner(strings.NewReader(string(legacy)))
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			var e struct {
				Kind      string    `json:"k"`
				ID        string    `json:"p"`
				ExpiresAt time.Time `json:"e,omitempty"`
			}
			if json.Unmarshal(line, &e) != nil || e.ID == "" {
				skipped++
				continue
			}
			if !e.ExpiresAt.IsZero() && !e.ExpiresAt.After(time.Now().UTC()) {
				skipped++ // dead key — not worth importing
				continue
			}
			payload := map[string]any{"k": e.Kind, "p": e.ID, "c": time.Now().UTC()}
			if !e.ExpiresAt.IsZero() {
				payload["e"] = e.ExpiresAt
			}
			if _, _, err := j.Append("consume", e.Kind+"\x00"+e.ID, payload, nil); err != nil {
				fatal("replay import: %v", err)
			}
			imported++
		}
	case "receipts":
		// edsig_v1 receipts are self-verifying — import only those
		// whose signatures still verify against the registry.
		var arr []json.RawMessage
		if err := json.Unmarshal(legacy, &arr); err == nil {
			for _, raw := range arr {
				var rcpt models.Receipt
				if json.Unmarshal(raw, &rcpt) != nil || rcpt.ReceiptID == "" {
					skipped++
					continue
				}
				ok, verr := receipt.VerifySignature(resolver, &rcpt)
				if !ok || verr != nil {
					skipped++
					continue
				}
				if _, _, err := j.Append("receipt", rcpt.ReceiptID, raw, nil); err != nil {
					fatal("receipt import: %v", err)
				}
				imported++
			}
		} else {
			skipped = -1 // unparseable list — quarantined wholesale
		}
	}

	marker := map[string]any{
		"migrated_from": "ovara-2.0",
		"store":         store,
		"quarantined":   q,
		"legacy_sha256": hex.EncodeToString(sum[:]),
		"imported":      imported,
		"skipped":       skipped,
		"migrated_at":   time.Now().UTC().Format(time.RFC3339),
	}
	seq, tip, err := j.Append(record.TypeMigration, "migration-0", marker, nil)
	if err != nil {
		fatal("migration marker %s: %v", store, err)
	}
	tips[store] = gwidentity.Tip{Seq: seq, Hash: tip}
	fmt.Printf("  %-14s quarantined → signed journal (imported=%d skipped=%d) %s\n", store, imported, skipped, path)
}
