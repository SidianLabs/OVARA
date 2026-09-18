package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"ovara.identity/internal/crypto"
	"ovara.identity/internal/federation"
	"ovara.identity/internal/store"
)

func main() {
	cmd := flag.String("cmd", "help", "Command to run: create-identity, list-identities, issue-lease, list-leases, revoke-lease, suspend-identity, revoke-identity")
	issuer := flag.String("issuer", "ovara", "Issuer name")
	subjectID := flag.String("subject-id", "", "Subject ID")
	owner := flag.String("owner", "", "Owner ID")
	actions := flag.String("actions", "*", "Allowed actions (comma-separated)")
	scope := flag.String("scope", "*", "Resource scope")
	ttl := flag.Int("ttl", 60, "TTL in minutes")
	depth := flag.Int("depth", 0, "Delegation depth")
	identityID := flag.String("identity-id", "", "Identity ID")
	leaseID := flag.String("lease-id", "", "Lease ID")
	keyFile := flag.String("key-file", "", "Path to file containing hex-encoded ed25519 private key of the issuer (required for issue-lease)")
	keyOut := flag.String("key-out", "", "Path to write the generated private key on create-identity (default <id>.key)")
	statePath := flag.String("state", "identities.json", "Path to persist identities and leases (empty = ephemeral, in-memory)")
	flag.Parse()

	r := store.NewRegistry()
	ls := store.NewLeaseStore()
	if *statePath != "" {
		if err := loadState(*statePath, r, ls); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading state: %v\n", err)
			os.Exit(1)
		}
	}
	iss := federation.NewIssuer(r, ls)
	save := func() {
		if *statePath == "" {
			return
		}
		if err := saveState(*statePath, r, ls); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving state: %v\n", err)
			os.Exit(1)
		}
	}

	switch *cmd {
	case "create-identity":
		if *subjectID == "" {
			fmt.Fprintln(os.Stderr, "subject-id is required")
			os.Exit(1)
		}
		id, priv, err := iss.CreateIdentity(*issuer, *subjectID, *owner)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Identity created:\n")
		fmt.Printf("  ID:          %s\n", id.ID)
		fmt.Printf("  Issuer:      %s\n", id.Issuer)
		fmt.Printf("  SubjectID:   %s\n", id.SubjectID)
		fmt.Printf("  Lifecycle:   %s\n", id.Lifecycle)
		fmt.Printf("  Digest:      %s\n", id.Digest())
		out := *keyOut
		if out == "" {
			out = id.ID + ".key"
		}
		if err := os.WriteFile(out, []byte(hex.EncodeToString(priv)), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing key file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  PrivateKey:  written to %s\n", out)
		save()

	case "list-identities":
		identities := r.List()
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tISSUER\tSUBJECT\tLIFECYCLE\tDIGEST")
		for _, id := range identities {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				id.ID, id.Issuer, id.SubjectID, id.Lifecycle, id.Digest()[:16])
		}
		w.Flush()

	case "issue-lease":
		if *identityID == "" || *subjectID == "" || *keyFile == "" {
			fmt.Fprintln(os.Stderr, "identity-id, subject-id, and key-file are required")
			os.Exit(1)
		}
		id, ok := r.Get(*identityID)
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: identity not found: %s\n", *identityID)
			os.Exit(1)
		}
		keyHex, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading key file: %v\n", err)
			os.Exit(1)
		}
		keyBytes, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid private-key hex in %s: %v\n", *keyFile, err)
			os.Exit(1)
		}
		if len(keyBytes) != ed25519.PrivateKeySize {
			fmt.Fprintf(os.Stderr, "Error: private-key must be %d bytes (got %d)\n", ed25519.PrivateKeySize, len(keyBytes))
			os.Exit(1)
		}
		priv := ed25519.PrivateKey(keyBytes)
		actionList := parseActions(*actions)
		lease, err := iss.IssueLease(id.ID, priv, *subjectID, actionList, *scope, *ttl, *depth)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		save()
		fmt.Printf("Lease issued:\n")
		out, _ := json.MarshalIndent(lease, "", "  ")
		fmt.Println(string(out))

	case "list-leases":
		leases := ls.List()
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "LEASE ID\tISSUER\tSUBJECT\tACTIONS\tEXPIRY")
		for _, l := range leases {
			fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\n",
				l.LeaseID, l.Issuer, l.Subject, l.AllowedActions, l.Expiry.Format("2006-01-02T15:04"))
		}
		w.Flush()

	case "revoke-lease":
		if *leaseID == "" {
			fmt.Fprintln(os.Stderr, "lease-id is required")
			os.Exit(1)
		}
		if err := iss.RevokeLease(*leaseID); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		save()
		fmt.Printf("Lease %s revoked\n", *leaseID)

	case "suspend-identity":
		if *identityID == "" {
			fmt.Fprintln(os.Stderr, "identity-id is required")
			os.Exit(1)
		}
		if err := r.Suspend(*identityID); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		save()
		fmt.Printf("Identity %s suspended\n", *identityID)

	case "revoke-identity":
		if *identityID == "" {
			fmt.Fprintln(os.Stderr, "identity-id is required")
			os.Exit(1)
		}
		if err := r.Revoke(*identityID); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		save()
		fmt.Printf("Identity %s revoked\n", *identityID)

	default:
		fmt.Println("Ovara Identity CLI")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  create-identity    Create a new agent identity")
		fmt.Println("  list-identities    List all identities")
		fmt.Println("  issue-lease        Issue a capability lease (requires -key-file)")
		fmt.Println("  list-leases        List all leases")
		fmt.Println("  revoke-lease       Revoke a capability lease")
		fmt.Println("  suspend-identity   Suspend an agent identity")
		fmt.Println("  revoke-identity    Revoke an agent identity")
		fmt.Println()
		fmt.Println("State is persisted to the -state file (default identities.json);")
		fmt.Println("pass -state '' for ephemeral, in-memory operation.")
	}
}

// cliState is the persisted form of the registry and lease store.
type cliState struct {
	Identities []*crypto.AgentIdentity   `json:"identities"`
	Leases     []*crypto.CapabilityLease `json:"leases"`
}

func loadState(path string, r *store.Registry, ls *store.LeaseStore) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var st cliState
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	for _, id := range st.Identities {
		if _, ok := r.Get(id.ID); !ok {
			if err := r.Register(id); err != nil {
				fmt.Fprintf(os.Stderr, "warning: skipping identity %s from %s: %v\n", id.ID, path, err)
			}
		}
	}
	for _, l := range st.Leases {
		if err := ls.Store(l); err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping lease %s from %s: %v\n", l.LeaseID, path, err)
		}
	}
	return nil
}

func saveState(path string, r *store.Registry, ls *store.LeaseStore) error {
	data, err := json.MarshalIndent(cliState{Identities: r.List(), Leases: ls.List()}, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func parseActions(s string) []string {
	if s == "*" {
		return []string{"*"}
	}
	var result []string
	for _, a := range strings.Split(s, ",") {
		if t := strings.TrimSpace(a); t != "" {
			result = append(result, t)
		}
	}
	if len(result) == 0 {
		return []string{"*"}
	}
	return result
}
