package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
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
	flag.Parse()

	r := store.NewRegistry()
	ls := store.NewLeaseStore()
	iss := federation.NewIssuer(r, ls)

	switch *cmd {
	case "create-identity":
		if *subjectID == "" {
			fmt.Fprintln(os.Stderr, "subject-id is required")
			os.Exit(1)
		}
		id, _, err := iss.CreateIdentity(*issuer, *subjectID, *owner)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Identity created:\n")
		fmt.Printf("  ID:         %s\n", id.ID)
		fmt.Printf("  Issuer:     %s\n", id.Issuer)
		fmt.Printf("  SubjectID:  %s\n", id.SubjectID)
		fmt.Printf("  Lifecycle:  %s\n", id.Lifecycle)
		fmt.Printf("  Digest:     %s\n", id.Digest())

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
		if *identityID == "" || *subjectID == "" {
			fmt.Fprintln(os.Stderr, "identity-id and subject-id are required")
			os.Exit(1)
		}
		id, ok := r.Get(*identityID)
		if !ok {
			// For demo: create identity first
			var err error
			id, _, err = crypto.NewAgentIdentity(*issuer, *subjectID, *owner)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			r.Register(id)
			*identityID = id.ID
			fmt.Printf("Auto-created identity: %s\n", id.ID)
		}
		// For CLI demo, generate a fresh key (real use would load from storage)
		_, priv, _ := crypto.NewAgentIdentity(*issuer, "tmp", "tmp")
		actionList := parseActions(*actions)
		lease, err := crypto.IssueCapabilityLease(id, priv, *subjectID, actionList, *scope, *ttl, *depth)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		ls.Store(lease)
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
		fmt.Printf("Identity %s revoked\n", *identityID)

	default:
		fmt.Println("Ovara Identity CLI")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  create-identity    Create a new agent identity")
		fmt.Println("  list-identities    List all identities")
		fmt.Println("  issue-lease        Issue a capability lease")
		fmt.Println("  list-leases        List all leases")
		fmt.Println("  revoke-lease       Revoke a capability lease")
		fmt.Println("  suspend-identity   Suspend an agent identity")
		fmt.Println("  revoke-identity    Revoke an agent identity")
	}
}

func parseActions(s string) []string {
	if s == "*" {
		return []string{"*"}
	}
	var result []string
	for _, a := range stringsSplit(s, ",") {
		if t := trimSpace(a); t != "" {
			result = append(result, t)
		}
	}
	if len(result) == 0 {
		return []string{"*"}
	}
	return result
}

func stringsSplit(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep[0] {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
