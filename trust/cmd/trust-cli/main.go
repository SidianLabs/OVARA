package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"ovara.trust/internal/degradation"
	"ovara.trust/internal/drift"
	"ovara.trust/internal/graph"
	"ovara.trust/internal/receipt"
)

func main() {
	cmd := flag.String("cmd", "help", "Command: add-org, list-orgs, federate, revoke-federation, compute-path, snapshot, drift-check, trust-score, verify-federated")
	source := flag.String("source", "", "Source domain")
	target := flag.String("target", "", "Target domain")
	name := flag.String("name", "", "Organization name")
	trustLevel := flag.Float64("trust-level", 1.0, "Trust level (0.0-1.0)")
	agentID := flag.String("agent", "", "Agent ID for drift/trust commands")
	decision := flag.String("decision", "", "Decision for trust-score (allow/deny/escalate)")
	digest := flag.String("digest", "", "Federated identity digest")
	domain := flag.String("domain", "", "Federated identity domain")
	pubKeyHex := flag.String("pubkey", "", "Hex-encoded ed25519 public key for verification")
	sigHex := flag.String("sig", "", "Hex-encoded signature for verification")
	flag.Parse()

	tg := graph.NewTrustGraph()

	switch *cmd {
	case "add-org":
		if *source == "" || *name == "" {
			fmt.Fprintln(os.Stderr, "source and name are required")
			os.Exit(1)
		}
		if err := tg.AddOrganization(graph.TrustDomain(*source), *name, nil); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Organization %s (%s) added\n", *source, *name)

	case "list-orgs":
		orgs := tg.GetAllOrganizations()
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "DOMAIN\tNAME\tACTIVE\tJOINED")
		for _, o := range orgs {
			fmt.Fprintf(w, "%s\t%s\t%v\t%s\n", o.Domain, o.Name, o.Active, o.JoinedAt.Format("2006-01-02"))
		}
		w.Flush()

	case "federate":
		if *source == "" || *target == "" {
			fmt.Fprintln(os.Stderr, "source and target are required")
			os.Exit(1)
		}
		if err := tg.Federate(graph.TrustDomain(*source), graph.TrustDomain(*target), *trustLevel, nil); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Federation %s -> %s (trust=%.2f) created\n", *source, *target, *trustLevel)

	case "revoke-federation":
		if *source == "" || *target == "" {
			fmt.Fprintln(os.Stderr, "source and target are required")
			os.Exit(1)
		}
		if err := tg.RevokeFederation(graph.TrustDomain(*source), graph.TrustDomain(*target)); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Federation %s -> %s revoked\n", *source, *target)

	case "compute-path":
		if *source == "" || *target == "" {
			fmt.Fprintln(os.Stderr, "source and target are required")
			os.Exit(1)
		}
		path, err := tg.ComputeTrustPath(graph.TrustDomain(*source), graph.TrustDomain(*target))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Trust path: %v\n", path.Domains)
		fmt.Printf("Trust score: %.4f\n", path.TrustScore)
		fmt.Printf("Depth: %d\n", path.Depth)
		fmt.Printf("Direct: %v\n", path.IsDirect())
		fmt.Printf("Hash: %s\n", path.Hash())

	case "snapshot":
		snap := tg.Snapshot()
		out, _ := json.MarshalIndent(snap, "", "  ")
		fmt.Println(string(out))

	case "drift-check":
		if *agentID == "" {
			fmt.Fprintln(os.Stderr, "agent is required")
			os.Exit(1)
		}
		detector := drift.NewDriftDetector(10, 0.5)
		result := detector.CheckDrift(*agentID)
		fmt.Printf("Agent: %s\n", *agentID)
		fmt.Printf("Drifting: %v\n", result.Drifting)
		fmt.Printf("Confidence: %.2f\n", result.Confidence)
		fmt.Printf("Window: %d\n", result.Window)

	case "trust-score":
		if *agentID == "" {
			fmt.Fprintln(os.Stderr, "agent is required")
			os.Exit(1)
		}
		model := degradation.NewDegradationModel()
		if *decision != "" {
			model.RecordDecision(*agentID, *decision)
		}
		score := model.GetScore(*agentID)
		level := model.GetLevel(*agentID)
		fmt.Printf("Agent: %s\n", *agentID)
		fmt.Printf("Score: %.4f\n", score)
		fmt.Printf("Level: %s\n", level)

	case "verify-federated":
		if *digest == "" || *domain == "" || *pubKeyHex == "" || *sigHex == "" {
			fmt.Fprintln(os.Stderr, "digest, domain, pubkey, and sig are required")
			os.Exit(1)
		}
		pubBytes, err := hex.DecodeString(*pubKeyHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid pubkey hex: %v\n", err)
			os.Exit(1)
		}
		sigBytes, err := hex.DecodeString(*sigHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid sig hex: %v\n", err)
			os.Exit(1)
		}
		fid := &receipt.FederatedIdentity{
			IdentityDigest: *digest,
			Domain:         *domain,
			Signature:      sigBytes,
		}
		pubKey := ed25519.PublicKey(pubBytes)
		if fid.Verify(pubKey) {
			fmt.Println("Signature: VALID")
		} else {
			fmt.Println("Signature: INVALID")
			os.Exit(1)
		}

	default:
		fmt.Println("Ovara Trust CLI")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  add-org             Add an organization to the trust graph")
		fmt.Println("  list-orgs           List all organizations")
		fmt.Println("  federate            Create a federation between two organizations")
		fmt.Println("  revoke-federation   Revoke a federation")
		fmt.Println("  compute-path        Compute the trust path between two organizations")
		fmt.Println("  snapshot            Export the full trust graph as JSON")
		fmt.Println("  drift-check         Check drift for an agent")
		fmt.Println("  trust-score         Get trust score for an agent")
		fmt.Println("  verify-federated    Verify a federated identity signature")
	}
}
