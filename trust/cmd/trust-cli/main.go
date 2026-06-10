package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"ovara.trust/internal/graph"
)

func main() {
	cmd := flag.String("cmd", "help", "Command: add-org, list-orgs, federate, revoke-federation, compute-path, snapshot")
	source := flag.String("source", "", "Source domain")
	target := flag.String("target", "", "Target domain")
	name := flag.String("name", "", "Organization name")
	trustLevel := flag.Float64("trust-level", 1.0, "Trust level (0.0-1.0)")
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
	}
}
