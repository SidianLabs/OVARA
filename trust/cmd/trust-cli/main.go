package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"ovara.trust/internal/chain_detection"
	"ovara.trust/internal/degradation"
	"ovara.trust/internal/drift"
	"ovara.trust/internal/graph"
	"ovara.trust/internal/receipt"
	"ovara.trust/internal/state"
)

func main() {
	cmd := flag.String("cmd", "help", "Command: add-org, list-orgs, federate, revoke-federation, compute-path, snapshot, drift-check, trust-score, verify-federated, state")
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
	stateFile := flag.String("state-file", "trust_state.json", "Path to trust state file")
	stateAction := flag.String("state-action", "", "State action: save, load, export, import")
	statePath := flag.String("state-path", "", "Path for state import")
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

	case "state":
		store := state.NewFileStore(*stateFile)
		switch *stateAction {
		case "save":
			detector := drift.NewDriftDetector(10, 0.5)
			model := degradation.NewDegradationModel()
			chainDet := chain_detection.NewChainDetector()

			trustState := &state.TrustState{
				AgentStates:  make(map[string]*state.AgentTrustState),
				AlertHistory: make([]state.AlertRecord, 0),
			}

			driftState := detector.ExportState()
			degState := model.ExportState()
			chainState := chainDet.ExportState()

			merged := mergeStates(driftState, degState, chainState)
			trustState.AgentStates = merged.AgentStates

			if err := store.Save(trustState); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving state: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Trust state saved to %s\n", *stateFile)

		case "load":
			loaded, err := store.Load()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading state: %v\n", err)
				os.Exit(1)
			}
			out, _ := json.MarshalIndent(loaded, "", "  ")
			fmt.Println(string(out))

		case "export":
			detector := drift.NewDriftDetector(10, 0.5)
			model := degradation.NewDegradationModel()
			chainDet := chain_detection.NewChainDetector()

			driftState := detector.ExportState()
			degState := model.ExportState()
			chainState := chainDet.ExportState()

			export := map[string]interface{}{
				"drift":    driftState,
				"degradation": degState,
				"chain":    chainState,
			}
			out, _ := json.MarshalIndent(export, "", "  ")
			fmt.Println(string(out))

		case "import":
			if *statePath == "" {
				fmt.Fprintln(os.Stderr, "state-path is required for import")
				os.Exit(1)
			}
			data, err := os.ReadFile(*statePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading import file: %v\n", err)
				os.Exit(1)
			}
			var importData map[string]json.RawMessage
			if err := json.Unmarshal(data, &importData); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing import file: %v\n", err)
				os.Exit(1)
			}

			detector := drift.NewDriftDetector(10, 0.5)
			model := degradation.NewDegradationModel()
			chainDet := chain_detection.NewChainDetector()

			if raw, ok := importData["drift"]; ok {
				var ds drift.DriftState
				json.Unmarshal(raw, &ds)
				detector.ImportState(ds)
			}
			if raw, ok := importData["degradation"]; ok {
				var ds degradation.DegradationState
				json.Unmarshal(raw, &ds)
				model.ImportState(ds)
			}
			if raw, ok := importData["chain"]; ok {
				var cs chain_detection.ChainState
				json.Unmarshal(raw, &cs)
				chainDet.ImportState(cs)
			}
			fmt.Println("Trust state imported successfully")

		default:
			fmt.Fprintln(os.Stderr, "state-action required: save, load, export, import")
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
		fmt.Println("  state               Trust state persistence (save/load/export/import)")
	}
}

func mergeStates(ds drift.DriftState, deg degradation.DegradationState, cs chain_detection.ChainState) *state.TrustState {
	trustState := &state.TrustState{
		AgentStates:  make(map[string]*state.AgentTrustState),
		AlertHistory: make([]state.AlertRecord, 0),
	}

	agentIDs := make(map[string]bool)
	for id := range ds.Agents {
		agentIDs[id] = true
	}
	for id := range deg.Agents {
		agentIDs[id] = true
	}
	for id := range cs.Agents {
		agentIDs[id] = true
	}

	for id := range agentIDs {
		as := &state.AgentTrustState{
			AgentID: id,
		}

		if das, ok := ds.Agents[id]; ok {
			as.DriftWindow = make([]state.ActionRecord, len(das.Actions))
			for i, a := range das.Actions {
				as.DriftWindow[i] = state.ActionRecord{
					IsRisky:  a.IsRisky,
					Action:   a.Action,
					Timestamp: timeFromNano(a.Timestamp),
				}
			}
		}

		if das, ok := deg.Agents[id]; ok {
			as.TrustScore = das.Score
			as.DegradationStreak = das.Streak
			if das.Score >= 0.8 {
				as.TrustLevel = "high"
			} else if das.Score >= 0.5 {
				as.TrustLevel = "medium"
			} else if das.Score > 0 {
				as.TrustLevel = "low"
			} else {
				as.TrustLevel = "none"
			}
		}

		if records, ok := cs.Agents[id]; ok {
			as.ChainHistory = make([]state.ChainRecord, len(records))
			for i, r := range records {
				as.ChainHistory[i] = state.ChainRecord{
					ChainHash: r.ChainHash,
					Depth:     r.Depth,
					Timestamp: timeFromNano(r.Timestamp),
				}
			}
		}

		trustState.AgentStates[id] = as
	}

	return trustState
}

func timeFromNano(nanos int64) time.Time {
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos).UTC()
}
