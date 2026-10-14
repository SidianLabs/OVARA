package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The fleet view: every deployment at a glance, one line each. A team runs
// one deployment per agent host, pod or job; `ovara fleet` reads them all
// (named, or every directory under a root that holds a proxy.json) and
// says for each what `ovara status` says for one: the profile, whether the
// gateway runs, the agents and how many are stopped, the approvals waiting
// on a person, whether the record verifies and when it was last written.

type fleetEntry struct {
	Deployment string     `json:"deployment"`
	Profile    string     `json:"profile,omitempty"`
	Baseline   string     `json:"baseline,omitempty"`
	Gateway    bool       `json:"gateway_running"`
	Agents     int        `json:"agents"`
	Stopped    int        `json:"stopped"`
	Pending    int        `json:"pending"` // -1 when the gateway is not running
	Receipts   int        `json:"receipts"`
	Valid      bool       `json:"receipts_valid"`
	Last       *time.Time `json:"last_activity,omitempty"`
	Error      string     `json:"error,omitempty"`
}

func cmdFleet(args []string) error {
	fs := flag.NewFlagSet("fleet", flag.ContinueOnError)
	dirs := fs.String("dirs", "", "deployment directories, comma-separated")
	root := fs.String("root", "", "a directory whose subdirectories are deployments (each with a proxy.json)")
	asJSON := fs.Bool("json", false, "machine-readable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	list, err := fleetDirs(*dirs, *root)
	if err != nil {
		return err
	}
	entries := fleetStatus(list)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}
	printFleet(os.Stdout, entries)
	return nil
}

// fleetDirs is the deployments to look at: the ones named, else every
// subdirectory of root that holds a proxy.json.
func fleetDirs(dirs, root string) ([]string, error) {
	var out []string
	for _, d := range strings.Split(dirs, ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	if root != "" {
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			d := filepath.Join(root, e.Name())
			if _, err := os.Stat(filepath.Join(d, "proxy.json")); err == nil {
				out = append(out, d)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no deployments: name them with -dirs A,B or a parent with -root D")
	}
	sort.Strings(out)
	return out, nil
}

// fleetStatus reads every deployment; one that cannot be read gets an
// entry with the error, never a missing line.
func fleetStatus(dirs []string) []fleetEntry {
	out := make([]fleetEntry, 0, len(dirs))
	for _, d := range dirs {
		e := fleetEntry{Deployment: d, Pending: -1}
		rep, err := deploymentStatus(d)
		if err != nil {
			e.Error = err.Error()
			out = append(out, e)
			continue
		}
		e.Profile, e.Baseline, e.Gateway = rep.Profile, rep.Baseline, rep.Gateway.Running
		e.Receipts, e.Valid, e.Last = rep.Receipts.Total, rep.Receipts.Valid, rep.Receipts.Last
		e.Pending = 0
		for _, a := range rep.Agents {
			e.Agents++
			if a.State == stateStopped {
				e.Stopped++
			}
			if a.Pending < 0 {
				e.Pending = -1
			} else if e.Pending >= 0 {
				e.Pending += a.Pending
			}
		}
		out = append(out, e)
	}
	return out
}

func printFleet(w io.Writer, entries []fleetEntry) {
	fmt.Fprintf(w, "%-28s %-10s %-9s %-14s %-8s %-16s %s\n", "DEPLOYMENT", "PROFILE", "GATEWAY", "AGENTS", "PENDING", "RECEIPTS", "LAST ACTIVITY")
	for _, e := range entries {
		if e.Error != "" {
			fmt.Fprintf(w, "%-28s %s\n", e.Deployment, "ERROR: "+e.Error)
			continue
		}
		gw := "stopped"
		if e.Gateway {
			gw = "running"
		}
		agents := fmt.Sprintf("%d", e.Agents)
		if e.Stopped > 0 {
			agents += fmt.Sprintf(" (%d stopped)", e.Stopped)
		}
		pending := "?"
		if e.Pending >= 0 {
			pending = fmt.Sprintf("%d", e.Pending)
		}
		rec := fmt.Sprintf("%d ok", e.Receipts)
		if !e.Valid {
			rec = fmt.Sprintf("%d FAIL", e.Receipts)
		}
		last := "-"
		if e.Last != nil {
			last = e.Last.Local().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(w, "%-28s %-10s %-9s %-14s %-8s %-16s %s\n", e.Deployment, e.Profile, gw, agents, pending, rec, last)
	}
}
