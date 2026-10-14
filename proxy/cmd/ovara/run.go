package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
	"ovara.proxy/internal/sandbox"
	"ovara.runtime.gateway/pkg/server"
)

// `ovara run -- <agent command>`: Ovara starts, the agent runs inside its
// environment, and when the agent exits Ovara stops and says what the run
// did. The deployment is the current directory's, or the default one
// (~/.ovara/run), created on first use; the agent's preset (presets.go) is
// applied to it.

// agentExit is returned when the agent command exited with a status, so
// that `ovara run` exits with the same one.
type agentExit struct{ code int }

func (e *agentExit) Error() string { return fmt.Sprintf("the agent exited with status %d", e.code) }

// defaultRunDir is the deployment `ovara run -- <agent>` uses when the
// current directory has none: ~/.ovara/run of the invoking user.
func defaultRunDir() string {
	home := os.Getenv("HOME")
	if su := os.Getenv("SUDO_USER"); su != "" {
		if u, err := user.Lookup(su); err == nil {
			home = u.HomeDir
		}
	}
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}
	return filepath.Join(home, ".ovara", "run")
}

// runPreset picks the preset for an agent command: "auto" by the program's
// name, "none" for none, or a preset by name.
func runPreset(argv0, choice string) (preset, bool, error) {
	switch choice {
	case "none":
		return preset{}, false, nil
	case "auto":
		p, ok := presetFor(argv0)
		return p, ok, nil
	}
	p, ok := presetNamed(choice)
	if !ok {
		names := make([]string, 0, len(presets))
		for _, q := range presets {
			names = append(names, q.Name)
		}
		return preset{}, false, fmt.Errorf("-preset %q: use auto, none, or one of %s", choice, strings.Join(names, ", "))
	}
	return p, true, nil
}

// agentProcessEnv is the environment the agent command runs with: the
// shell's, minus the variables Ovara sets (replaced by its own values) and
// minus other secret-looking variables (see `ovara env`), plus Ovara's.
func agentProcessEnv(environ []string, vars []envVar) []string {
	set := map[string]bool{}
	for _, v := range vars {
		set[strings.ToUpper(v.name)] = true
	}
	drop := map[string]bool{}
	for _, n := range secretEnvNames(environ, set) {
		drop[strings.ToUpper(n)] = true
	}
	out := make([]string, 0, len(environ)+len(vars))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		up := strings.ToUpper(name)
		if set[up] || drop[up] {
			continue
		}
		out = append(out, kv)
	}
	for _, v := range vars {
		out = append(out, v.name+"="+v.value)
	}
	return out
}

// runAgent starts the agent command with Ovara's environment, waits for
// it, stops Ovara and prints what the run did. If Ovara stops first (a
// signal), the agent is stopped too: it must not outlive its checkpoint.
func runAgent(command []string, cwd, dir string, cfg *config.Config, agentName string, gatewayDone <-chan struct{}) error {
	if agentName != "" {
		tok, err := agentProxyToken(cfg, agentName)
		if err != nil {
			return err
		}
		cfg.AgentToken = tok
	}
	vars, notes, err := agentEnv(dir, cfg, "127.0.0.1")
	if err != nil {
		return err
	}
	for _, n := range notes {
		log.Printf("note: %s", n)
	}
	cmd := exec.Command(command[0], command[1:]...) //nolint:gosec // the agent command is the person's own, given on the command line
	cmd.Dir = cwd
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = agentProcessEnv(os.Environ(), vars)
	before := receiptLineCount(cfg.ReceiptsFile)
	log.Printf("starting the agent through Ovara: %s", strings.Join(command, " "))
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s: %w", command[0], err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
		log.Printf("the agent exited; stopping Ovara")
		server.Stop()
	case <-gatewayDone:
		log.Printf("Ovara is stopping; stopping the agent")
		_ = cmd.Process.Kill()
		waitErr = <-done
	}
	<-gatewayDone
	printRunSummary(cfg.ReceiptsFile, before)
	fmt.Fprintf(os.Stderr, "==> the record: ovara log -dir %s\n", dir)
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		return &agentExit{code: ee.ExitCode()}
	}
	return waitErr
}

// printRunSummary tallies the receipts a run added: how many requests went
// through Ovara, with what decision, to how many hosts.
// printRunSummary tallies the receipts after the first skip lines (what
// the run let through, held and refused, and how many hosts it named),
// prints the line, and returns the tally for the run's summary.
func printRunSummary(receiptsFile string, skip int) (c sandbox.Counts, hosts int) {
	c, hosts, total := tallyReceipts(receiptsFile, skip)
	fmt.Fprintf(os.Stderr, "==> %d request(s) through Ovara: %d allowed, %d paused, %d denied; %d host(s)\n",
		total, c.Allowed, c.Paused, c.Denied, hosts)
	return c, hosts
}

// tallyReceipts counts the receipts after the first skip lines by decision,
// and the distinct hosts they name.
func tallyReceipts(receiptsFile string, skip int) (c sandbox.Counts, hosts, total int) {
	seen := map[string]bool{}
	n := 0
	_ = receipts.ForEachLine(receiptsFile, func(line []byte) error { // absent: a run that made no request
		n++
		if n <= skip {
			return nil
		}
		total++
		var r struct {
			Decision string `json:"decision"`
			URL      string `json:"url"`
		}
		if json.Unmarshal(line, &r) != nil {
			return nil
		}
		switch r.Decision {
		case "allow":
			c.Allowed++
		case "escalate":
			c.Paused++
		case "deny":
			c.Denied++
		}
		if h := r.URL; h != "" {
			if i := strings.Index(h, "://"); i >= 0 {
				h = h[i+3:]
			}
			if i := strings.IndexAny(h, "/?"); i >= 0 {
				h = h[:i]
			}
			seen[h] = true
		}
		return nil
	})
	return c, len(seen), total
}

// receiptLineCount is the number of receipts in the chain, segments
// included (0 when it does not exist yet).
func receiptLineCount(path string) int {
	return receipts.Count(path)
}
