package main

// Named agents and stopping them.
//
//	ovara agent add NAME     give an agent its own proxy token
//	ovara agent list         the agents, and which are stopped
//	ovara agent remove NAME  take an agent's token away
//	ovara agent restore NAME let a stopped agent back in
//	ovara kill [-agent NAME] stop an agent (every agent without -agent) now
//
// Each named agent has its own token in proxy.json ("agents"), so
// receipts and approvals say which agent did what, and one agent can be
// stopped without stopping the others. `ovara kill` writes the stopped
// list (var/revoked_agents.json, owner-only), which the running proxy
// re-reads within a second, and denies what the agent is waiting on.
// A stopped agent stays stopped across restarts until it is restored.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ovara.proxy/internal/config"
)

// splitName takes the NAME argument from before or after the flags.
func splitName(fs *flag.FlagSet, args []string) (string, error) {
	name := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if name == "" {
		name = fs.Arg(0)
	}
	return name, nil
}

func cmdAgent(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ovara agent add|list|remove|restore [NAME] [-dir .]")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("agent "+sub, flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory (where `ovara init` wrote proxy.json)")
	all := false
	if sub == "restore" {
		fs.BoolVar(&all, "all", false, "let every stopped agent back in")
	}
	name, err := splitName(fs, rest)
	if err != nil {
		return err
	}
	switch sub {
	case "add":
		return agentAdd(os.Stdout, *dir, name)
	case "list":
		return agentList(os.Stdout, *dir)
	case "remove":
		return agentRemove(os.Stdout, *dir, name)
	case "restore":
		if all {
			name = config.AllAgents
		}
		return agentRestore(os.Stdout, *dir, name)
	}
	return fmt.Errorf("unknown: ovara agent %s (use add, list, remove or restore)", sub)
}

func proxyJSONPath(dir string) string { return filepath.Join(dir, "proxy.json") }

// revokedPath is where the deployment in dir keeps its stopped agents.
func revokedPath(dir string) (string, error) {
	cfg, err := config.Load(proxyJSONPath(dir))
	if err != nil {
		return "", fmt.Errorf("cannot read proxy.json in %s: %w (run `ovara init` first, or pass -dir)", dir, err)
	}
	p := cfg.RevokedAgentsFile
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	return p, nil
}

func agentAdd(w io.Writer, dir, name string) error {
	if err := config.ValidAgentName(name); err != nil {
		return err
	}
	agents, _, err := config.ReadAgents(proxyJSONPath(dir))
	if err != nil {
		return err
	}
	if _, ok := agents[name]; ok {
		return fmt.Errorf("agent %q already exists (ovara agent remove %s first to give it a new token)", name, name)
	}
	tok, err := config.NewAgentToken()
	if err != nil {
		return err
	}
	if agents == nil {
		agents = map[string]string{}
	}
	agents[name] = tok
	if err := config.WriteAgents(proxyJSONPath(dir), agents); err != nil {
		return err
	}
	// The token is not printed: scrollback and CI logs keep what is printed.
	fmt.Fprintf(w, "added agent %q: its token is in %s (readable only by you); a running Ovara accepts it within a second\n", name, proxyJSONPath(dir))
	fmt.Fprintf(w, "start it in a shell set up with:  eval \"$(ovara env -dir %s -agent %s)\"\n", dir, name)
	return nil
}

func agentRemove(w io.Writer, dir, name string) error {
	agents, _, err := config.ReadAgents(proxyJSONPath(dir))
	if err != nil {
		return err
	}
	if _, ok := agents[name]; !ok {
		return fmt.Errorf("no agent named %q (see ovara agent list)", name)
	}
	delete(agents, name)
	if err := config.WriteAgents(proxyJSONPath(dir), agents); err != nil {
		return err
	}
	fmt.Fprintf(w, "removed agent %q: a running Ovara refuses its token within a second\n", name)
	return nil
}

func agentList(w io.Writer, dir string) error {
	agents, legacy, err := config.ReadAgents(proxyJSONPath(dir))
	if err != nil {
		return err
	}
	rp, err := revokedPath(dir)
	if err != nil {
		return err
	}
	rv, err := config.LoadRevoked(rp)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(agents))
	for n := range agents {
		names = append(names, n)
	}
	sort.Strings(names)
	if legacy != "" {
		names = append([]string{config.DefaultAgentName}, names...)
	}
	if len(names) == 0 {
		fmt.Fprintln(w, "no agents: the proxy does not ask its clients for a token")
		return nil
	}
	if at, ok := rv.Stopped[config.AllAgents]; ok {
		fmt.Fprintf(w, "EVERY agent was stopped at %s (ovara agent restore -all)\n", at.Local().Format("2006-01-02 15:04:05"))
	}
	for _, n := range names {
		state := "active"
		if at, ok := rv.Stopped[n]; ok {
			state = "STOPPED at " + at.Local().Format("2006-01-02 15:04:05")
		}
		note := ""
		if n == config.DefaultAgentName {
			note = "  (agent_token)"
		}
		fmt.Fprintf(w, "%-20s %s%s\n", n, state, note)
	}
	return nil
}

func agentRestore(w io.Writer, dir, name string) error {
	if name == "" {
		return errors.New("usage: ovara agent restore NAME [-dir .]   (or -all)")
	}
	rp, err := revokedPath(dir)
	if err != nil {
		return err
	}
	rv, err := config.LoadRevoked(rp)
	if err != nil {
		return err
	}
	if name == config.AllAgents {
		rv.Stopped = map[string]time.Time{}
	} else {
		if _, ok := rv.Stopped[name]; !ok {
			if _, all := rv.Stopped[config.AllAgents]; all {
				return fmt.Errorf("every agent is stopped (ovara kill without -agent): use ovara agent restore -all")
			}
			return fmt.Errorf("agent %q is not stopped", name)
		}
		delete(rv.Stopped, name)
	}
	if err := rv.Save(rp); err != nil {
		return err
	}
	who := fmt.Sprintf("agent %q", name)
	if name == config.AllAgents {
		who = "every agent"
	}
	fmt.Fprintf(w, "restored %s: a running Ovara lets it back in within a second\n", who)
	return nil
}

// knownAgent reports whether name is an agent of the deployment.
func knownAgent(dir, name string) (bool, error) {
	agents, legacy, err := config.ReadAgents(proxyJSONPath(dir))
	if err != nil {
		return false, err
	}
	if name == config.DefaultAgentName {
		return legacy != "", nil
	}
	_, ok := agents[name]
	return ok, nil
}

func cmdKill(args []string) error {
	fs, dir := dirFlag("kill")
	agent := fs.String("agent", "", "the agent to stop (see ovara agent list); without it, every agent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return kill(os.Stdout, *dir, *agent, func() (*adminClient, error) { return newAdminClient(*dir) })
}

// kill stops agent (every agent when it is ""): the stopped list first,
// so the proxy refuses it even if the gateway cannot be reached, then the
// approvals it is waiting on are denied.
func kill(w io.Writer, dir, agent string, admin func() (*adminClient, error)) error {
	name := agent
	if name == "" {
		name = config.AllAgents
	} else if ok, err := knownAgent(dir, name); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("no agent named %q (see ovara agent list)", name)
	}
	rp, err := revokedPath(dir)
	if err != nil {
		return err
	}
	rv, err := config.LoadRevoked(rp)
	if err != nil {
		return fmt.Errorf("%w (fix or remove the file, then run ovara kill again)", err)
	}
	rv.Stopped[name] = time.Now().UTC()
	if err := rv.Save(rp); err != nil {
		return err
	}
	who := fmt.Sprintf("agent %q", name)
	if name == config.AllAgents {
		who = "every agent"
	}
	fmt.Fprintf(w, "stopped %s: the running proxy refuses its requests within a second, and it stays stopped after a restart\n", who)

	c, err := admin()
	if err == nil {
		var list []pendingApproval
		if list, err = c.pending(); err == nil {
			denied := 0
			for _, a := range list {
				if name != config.AllAgents && approvalAgent(a) != name {
					continue
				}
				if e := c.resolve(a.ApprovalID, false, whoAmI(), "the agent was stopped by its operator"); e != nil {
					fmt.Fprintf(w, "could not deny %s: %v\n", a.ApprovalID, e)
					continue
				}
				denied++
			}
			fmt.Fprintf(w, "denied %d request(s) it was waiting on\n", denied)
		}
	}
	if err != nil {
		fmt.Fprintf(w, "its waiting requests were not denied (%v); they stop waiting anyway once the proxy sees the stop\n", err)
	}
	restore := name
	if name == config.AllAgents {
		restore = "-all"
	}
	fmt.Fprintf(w, "to let it back in:  ovara agent restore %s -dir %s\n", restore, dir)
	return nil
}

// approvalAgent is the agent an approval is for, as the proxy named it.
func approvalAgent(a pendingApproval) string { return a.Context["agent"] }

// agentProxyToken returns the token `ovara env -agent NAME` hands out.
func agentProxyToken(cfg *config.Config, name string) (string, error) {
	if name == config.DefaultAgentName {
		if cfg.AgentToken == "" {
			return "", errors.New("this deployment has no agent_token")
		}
		return cfg.AgentToken, nil
	}
	tok, ok := cfg.Agents[name]
	if !ok {
		return "", fmt.Errorf("no agent named %q (ovara agent add %s)", name, name)
	}
	return tok, nil
}
