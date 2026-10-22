//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ptyDriver runs a command under a pseudo-terminal as its session leader and
// foreground group, as a person's terminal would, types TYPE once the program
// has printed READY, and reports what happened. CI never has a terminal, which
// is how an agent that could not read one went unseen: it ran in a background
// process group, so its first read of the terminal stopped it.
const ptyDriver = `
import os, pty, select, signal, sys, time
timeout = float(sys.argv[1]); send = sys.argv[2].encode().decode("unicode_escape").encode("latin1"); argv = sys.argv[3:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(argv[0], argv)
out = b""; sent = False; t0 = time.time(); status = None
while time.time() - t0 < timeout and status is None:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try: d = os.read(fd, 4096)
        except OSError: d = b""
        if d: out += d
    if not sent and b"READY" in out:
        time.sleep(0.5); os.write(fd, send); sent = True
    p, st = os.waitpid(pid, os.WNOHANG)
    if p: status = st
if status is None:
    # ask it to stop (it stops its proxy), then insist
    os.kill(pid, signal.SIGTERM); time.sleep(8)
    try: os.kill(pid, signal.SIGKILL)
    except OSError: pass
    os.waitpid(pid, 0)
    print("HUNG sent=%s" % sent)
else:
    print("DONE sent=%s" % sent)
sys.stdout.write(out.decode(errors="replace"))
`

// TestBoxTier1_AgentGetsTheTerminal runs a real tier 1 box on a terminal: what
// the person types reaches the agent, and Ctrl-C goes to the agent (as it
// would without Ovara) instead of to Ovara, which used to catch it and send the
// agent SIGTERM.
func TestBoxTier1_AgentGetsTheTerminal(t *testing.T) {
	bin, dir, project := vmE2E(t)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", "ovara-box").Run() })
	cases := []struct {
		name, script, send string
		want               []string
	}{
		{"typed line", "echo READY; read -r l; echo \"got:$l\"; exit 3", `hello\n`, []string{"got:hello", "agent exited with status 3"}},
		{"ctrl-c", "trap 'echo caught-int; exit 7' INT; echo READY; sleep 30 & wait", `\x03`, []string{"caught-int", "agent exited with status 7"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			agent := filepath.Join(t.TempDir(), "agent.sh")
			if err := os.WriteFile(agent, []byte("#!/bin/bash\n"+c.script+"\n"), 0o755); err != nil { //nolint:gosec // a test script that must be executable
				t.Fatal(err)
			}
			_ = exec.Command("ip", "netns", "del", "ovara-box").Run() // a clean start for each box
			args := []string{"-c", ptyDriver, "90", c.send, bin, "box", "-dir", filepath.Join(dir, c.name), "-ui", "off", "-keep", "-no-commit-back",
				"-mount", agent + ":/tmp/agent.sh", project, "--", "bash", "/tmp/agent.sh"}
			out, err := exec.Command("python3", args...).CombinedOutput() //nolint:gosec // the binary under test, driven through a pty
			log := string(out)
			if err != nil {
				t.Fatalf("driver: %v\n%s", err, log)
			}
			if strings.HasPrefix(log, "HUNG") {
				t.Fatalf("the box hung on a terminal (the agent never got it):\n%s", log)
			}
			for _, w := range c.want {
				if !strings.Contains(log, w) {
					t.Errorf("output lacks %q:\n%s", w, log)
				}
			}
		})
	}
}
