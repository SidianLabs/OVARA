package boxgate

import "testing"

// The command line is read from the agent's process: building the
// resource from any argv must never panic.
func FuzzCommandLine(f *testing.F) {
	f.Add("bash", "-c", "rm -rf /")
	f.Add("/usr/bin/sh", "-lc", "x")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		_ = CommandLine(Exec{Argv: []string{a, b, c}})
		_ = CommandLine(Exec{Argv: []string{a}})
		_ = CommandLine(Exec{Exe: a})
	})
}
