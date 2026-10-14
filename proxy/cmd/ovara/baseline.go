package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ovara.runtime.gateway/pkg/baseline"
)

// `ovara policy baseline keygen|sign|verify`: an organisation's baseline
// (policy_baseline_file in config.json) is a policy the project's may only
// narrow. Signed, and with its public key pinned (policy_baseline_pubkey),
// it cannot be swapped for a looser one by whoever can edit the project's
// files: the gateway refuses to start on a baseline that does not verify.
func cmdPolicyBaseline(args []string) error {
	usage := errors.New("usage: ovara policy baseline keygen [-out DIR] | sign [-key FILE] [-in FILE] | verify [-pub FILE|HEX] [-in FILE]")
	if len(args) == 0 {
		return usage
	}
	switch args[0] {
	case "keygen":
		fs := flag.NewFlagSet("policy baseline keygen", flag.ContinueOnError)
		out := fs.String("out", ".", "directory for baseline.key (private, owner-only) and baseline.pub (public)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		pub, priv, err := baseline.KeyGen()
		if err != nil {
			return err
		}
		keyPath, pubPath := filepath.Join(*out, "baseline.key"), filepath.Join(*out, "baseline.pub")
		if err := os.MkdirAll(*out, 0o700); err != nil {
			return err
		}
		if _, err := os.Stat(keyPath); err == nil {
			return fmt.Errorf("%s exists; a new key would orphan every signature made with the old one", keyPath)
		}
		if err := os.WriteFile(keyPath, []byte(priv+"\n"), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(pubPath, []byte(pub+"\n"), 0o644); err != nil { //nolint:gosec // the PUBLIC key
			return err
		}
		fmt.Printf("private key: %s (keep it with whoever signs the baseline; never in the deployment)\npublic key:  %s\n\n", keyPath, pubPath)
		fmt.Printf("pin it in the gateway's config.json:\n  \"policy_baseline_file\": \"baseline.json\",\n  \"policy_baseline_pubkey\": \"%s\"\nthen sign the baseline:  ovara policy baseline sign -key %s -in baseline.json\n", pub, keyPath)
		return nil
	case "sign":
		fs := flag.NewFlagSet("policy baseline sign", flag.ContinueOnError)
		key := fs.String("key", "baseline.key", "the private key file from keygen")
		in := fs.String("in", "baseline.json", "the baseline policy to sign")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		priv, err := os.ReadFile(*key) //nolint:gosec // the operator's own key file
		if err != nil {
			return err
		}
		data, err := os.ReadFile(*in) //nolint:gosec // the operator's own policy file
		if err != nil {
			return err
		}
		sig, err := baseline.Sign(data, string(priv))
		if err != nil {
			return err
		}
		if err := os.WriteFile(baseline.SigPath(*in), []byte(sig+"\n"), 0o644); err != nil { //nolint:gosec // a signature is public
			return err
		}
		fmt.Printf("signed %s: %s (sign again after every change; the gateway refuses a baseline whose signature does not match)\n", *in, baseline.SigPath(*in))
		return nil
	case "verify":
		fs := flag.NewFlagSet("policy baseline verify", flag.ContinueOnError)
		pub := fs.String("pub", "baseline.pub", "the public key: a file, or the hex itself")
		in := fs.String("in", "baseline.json", "the baseline policy")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		pubHex := *pub
		if b, err := os.ReadFile(*pub); err == nil { //nolint:gosec // the operator's own public key file
			pubHex = string(b)
		}
		data, err := os.ReadFile(*in) //nolint:gosec // the operator's own policy file
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(baseline.SigPath(*in)) //nolint:gosec // next to the operator's own file
		if err != nil {
			return fmt.Errorf("no signature to verify: %w", err)
		}
		if err := baseline.Verify(data, strings.TrimSpace(string(sig)), pubHex); err != nil {
			return fmt.Errorf("%s: %w", *in, err)
		}
		fmt.Printf("%s: the signature verifies under this key\n", *in)
		return nil
	}
	return usage
}
