package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Lima drives a Lima VM (https://lima-vm.io) through `limactl`, for macOS.
// It needs Lima 1.0 or later.
type Lima struct {
	// Limactl is the limactl binary; empty means "limactl" on PATH.
	Limactl string
	// Dir holds the instance configs Ovara writes; empty means the
	// system temporary directory.
	Dir string
}

// limaHost is how a Lima guest names the host. Lima writes it into the
// guest's hosts file, so it resolves without DNS (which the lockdown drops).
const limaHost = "host.lima.internal"

// Ubuntu 24.04 LTS cloud images, the guest the box runs in.
var limaImages = []limaImage{
	{Location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img", Arch: "x86_64"},
	{Location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img", Arch: "aarch64"},
}

func (l *Lima) Name() string { return "lima" }

// limaConfig is the subset of Lima's instance configuration Ovara sets. It
// is written as JSON, which Lima reads as YAML. Every setting that would
// let the guest see or reach the host is turned off explicitly rather than
// left to Lima's defaults, which share the home directory and forward ports.
type limaConfig struct {
	Images            []limaImage       `json:"images"`
	CPUs              int               `json:"cpus"`
	Memory            string            `json:"memory"`
	Disk              string            `json:"disk"`
	Mounts            []any             `json:"mounts"` // none: the workspace is copied in, never shared
	SSH               limaSSH           `json:"ssh"`
	Containerd        limaContainerd    `json:"containerd"`
	PortForwards      []limaPortForward `json:"portForwards"`
	PropagateProxyEnv bool              `json:"propagateProxyEnv"` // the host's proxy settings and their credentials stay on the host
	Provision         []limaProvision   `json:"provision"`
}

type limaImage struct {
	Location string `json:"location"`
	Arch     string `json:"arch"`
}

type limaSSH struct {
	ForwardAgent      bool `json:"forwardAgent"`      // the host's SSH keys are not offered to the guest
	ForwardX11        bool `json:"forwardX11"`        // nor its display
	LoadDotSSHPubKeys bool `json:"loadDotSSHPubKeys"` // the host user's keys are not authorised in the guest
}

type limaContainerd struct {
	System bool `json:"system"`
	User   bool `json:"user"`
}

type limaPortForward struct {
	GuestIP        string `json:"guestIP,omitempty"`
	GuestPortRange [2]int `json:"guestPortRange"`
	Ignore         bool   `json:"ignore"`
}

type limaProvision struct {
	Mode   string `json:"mode"`
	Script string `json:"script"`
}

// Config renders the instance configuration for spec.
func (l *Lima) Config(spec Spec) ([]byte, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	c := limaConfig{
		Images: limaImages,
		CPUs:   spec.CPUs,
		Memory: fmt.Sprintf("%dGiB", spec.MemoryGiB),
		Disk:   fmt.Sprintf("%dGiB", spec.DiskGiB),
		Mounts: []any{},
		// no port a guest process opens is forwarded to the host, on the
		// loopback or any address
		PortForwards: []limaPortForward{
			{GuestPortRange: [2]int{1, 65535}, Ignore: true},
			{GuestIP: "0.0.0.0", GuestPortRange: [2]int{1, 65535}, Ignore: true},
		},
		Provision: []limaProvision{{Mode: "system", Script: provisionScript(limaHost, spec.ProxyPort, spec.GatePort)}},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (l *Lima) bin() string {
	if l.Limactl != "" {
		return l.Limactl
	}
	return "limactl"
}

// limactl runs one limactl command and returns its standard output; on
// failure the error carries what it printed.
func (l *Lima) limactl(ctx context.Context, stdio *Stdio, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, l.bin(), args...) //nolint:gosec // limactl with arguments built here from a validated spec
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if stdio != nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = stdio.Stdin, stdio.Stdout, stdio.Stderr
	}
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		return out.String(), fmt.Errorf("limactl %s: %w: %s", args[0], err, msg)
	}
	return out.String(), nil
}

// Create writes the instance config and creates and starts the VM.
func (l *Lima) Create(ctx context.Context, spec Spec) error {
	cfg, err := l.Config(spec)
	if err != nil {
		return err
	}
	// a fresh private directory, so no one can plant the file in advance
	dir, err := os.MkdirTemp(l.Dir, spec.Name+"-")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "lima.yaml")
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		return err
	}
	if _, err := l.limactl(ctx, nil, "create", "--tty=false", "--name="+spec.Name, path); err != nil {
		return err
	}
	_, err = l.limactl(ctx, nil, "start", "--tty=false", spec.Name)
	return err
}

// Verify checks, from inside the guest, that the lockdown table is loaded
// and that a direct connection out fails. Both must hold; anything else,
// including an error running the check, is a refusal.
func (l *Lima) Verify(ctx context.Context, name string) error {
	if !ValidName(name) {
		return fmt.Errorf("vm name %q is not one Ovara made", name)
	}
	rules, err := l.limactl(ctx, nil, "shell", "--workdir=/", name, "--", "sudo", "nft", "list", "table", "inet", lockdownTable)
	if err != nil {
		return fmt.Errorf("vm %s: the network lockdown is not loaded: %w", name, err)
	}
	if !strings.Contains(rules, "policy drop") {
		return fmt.Errorf("vm %s: the network lockdown has no drop policy", name)
	}
	// A direct connection to a public address must fail. 1.1.1.1:443 is
	// only a destination; nothing is sent if the lockdown holds. The probe
	// says BLOCKED or OPEN itself, so a probe that could not run at all (no
	// bash, no timeout) is a refusal too, not a pass.
	out, err := l.limactl(ctx, nil, "shell", "--workdir=/", name, "--", "bash", "-c", probeScript)
	if err != nil {
		return fmt.Errorf("vm %s: the egress probe did not run: %w", name, err)
	}
	if strings.TrimSpace(out) != "BLOCKED" {
		return fmt.Errorf("vm %s: a direct connection out was not blocked (%q); the lockdown does not hold", name, strings.TrimSpace(out))
	}
	return nil
}

// probeScript tries a direct connection out and reports which way it went.
const probeScript = `if timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then echo OPEN; else echo BLOCKED; fi`

func (l *Lima) CopyIn(ctx context.Context, name, hostSrc, guestDst string) error {
	if !ValidName(name) {
		return fmt.Errorf("vm name %q is not one Ovara made", name)
	}
	_, err := l.limactl(ctx, nil, "copy", "-r", hostSrc, name+":"+guestDst)
	return err
}

func (l *Lima) CopyOut(ctx context.Context, name, guestSrc, hostDst string) error {
	if !ValidName(name) {
		return fmt.Errorf("vm name %q is not one Ovara made", name)
	}
	_, err := l.limactl(ctx, nil, "copy", "-r", name+":"+guestSrc, hostDst)
	return err
}

func (l *Lima) Run(ctx context.Context, name string, argv []string, stdio Stdio) (int, error) {
	if !ValidName(name) {
		return 0, fmt.Errorf("vm name %q is not one Ovara made", name)
	}
	if len(argv) == 0 {
		return 0, errors.New("vm run: no command")
	}
	args := append([]string{"shell", "--workdir=/", name, "--"}, argv...)
	_, err := l.limactl(ctx, &stdio, args...)
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 0, err
	}
	return 0, nil
}

func (l *Lima) Delete(ctx context.Context, name string) error {
	if !ValidName(name) {
		return fmt.Errorf("vm name %q is not one Ovara made", name)
	}
	_, err := l.limactl(ctx, nil, "delete", "--force", name)
	return err
}

var _ Driver = (*Lima)(nil)
