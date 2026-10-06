// Package action implements v2's closed action vocabulary and
// canonicalization (spec/action_model.md). Matching never sees raw
// strings — everything evaluates on the canonical form.
package action

import (
	"fmt"
	"regexp"
	"strings"
)

// Type is the closed action vocabulary (v2.0). Unknown strings never
// reach the evaluator — Canonicalize maps them to TypeRawUnknown.
type Type string

const (
	TypeShellExec    Type = "shell.exec"
	TypeGitPush      Type = "git.push"
	TypeGitPull      Type = "git.pull"
	TypeGitFetch     Type = "git.fetch"
	TypeGitCheckout  Type = "git.checkout"
	TypeGitForcePush Type = "git.force_push"
	TypeGithubPush   Type = "github.push"
	TypeGithubPR     Type = "github.pr"
	TypeGithubMerge  Type = "github.merge"
	TypeGithubDelBr  Type = "github.delete_branch"
	TypeCIDeploy     Type = "ci.deploy"
	TypeCIBuildTrig  Type = "ci.build_trigger"
	TypeCIApproval   Type = "ci.approval"
	TypeFSRead       Type = "fs.read"
	TypeFSWrite      Type = "fs.write"
	TypeFSDelete     Type = "fs.delete"
	TypeFSExec       Type = "fs.exec_spawn"
	TypeNetEgress    Type = "net.egress"
	TypeNetDNS       Type = "net.dns"
	TypeMCPCall      Type = "mcp.call"
	TypePkgInstall   Type = "pkg.install"
	TypeProcSpawn    Type = "proc.spawn"
	TypeIPCSend      Type = "ipc.send"
	TypeCredInject   Type = "cred.inject"
	TypeAgentMsg     Type = "agent.message"
	TypeHTTPRequest  Type = "http.request"
	// TypeRawUnknown is the conservative catch-class for parseable
	// input that isn't in the vocabulary, or unparseable input.
	// Policy treats it as escalate-only (spec §5).
	TypeRawUnknown Type = "raw.unknown"
)

var knownTypes = map[Type]bool{}

func init() {
	for _, t := range []Type{TypeShellExec, TypeGitPush, TypeGitPull,
		TypeGitFetch, TypeGitCheckout, TypeGitForcePush, TypeGithubPush,
		TypeGithubPR, TypeGithubMerge, TypeGithubDelBr, TypeCIDeploy,
		TypeCIBuildTrig, TypeCIApproval, TypeFSRead, TypeFSWrite,
		TypeFSDelete, TypeFSExec, TypeNetEgress, TypeNetDNS, TypeMCPCall,
		TypePkgInstall, TypeProcSpawn, TypeIPCSend, TypeCredInject,
		TypeAgentMsg, TypeHTTPRequest} {
		knownTypes[t] = true
	}
}

// Valid reports whether t is in the vocabulary (raw.unknown excluded —
// it is produced by canonicalization, never accepted as input).
func (t Type) Valid() bool { return knownTypes[t] }

// Env is the deployment environment class.
type Env string

const (
	EnvLocal      Env = "local"
	EnvDev        Env = "dev"
	EnvStaging    Env = "staging"
	EnvProduction Env = "production"
)

func ParseEnv(s string) (Env, bool) {
	switch Env(s) {
	case EnvLocal, EnvDev, EnvStaging, EnvProduction:
		return Env(s), true
	}
	return "", false
}

// Action is the canonical request. Actor is never caller-supplied —
// the runtime fills it from the authenticated credential.
type Action struct {
	Type     Type   `json:"type"`
	Resource string `json:"resource"` // canonical resource form
	Env      Env    `json:"env"`
	// ParseFlag marks degraded canonicalization — set when the raw
	// input couldn't be fully normalized. Policy may escalate on it.
	ParseFlag bool `json:"parse_flag,omitempty"`
}

// Canonicalize maps (typeStr, rawResource) to a canonical Action.
// Errors are for structurally invalid input (reject = fail-closed);
// TypeRawUnknown is a *result*, not an error — it stays evaluatable.
func Canonicalize(typeStr, rawResource string) (Action, error) {
	t := Type(strings.TrimSpace(typeStr))
	if !t.Valid() {
		return Action{Type: TypeRawUnknown, Resource: rawResource,
			ParseFlag: true}, nil
	}
	switch resourceKindOf(t) {
	case kindNet:
		res, err := canonNet(rawResource)
		if err != nil {
			return Action{}, err
		}
		return Action{Type: t, Resource: res}, nil
	case kindFS:
		res, err := canonPath(rawResource)
		if err != nil {
			return Action{}, err
		}
		return Action{Type: t, Resource: res}, nil
	case kindShell:
		cmds, flagged, err := canonShell(rawResource)
		if err != nil {
			return Action{}, err
		}
		return Action{Type: t, Resource: cmds, ParseFlag: flagged}, nil
	default:
		// kindOpaque — identifiers like branch names, repo paths
		res := strings.TrimSpace(rawResource)
		if res == "" {
			return Action{}, fmt.Errorf("action: empty resource")
		}
		return Action{Type: t, Resource: res}, nil
	}
}

type resKind int

const (
	kindOpaque resKind = iota
	kindNet
	kindFS
	kindShell
)

func resourceKindOf(t Type) resKind {
	switch t {
	case TypeNetEgress, TypeNetDNS, TypeHTTPRequest:
		return kindNet
	case TypeFSRead, TypeFSWrite, TypeFSDelete, TypeFSExec:
		return kindFS
	case TypeShellExec, TypeProcSpawn, TypePkgInstall:
		return kindShell
	}
	return kindOpaque
}

var envRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*=`)

// IsOpaque reports whether the action type carries a free-form
// resource (identifiers, not canonicalizable addresses).
func IsOpaque(t Type) bool { return resourceKindOf(t) == kindOpaque }
