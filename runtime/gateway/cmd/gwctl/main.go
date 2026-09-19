// ovara-gwctl — domain gateway admission tool (P2.3.2).
//
// Operator-side command that writes enrollment grants, denials, and
// retirements into the domain gateway registry. The gateway server
// binary never invokes this path — admission authority is separated
// from the applicant: a gateway cannot mint its own grant, it can only
// consume one an operator wrote.
//
// Authority = write access to the domain registry file (flock-
// serialized, same trust boundary as P2.1/P2.2 stores). Grants are
// unsigned records in the domain journal — within a single-filesystem
// trust domain, signing would add nothing (any "authority key" would
// live in the same filesystem).
//
// usage:
//
//	gwctl grant  --registry F --gateway-id G [--pubkey HEX] [--ttl 600s]
//	gwctl deny   --registry F --grant-id ID
//	gwctl retire --registry F --gateway-id G
//	gwctl list   --registry F [--gateway-id G]
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"ovara.runtime.gateway/internal/gwidentity"
)

func openReg(path string, create bool) *gwidentity.Registry {
	if path == "" {
		fatal("--registry is required")
	}
	var r *gwidentity.Registry
	var err error
	if create {
		r, err = gwidentity.Open(path)
	} else {
		r, err = gwidentity.OpenExisting(path)
	}
	if err != nil {
		fatal("open registry: %v", err)
	}
	return r
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "gwctl: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: gwctl <grant|deny|retire|list> --registry F [flags]")
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	reg := fs.String("registry", "", "domain registry file (required)")
	gw := fs.String("gateway-id", "", "gateway id")
	pub := fs.String("pubkey", "", "pinned ed25519 public key (hex, optional)")
	ttl := fs.Duration("ttl", 0, "grant lifetime (0 = no expiry)")
	grantID := fs.String("grant-id", "", "grant id")
	fs.Parse(args)

	// Only `grant` may initialize a missing registry — list/deny/retire
	// operate on existing state and must not mint an empty one.
	r := openReg(*reg, cmd == "grant")
	defer r.Close()

	switch cmd {
	case "grant":
		if *gw == "" {
			fatal("--gateway-id is required")
		}
		var pk []byte
		if *pub != "" {
			var err error
			pk, err = hex.DecodeString(*pub)
			if err != nil || len(pk) != 32 {
				fatal("--pubkey must be 32-byte hex")
			}
		}
		g, err := r.Authorize(*gw, pk, *ttl)
		if err != nil {
			fatal("grant: %v", err)
		}
		fmt.Printf("grant authorized: grant_id=%s gateway_id=%s pinned=%v expires=%s\n",
			g.GrantID, g.GatewayID, g.PublicKey != "",
			g.ExpiresAt.Format(time.RFC3339))

	case "deny":
		if *grantID == "" {
			fatal("--grant-id is required")
		}
		if err := r.Deny(*grantID); err != nil {
			fatal("deny: %v", err)
		}
		fmt.Printf("grant denied: %s\n", *grantID)

	case "retire":
		if *gw == "" {
			fatal("--gateway-id is required")
		}
		if err := r.Destroy(*gw); err != nil {
			fatal("retire: %v", err)
		}
		fmt.Printf("gateway retired (tombstoned): %s\n", *gw)

	case "list":
		ids := []string{*gw}
		if *gw == "" {
			ids = r.AllGateways()
		}
		for _, id := range ids {
			recs, err := r.Lookup(id)
			if err != nil {
				continue
			}
			for _, k := range recs {
				fmt.Printf("key    %s  %s  state=%s gen=%d pub=%s…\n",
					k.GatewayID, k.KeyID, k.State, k.Generation, k.PublicKey[:12])
			}
			gs, _ := r.GrantsFor(id)
			for _, g := range gs {
				fmt.Printf("grant  %s  %s  state=%s pinned=%v expires=%s\n",
					g.GatewayID, g.GrantID, g.State, g.PublicKey != "",
					g.ExpiresAt.Format(time.RFC3339))
			}
		}

	default:
		fatal("unknown command %q", cmd)
	}
}
