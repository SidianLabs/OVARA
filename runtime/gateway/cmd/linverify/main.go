// linverify is the receiver-side verifier for OVARA action lineage:
// given a bundle, the receiving domain's pinned anchor, and (for the
// strongest check) the request it actually received, it runs the
// fail-closed offline verdict — no contact with the issuing domain.
//
//	linverify -bundle bundle.json -anchor anchor.json [-request request.json]
//
// stdout is the verdict JSON (accept / layer / detail / layers passed);
// exit 0 on accept, 1 on reject, 2 on usage or input errors.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"ovara.runtime.gateway/internal/lineage"
	"ovara.runtime.gateway/internal/models"
)

func main() {
	bundlePath := flag.String("bundle", "", "JSON lineage bundle (required)")
	anchorPath := flag.String("anchor", "", "JSON pinned anchor (required)")
	requestPath := flag.String("request", "", "JSON delivered request — enables VerifyDelivered (optional)")
	flag.Parse()
	if *bundlePath == "" || *anchorPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	read := func(path string, v any) {
		b, err := os.ReadFile(path)
		if err != nil {
			fatal("read %s: %v", path, err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			fatal("parse %s: %v", path, err)
		}
	}

	var b lineage.Bundle
	read(*bundlePath, &b)

	var af lineage.AnchorFile
	read(*anchorPath, &af)
	a, err := af.Anchor()
	if err != nil {
		fatal("anchor: %v", err)
	}

	var v *lineage.Verdict
	if *requestPath != "" {
		var req models.ActionRequest
		read(*requestPath, &req)
		v = lineage.VerifyDelivered(&b, a, &req)
	} else {
		v = lineage.Verify(&b, a)
	}

	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
	if !v.Accept {
		os.Exit(1)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "linverify: "+format+"\n", args...)
	os.Exit(2)
}
