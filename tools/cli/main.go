package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	gatewayURL = flag.String("gateway", "http://localhost:8080", "Gateway URL")
	apiKey     = flag.String("key", "", "API key")
	osExit     = os.Exit
)

func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		usage()
		osExit(1)
		return
	}

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	case "status":
		doStatus()
	case "health":
		doHealth()
	case "check":
		doCheck(cmdArgs)
	case "receipts":
		doReceipts()
	case "policy":
		doPolicy()
	case "gateways":
		doGateways()
	case "enroll":
		doEnroll()
	case "metrics":
		doMetrics()
	case "approvals":
		doApprovals(cmdArgs)
	case "trust":
		doTrust(cmdArgs)
	case "verify":
		doVerify(cmdArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		osExit(1)
		return
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `ovara — Ovara Runtime Gateway CLI

Usage:
  ovara [flags] <command> [args]

Commands:
  status        Gateway status and enrollment info
  health        Health check
  check <action> <resource>  Check if action is allowed
  receipts      List recent receipts
  policy        Show current policy
  gateways      List gateways (control plane)
  enroll <url> <org-id>  Enroll gateway with control plane
  metrics       Show runtime metrics
  approvals     List/manage approvals
  trust <sub> [args]  Trust score, drift, or graph
  verify        Verify execution receipts

Flags:
`)
	flag.PrintDefaults()
}

func doStatus() {
	resp := get("/v1/runtime/status")
	if resp != nil {
		printJSON(resp)
	}
}

func doHealth() {
	resp := get("/v1/runtime/health")
	if resp != nil {
		printJSON(resp)
	}
}

func doCheck(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ovara check <action> <resource>")
		return
	}
	actionType, resource := args[0], args[1]
	body := map[string]string{
		"action_type": actionType,
		"resource":    resource,
		"environment": "local",
	}
	resp := post("/v1/runtime/check", body)
	if resp != nil {
		printJSON(resp)
	}
}

func doReceipts() {
	resp := get("/v1/runtime/receipts")
	if resp != nil {
		printJSON(resp)
	}
}

func doPolicy() {
	resp := get("/v1/runtime/policy")
	if resp != nil {
		printJSON(resp)
	}
}

func doGateways() {
	resp := get("/v1/gateways")
	if resp != nil {
		printJSON(resp)
	}
}

func doEnroll() {
	args := flag.Args()
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ovara enroll <organization-id>")
		return
	}
	orgID := args[1]
	body := map[string]string{"organizationId": orgID}
	resp := post("/v1/gateways/enroll", body)
	if resp != nil {
		printJSON(resp)
	}
}

func doMetrics() {
	resp := get("/v1/runtime/metrics")
	if resp != nil {
		printJSON(resp)
	}
}

func doApprovals(args []string) {
	if len(args) == 0 {
		resp := get("/v1/approvals")
		if resp != nil {
			printJSON(resp)
		}
		return
	}

	if args[0] == "approve" {
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: ovara approvals approve <id>")
			return
		}
		id := args[1]
		body := map[string]string{"action": "approve"}
		resp := post("/v1/approvals/"+id, body)
		if resp != nil {
			printJSON(resp)
		}
		return
	}

	if args[0] == "deny" {
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: ovara approvals deny <id> --reason=<reason>")
			return
		}
		id := args[1]
		reason := ""
		for _, a := range args[2:] {
			if strings.HasPrefix(a, "--reason=") {
				reason = strings.TrimPrefix(a, "--reason=")
			}
		}
		body := map[string]string{"action": "deny", "reason": reason}
		resp := post("/v1/approvals/"+id, body)
		if resp != nil {
			printJSON(resp)
		}
		return
	}

	state := ""
	if strings.HasPrefix(args[0], "--state=") {
		state = strings.TrimPrefix(args[0], "--state=")
	}
	path := "/v1/approvals"
	if state != "" {
		path += "?state=" + state
	}
	resp := get(path)
	if resp != nil {
		printJSON(resp)
	}
}

func doTrust(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: ovara trust score|drift|graph [args]")
		return
	}

	sub := args[0]
	switch sub {
	case "score":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: ovara trust score <agent-id>")
			return
		}
		resp := get("/v1/trust/score/" + args[1])
		if resp != nil {
			printJSON(resp)
		}
	case "drift":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: ovara trust drift <agent-id>")
			return
		}
		resp := get("/v1/trust/drift/" + args[1])
		if resp != nil {
			printJSON(resp)
		}
	case "graph":
		resp := get("/v1/trust/graph")
		if resp != nil {
			printJSON(resp)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown trust subcommand: %s\n", sub)
	}
}

func doVerify(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ovara verify <receipt-id> | ovara verify --all")
		return
	}

	if args[0] == "--all" {
		resp := get("/v1/receipts/verify")
		if resp != nil {
			printJSON(resp)
		}
		return
	}

	receiptID := args[0]
	resp := get("/v1/receipts/" + receiptID + "/verify")
	if resp != nil {
		printJSON(resp)
	}
}

func get(path string) map[string]interface{} {
	req, _ := http.NewRequest(http.MethodGet, strings.TrimRight(*gatewayURL, "/")+path, nil)
	setHeaders(req)
	return do(req)
}

func post(path string, body interface{}) map[string]interface{} {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, strings.TrimRight(*gatewayURL, "/")+path, bytes.NewReader(data))
	setHeaders(req)
	return do(req)
}

func setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	if *apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+*apiKey)
	}
}

func do(req *http.Request) map[string]interface{} {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "error: %s (status %d)\n", string(body), resp.StatusCode)
		osExit(1)
		return nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println(string(body))
		os.Exit(0)
	}
	return result
}

func printJSON(v interface{}) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}
