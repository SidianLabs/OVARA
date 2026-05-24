package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/config"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/handlers"
	"ovara.runtime.gateway/internal/logging"
	"ovara.runtime.gateway/internal/policy"
)

func main() {
	configPath := os.Getenv("OVARA_CONFIG")
	if configPath == "" {
		configPath = "etc/config.json"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	policyStore := policy.NewStore(cfg.PolicyVersion)

	var decisionLogger *logging.DecisionLogger
	if cfg.DecisionLogFile != "" {
		decisionLogger, err = logging.NewDecisionLogger(cfg.DecisionLogFile)
		if err != nil {
			log.Printf("warning: failed to create decision logger: %v", err)
		}
	}
	if decisionLogger != nil {
		defer decisionLogger.Close()
	}

	eval := evaluator.New(policyStore)
	h := handlers.New(eval, decisionLogger, cfg)

	approvalStore := approval.NewInMemoryStore()
	approvalService := approval.NewService(approvalStore)
	approvalHandler := handlers.NewApprovalHandler(approvalService)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	approvalHandler.RegisterRoutes(mux)

	addr := ":" + cfg.ServerPort
	log.Printf("ovara runtime gateway listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	signal.Ignore(syscall.SIGPIPE)
}