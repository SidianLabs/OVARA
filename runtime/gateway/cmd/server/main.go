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
	"ovara.runtime.gateway/internal/receipts"
	"ovara.runtime.gateway/internal/trust"

	"github.com/fsnotify/fsnotify"
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
	var watcher *policy.Watcher

	if cfg.PolicyFile != "" {
		policySource := policy.NewLocalFileSource(cfg.PolicyFile, cfg.PolicyVersion)
		store, err := policySource.Load()
		if err != nil {
			log.Printf("warning: failed to load policy from file: %v", err)
		} else {
			policyStore = store
			policyStore.SetFilePath(cfg.PolicyFile)

			if cfg.PolicyRefreshInterval > 0 {
				w, err := policy.NewWatcher(policySource)
				if err != nil {
					log.Printf("warning: failed to create policy watcher: %v", err)
				} else {
					watcher = w
					if err := watcher.Watch(cfg.PolicyFile); err != nil {
						log.Printf("warning: failed to watch policy file: %v", err)
					} else {
						go func() {
							for event := range watcher.Events() {
								if event.Has(fsnotify.Write) {
									if _, err := watcher.Reload(); err != nil {
										log.Printf("policy reload failed: %v", err)
									} else {
										log.Printf("policy reloaded")
									}
								}
							}
						}()
					}
				}
			}
		}
	}

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

	receiptsStore := receipts.NewInMemoryStore()

	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	h := handlers.New(eval, decisionLogger, cfg, receiptsStore)

	trustHandler := trust.NewHandler(shieldStore, trust.NewEvaluator(shieldStore))

	approvalStore := approval.NewInMemoryStore()
	approvalService := approval.NewService(approvalStore)
	approvalHandler := handlers.NewApprovalHandler(approvalService)
	receiptHandler := handlers.NewReceiptHandler(receiptsStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	approvalHandler.RegisterRoutes(mux)
	receiptHandler.RegisterRoutes(mux)
	trustHandler.RegisterRoutes(mux)

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