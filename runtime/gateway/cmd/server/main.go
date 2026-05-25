package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/config"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/enrollment"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/handlers"
	"ovara.runtime.gateway/internal/logging"
	"ovara.runtime.gateway/internal/metrics"
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

	env := os.Getenv("OVARA_ENVIRONMENT")
	if env == "" {
		env = "local"
	}

	enrollmentFile := cfg.EnrollmentFile
	if enrollmentFile == "" {
		enrollmentFile = "var/data/enrollment.json"
	}
	enrollmentSvc := enrollment.NewLocalService(enrollmentFile,
		enrollment.WithGatewayName(cfg.GatewayName),
		enrollment.WithGatewayVersion(cfg.GatewayVersion),
	)
	if err := enrollmentSvc.Initialize(env); err != nil {
		log.Printf("warning: failed to initialize enrollment: %v", err)
	}

	var stopHeartbeat func()
	if cfg.HeartbeatIntervalSec > 0 {
		interval := time.Duration(cfg.HeartbeatIntervalSec) * time.Second
		stopHeartbeat = enrollmentSvc.StartHeartbeat(interval)
		log.Printf("enrollment heartbeat started (interval=%ds)", cfg.HeartbeatIntervalSec)
	} else {
		interval := 30 * time.Second
		stopHeartbeat = enrollmentSvc.StartHeartbeat(interval)
		log.Printf("enrollment heartbeat started (default interval=%ds)", int(interval.Seconds()))
	}
	metrics.RecordHeartbeat()

	log.Printf("gateway_id=%s enrollment_state=%s environment=%s",
		enrollmentSvc.GetIdentity().ID,
		enrollmentSvc.GetIdentity().EnrollmentState,
		enrollmentSvc.GetIdentity().Environment)

	policyStore := policy.NewStore(cfg.PolicyVersion)
	var watcher *policy.Watcher
	var wg sync.WaitGroup

	var eventStore events.Store
	if cfg.EventsFile != "" {
		store, err := events.NewFileBackedStore(cfg.EventsFile, cfg.EventsMaxSize)
		if err != nil {
			log.Printf("warning: failed to create file-backed event store: %v, using in-memory", err)
			eventStore = events.NewInMemoryStore(10000)
		} else {
			eventStore = store
			log.Printf("event store persisted to %s (max=%d)", cfg.EventsFile, cfg.EventsMaxSize)
		}
	} else {
		eventStore = events.NewInMemoryStore(10000)
		log.Printf("event store in-memory (no persistence configured)")
	}

	if cfg.PolicyFile != "" {
		initialSource := policy.NewLocalFileSource(cfg.PolicyFile, cfg.PolicyVersion, policyStore)
		store, err := initialSource.Load()
		if err != nil {
			log.Printf("warning: failed to load policy from file: %v", err)
		} else {
			policyStore = store

			if cfg.PolicyRefreshInterval > 0 {
				policySource := policy.NewLocalFileSource(cfg.PolicyFile, cfg.PolicyVersion, policyStore)
				w, err := policy.NewWatcher(policySource)
				if err != nil {
					log.Printf("warning: failed to create policy watcher: %v", err)
				} else {
					watcher = w
					if err := watcher.Watch(cfg.PolicyFile); err != nil {
						log.Printf("warning: failed to watch policy file: %v", err)
					} else {
						wg.Add(1)
						go func() {
							defer wg.Done()
							for event := range watcher.Events() {
								if event.Has(fsnotify.Write) {
									if err := watcher.Reload(); err != nil {
										log.Printf("policy reload failed: %v", err)
										metrics.RecordPolicyReload(false, err.Error())
										if eventStore != nil {
											evt := events.NewEvent(events.EventTypePolicyReloadFailed).
												WithGatewayID(enrollmentSvc.GetIdentity().ID).
												WithPayload(map[string]any{
													"error":  err.Error(),
													"source": cfg.PolicyFile,
												})
											eventStore.Append(evt)
										}
									} else {
										log.Printf("policy reloaded from %s", cfg.PolicyFile)
										metrics.RecordPolicyReload(true, "")
										if eventStore != nil {
											evt := events.NewEvent(events.EventTypePolicyReloaded).
												WithGatewayID(enrollmentSvc.GetIdentity().ID).
												WithPayload(map[string]any{
													"success": true,
													"source":  cfg.PolicyFile,
												})
											eventStore.Append(evt)
										}
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

	var receiptsStore receipts.Store
	if cfg.ReceiptsFile != "" {
		var maxAge time.Duration
		if cfg.ReceiptsMaxAgeMinutes > 0 {
			maxAge = time.Duration(cfg.ReceiptsMaxAgeMinutes) * time.Minute
		}
		store, err := receipts.NewFileBackedStore(cfg.ReceiptsFile, cfg.ReceiptsMaxSize, maxAge)
		if err != nil {
			log.Printf("warning: failed to create file-backed receipt store: %v, falling back to in-memory", err)
			receiptsStore = receipts.NewInMemoryStore()
		} else {
			receiptsStore = store
			log.Printf("receipts persisted to %s (max=%d, max_age=%dm)", cfg.ReceiptsFile, cfg.ReceiptsMaxSize, cfg.ReceiptsMaxAgeMinutes)
		}
	} else {
		receiptsStore = receipts.NewInMemoryStore()
		log.Printf("receipts in-memory (no persistence configured)")
	}

	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)

	var approvalStore approval.Store
	if cfg.ApprovalsFile != "" {
		store, err := approval.NewFileBackedStore(cfg.ApprovalsFile)
		if err != nil {
			log.Printf("warning: failed to create file-backed approval store: %v, falling back to in-memory", err)
			approvalStore = approval.NewInMemoryStore()
		} else {
			approvalStore = store
			log.Printf("approvals persisted to %s", cfg.ApprovalsFile)
		}
	} else {
		approvalStore = approval.NewInMemoryStore()
		log.Printf("approvals in-memory (no persistence configured)")
	}

	var continuationStore continuation.Store
	if cfg.ContinuationsFile != "" {
		store, err := continuation.NewFileBackedStore(cfg.ContinuationsFile, cfg.ContinuationsMaxSize)
		if err != nil {
			log.Printf("warning: failed to create file-backed continuation store: %v, using in-memory", err)
			continuationStore = continuation.NewInMemoryStore()
		} else {
			continuationStore = store
			log.Printf("continuation store persisted to %s (max=%d)", cfg.ContinuationsFile, cfg.ContinuationsMaxSize)
		}
	} else {
		continuationStore = continuation.NewInMemoryStore()
		log.Printf("continuation store in-memory (no persistence configured)")
	}

	h := handlers.New(eval, decisionLogger, cfg, receiptsStore)
	h.SetEnrollment(enrollmentSvc)

	trustHandler := trust.NewHandler(shieldStore, trust.NewEvaluator(shieldStore))
	approvalService := approval.NewService(approvalStore)
	approvalHandler := handlers.NewApprovalHandler(approvalService)
	receiptHandler := handlers.NewReceiptHandler(receiptsStore)

	h.SetApprovalService(approvalService)
	h.SetShieldStats(shieldStore.Stats)
	h.SetEventStore(eventStore)
	h.SetContinuationStore(continuationStore)
	approvalHandler.SetEventStore(eventStore)
	approvalHandler.SetGatewayID(enrollmentSvc.GetIdentity().ID)
	approvalHandler.SetContinuationStore(continuationStore)

	trustHandler.SetEventStore(eventStore)
	trustHandler.SetGatewayID(enrollmentSvc.GetIdentity().ID)

	eventHandler := handlers.NewEventHandler(eventStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	approvalHandler.RegisterRoutes(mux)
	receiptHandler.RegisterRoutes(mux)
	trustHandler.RegisterRoutes(mux)
	eventHandler.RegisterRoutes(mux)

	continuationHandler := handlers.NewContinuationHandler(continuationStore)
	continuationHandler.RegisterRoutes(mux)

	var execStore execution.Store
	execStore = execution.NewInMemoryStore()
	if cfg.ExecutionFile != "" {
		store, err := execution.NewFileBackedStoreWithRetention(
			cfg.ExecutionFile,
			cfg.ExecutionsMaxSize,
			cfg.ExecutionRetentionDays,
			cfg.ExecutionMaxRecords,
		)
		if err != nil {
			log.Printf("warning: failed to create file-backed execution store: %v, using in-memory", err)
			execStore = execution.NewInMemoryStore()
		} else {
			execStore = store
			log.Printf("execution store persisted to %s (max=%d, retention_days=%d, max_records=%d)",
				cfg.ExecutionFile, cfg.ExecutionsMaxSize, cfg.ExecutionRetentionDays, cfg.ExecutionMaxRecords)
		}
	} else {
		log.Printf("execution store in-memory (no persistence configured)")
	}
	shellExec := execution.NewShellExecutorWithLimits(
		60,
		cfg.ExecutionStdoutLimitBytes,
		cfg.ExecutionStderrLimitBytes,
	)
	if cfg.ExecutionWorkingDir != "" {
		shellExec.WorkingDir = cfg.ExecutionWorkingDir
	}
	if len(cfg.ExecutionAllowedEnvVars) > 0 {
		shellExec.AllowedEnvVars = cfg.ExecutionAllowedEnvVars
	}
	log.Printf("shell executor configured (stdout_limit=%d, stderr_limit=%d, workdir=%q, allowed_env=%v)",
		cfg.ExecutionStdoutLimitBytes, cfg.ExecutionStderrLimitBytes, cfg.ExecutionWorkingDir, cfg.ExecutionAllowedEnvVars)
	execHandler := handlers.NewExecutionHandler(execStore)
	execHandler.SetExecutor(shellExec)
	execHandler.RegisterRoutes(mux)

	continuationHandler.SetExecutionStore(execStore)
	continuationHandler.SetExecutor(shellExec)
	continuationHandler.SetEventStore(eventStore)
	continuationHandler.SetGatewayID(enrollmentSvc.GetIdentity().ID)

	execSweeper := execution.NewSweeper(execStore)
	execSweeper.Start(cfg.ExecutionSweepIntervalSec)
	log.Printf("execution sweeper started (interval=%ds)", cfg.ExecutionSweepIntervalSec)

	sweeper := continuation.NewSweeper(continuationStore)
	sweeper.SetEventStore(eventStore)
	sweeper.SetGatewayID(enrollmentSvc.GetIdentity().ID)

	expiredOnStartup := sweeper.ReconcileOnStartup()
	if expiredOnStartup > 0 {
		log.Printf("continuation reconciliation: %d expired on startup", expiredOnStartup)
	}

	sweepInterval := cfg.ContinuationSweepIntervalSec
	if sweepInterval > 0 {
		sweeper.Start(sweepInterval)
		log.Printf("continuation sweeper started (interval=%ds)", sweepInterval)
	}

	addr := ":" + cfg.ServerPort
	log.Printf("ovara runtime gateway v%s listening on %s", cfg.GatewayVersion, addr)
	log.Printf("gateway_id=%s enrollment_state=%s environment=%s",
		enrollmentSvc.GetIdentity().ID,
		enrollmentSvc.GetIdentity().EnrollmentState,
		enrollmentSvc.GetIdentity().Environment)

	if cacheTTL := time.Duration(cfg.DecisionCacheTTLMin) * time.Minute; cacheTTL > 0 {
		h.StartCacheCleanup(cacheTTL)
		log.Printf("decision cache cleanup enabled (ttl=%v)", cacheTTL)
	} else {
		h.StartCacheCleanup(5 * time.Minute)
		log.Printf("decision cache cleanup using default 5m interval")
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("shutting down...")
		if watcher != nil {
			watcher.Close()
		}
		if stopHeartbeat != nil {
			stopHeartbeat()
			log.Println("enrollment heartbeat stopped")
		}
		if fb, ok := eventStore.(*events.FileBackedStore); ok {
			fb.Close()
		}
		if fbCnt, ok := continuationStore.(*continuation.FileBackedStore); ok {
			fbCnt.Close()
		}
		if fbExe, ok := execStore.(*execution.FileBackedStore); ok {
			fbExe.Close()
		}
		if sweeper != nil {
			sweeper.Stop()
		}
		if execSweeper != nil {
			execSweeper.Stop()
		}
		wg.Wait()
		os.Exit(0)
	}()

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	signal.Ignore(syscall.SIGPIPE)
}