// Package server exposes the OVARA runtime gateway as an embeddable
// in-process server so that other binaries (e.g. a unified ovara CLI)
// can run it without shelling out to a separate executable.
package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/auth"
	"ovara.runtime.gateway/internal/capabilities"
	"ovara.runtime.gateway/internal/config"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/enrollment"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/handlers"
	"ovara.runtime.gateway/internal/identity"
	"ovara.runtime.gateway/internal/integrity"
	"ovara.runtime.gateway/internal/logging"
	"ovara.runtime.gateway/internal/metrics"
	"ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/receipt"
	"ovara.runtime.gateway/internal/receipts"
	"ovara.runtime.gateway/internal/sandbox"
	"ovara.runtime.gateway/internal/trust"

	"github.com/fsnotify/fsnotify"
)

// Run starts the gateway with the given config file and blocks until
// shutdown. It is safe to call in a goroutine.
func Run(configPath string) error {
	if configPath == "" {
		configPath = os.Getenv("OVARA_CONFIG")
	}
	if configPath == "" {
		configPath = "etc/config.json"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
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
		store, err := events.NewFileBackedStoreWithRetention(cfg.EventsFile, cfg.EventsMaxSize, cfg.EventsRetentionDays, cfg.EventsMaxRecords)
		if err != nil {
			log.Printf("warning: failed to create file-backed event store: %v, using in-memory", err)
			eventStore = events.NewInMemoryStore(10000)
		} else {
			eventStore = store
			log.Printf("event store persisted to %s (max=%d, retention_days=%d, max_records=%d)", cfg.EventsFile, cfg.EventsMaxSize, cfg.EventsRetentionDays, cfg.EventsMaxRecords)
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

	var leaseValidator *identity.Validator
	if len(cfg.TrustedIssuers) > 0 {
		trustedKeys := make(map[string][]byte, len(cfg.TrustedIssuers))
		for issuer, hexKey := range cfg.TrustedIssuers {
			key, err := hex.DecodeString(hexKey)
			if err != nil {
				return fmt.Errorf("trusted_issuers: invalid hex public key for issuer %q: %v", issuer, err)
			}
			trustedKeys[issuer] = key
		}
		leaseValidator = identity.NewValidatorWithTrustedKeys(trustedKeys)
		eval.SetValidator(leaseValidator)
		log.Printf("trusted issuers configured (%d issuer key(s) for lease signature verification)", len(trustedKeys))
	} else {
		log.Printf("WARNING: trusted_issuers not configured; signed capability leases cannot be verified and will FAIL validation. Set trusted_issuers in config.json.")
	}

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
		store, err := continuation.NewFileBackedStoreWithRetention(cfg.ContinuationsFile, cfg.ContinuationsMaxSize, cfg.ContinuationRetentionDays, cfg.ContinuationMaxRecords)
		if err != nil {
			log.Printf("warning: failed to create file-backed continuation store: %v, using in-memory", err)
			continuationStore = continuation.NewInMemoryStore()
		} else {
			continuationStore = store
			log.Printf("continuation store persisted to %s (max=%d, retention_days=%d, max_records=%d)", cfg.ContinuationsFile, cfg.ContinuationsMaxSize, cfg.ContinuationRetentionDays, cfg.ContinuationMaxRecords)
		}
	} else {
		continuationStore = continuation.NewInMemoryStore()
		log.Printf("continuation store in-memory (no persistence configured)")
	}

	h := handlers.New(eval, decisionLogger, cfg, receiptsStore)
	h.SetEnrollment(enrollmentSvc)

	policyHandler := handlers.NewPolicyHandler(eval, policyStore)
	policyHandler.SetEventStore(eventStore)
	policyHandler.SetGatewayID(enrollmentSvc.GetIdentity().ID)
	// Restrict caller-supplied policy file paths (file_path, candidate_file,
	// ?file=) to a single directory to prevent local file reads.
	policyDir := cfg.PolicyDir
	if policyDir == "" && cfg.PolicyFile != "" {
		if abs, err := filepath.Abs(cfg.PolicyFile); err == nil {
			policyDir = filepath.Dir(abs)
		}
	}
	policyHandler.SetPolicyDir(policyDir)
	if policyDir != "" {
		log.Printf("policy file inputs restricted to %s", policyDir)
	}

	var capabilitiesStore capabilities.Store
	if cfg.CapabilitiesFile != "" {
		store, err := capabilities.NewFileBackedStore(cfg.CapabilitiesFile, cfg.CapabilitiesMaxSize, 0)
		if err != nil {
			log.Printf("warning: failed to create file-backed capabilities store: %v, falling back to in-memory", err)
			capabilitiesStore = capabilities.NewInMemoryStore()
		} else {
			capabilitiesStore = store
			log.Printf("capabilities persisted to %s (max=%d)", cfg.CapabilitiesFile, cfg.CapabilitiesMaxSize)
		}
	} else {
		capabilitiesStore = capabilities.NewInMemoryStore()
		log.Printf("capabilities in-memory (no persistence configured)")
	}

	var capabilitiesHistoryStore *capabilities.FileBackedHistoryStore
	if cfg.CapabilitiesHistoryFile != "" {
		store, err := capabilities.NewFileBackedHistoryStore(cfg.CapabilitiesHistoryFile, 50000)
		if err != nil {
			log.Printf("warning: failed to create file-backed history store: %v, using in-memory", err)
		} else {
			capabilitiesHistoryStore = store
			log.Printf("capability history persisted to %s", cfg.CapabilitiesHistoryFile)
		}
	}

	capabilitiesHandler := handlers.NewCapabilitiesHandler(capabilitiesStore)
	capabilitiesHandler.SetEventStore(eventStore)
	capabilitiesHandler.SetGatewayID(enrollmentSvc.GetIdentity().ID)
	if leaseValidator != nil {
		capabilitiesHandler.SetLeaseValidator(leaseValidator)
	} else if cfg.AllowUnsignedLeases {
		capabilitiesHandler.SetAllowUnsignedLeases(true)
		log.Printf("WARNING: no trusted_issuers configured and allow_unsigned_leases=true; /v1/capabilities/track accepts leases WITHOUT signature verification")
	} else {
		log.Printf("WARNING: no trusted_issuers configured; /v1/capabilities/track rejects leases it cannot verify. Set allow_unsigned_leases=true to opt in to unsigned leases (dev only).")
	}
	if capabilitiesHistoryStore != nil {
		capabilitiesHandler.SetHistoryStore(capabilitiesHistoryStore)
	}
	eval.SetRevocationChecker(capabilitiesHandler)

	trustHandler := trust.NewHandler(shieldStore, trust.NewEvaluator(shieldStore))
	approvalService := approval.NewService(approvalStore)
	approvalHandler := handlers.NewApprovalHandler(approvalService)
	receiptHandler := handlers.NewReceiptHandler(receiptsStore)

	h.SetApprovalService(approvalService)
	h.SetShieldStats(shieldStore.Stats)
	h.SetEventStore(eventStore)
	h.SetContinuationStore(continuationStore)

	signingKey := cfg.ReceiptSigningKey
	if signingKey == "" {
		// Generate a secure random per-process signing key when none is configured.
		// Receipts signed with this key cannot be verified after a restart, so
		// production deployments must set receipt_signing_key in config.json.
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("failed to generate receipt signing key: %v", err)
		}
		signingKey = hex.EncodeToString(key)
		log.Printf("WARNING: receipt_signing_key not configured; using a random per-process key. Set receipt_signing_key for cross-restart receipt verification.")
	}
	h.SetReceiptSigner(receipt.NewSigner([]byte(signingKey)))
	log.Printf("receipt signer configured (sig_v1, hmac-sha256)")

	approvalHandler.SetEventStore(eventStore)
	approvalHandler.SetGatewayID(enrollmentSvc.GetIdentity().ID)
	approvalHandler.SetContinuationStore(continuationStore)

	trustHandler.SetEventStore(eventStore)
	trustHandler.SetGatewayID(enrollmentSvc.GetIdentity().ID)

	eventHandler := handlers.NewEventHandler(eventStore)

	continuationHandler := handlers.NewContinuationHandler(continuationStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	policyHandler.RegisterRoutes(mux)
	capabilitiesHandler.RegisterRoutes(mux)
	approvalHandler.RegisterRoutes(mux)
	receiptHandler.RegisterRoutes(mux)
	trustHandler.RegisterRoutes(mux)
	eventHandler.RegisterRoutes(mux)

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
	h.SetExecutionStore(execStore)
	h.SetCapabilitiesStore(capabilitiesStore)

	checker := integrity.NewChecker()
	checker.SetEventStore(eventStore)
	checker.SetContinuationStore(continuationStore)
	checker.SetExecutionStore(execStore)
	checker.SetReceiptStore(receiptsStore)
	checker.SetApprovalStore(approvalStore)
	checker.SetGatewayInfo(enrollmentSvc.GetIdentity().ID, cfg.GatewayVersion)
	h.SetIntegrityChecker(checker)
	log.Printf("integrity checker configured")

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
	execHandler.SetContinuationStore(continuationStore)

	execRegistry := execution.NewExecutorRegistry()
	execRegistry.Register("shell", shellExec)

	directExec := execution.NewDirectExecutor(60)
	execRegistry.Register("exec", directExec)
	log.Printf("direct executor configured (exec: action type)")

	gitExec := execution.NewGitExecutor(60)
	execRegistry.Register("git.push", gitExec)
	execRegistry.Register("git.pull", gitExec)
	execRegistry.Register("git.fetch", gitExec)
	execRegistry.Register("git.checkout", gitExec)
	log.Printf("git executor configured (git.push, git.pull, git.fetch, git.checkout)")

	sandboxEnabled := os.Getenv("OVARA_SANDBOX_ENABLED")
	if sandboxEnabled == "true" {
		dockerSandbox := sandbox.NewDockerSandbox("")
		sandboxExec := execution.NewSandboxExecutor(dockerSandbox, 60)
		execRegistry.Register("shell.sandboxed", sandboxExec)
		log.Printf("sandbox executor configured (shell.sandboxed, docker-based, network disabled)")
	} else {
		log.Printf("sandbox executor NOT configured: set OVARA_SANDBOX_ENABLED=true to enable")
	}

	if cfg.GitHubToken != "" {
		githubExec := execution.NewGitHubExecutor(cfg.GitHubToken, 60)
		execRegistry.Register("github.push", githubExec)
		execRegistry.Register("github.pr", githubExec)
		execRegistry.Register("github.merge", githubExec)
		execRegistry.Register("github.delete_branch", githubExec)
		log.Printf("github executor configured (github.push, github.pr, github.merge, github.delete_branch)")
	} else {
		log.Printf("github executor NOT configured: github_token not set in config")
	}

	if cfg.CIToken != "" || cfg.CIWebhookURL != "" {
		ciExec := execution.NewCIExecutor(60)
		if cfg.CIToken != "" {
			ciExec.RegisterProvider(execution.NewGitHubActionsProvider(cfg.CIToken, 60))
		}
		if cfg.CIWebhookURL != "" {
			ciExec.RegisterProvider(execution.NewWebhookProvider(cfg.CIWebhookURL, cfg.CIToken, 60))
		}
		execRegistry.Register("ci.trigger", ciExec)
		log.Printf("ci executor configured (ci.trigger)")
	} else {
		log.Printf("ci executor NOT configured: ci_token and ci_webhook_url not set in config")
	}

	continuationHandler.SetExecutionStore(execStore)
	continuationHandler.SetExecutorRegistry(execRegistry)
	continuationHandler.SetExecutor(shellExec)
	continuationHandler.SetEventStore(eventStore)
	continuationHandler.SetGatewayID(enrollmentSvc.GetIdentity().ID)

	orchestrator := continuation.NewOrchestrator(continuationStore, execStore, execRegistry)
	orchestrator.SetEventStore(eventStore)
	orchestrator.SetGatewayID(enrollmentSvc.GetIdentity().ID)
	orchestrator.SetStuckExecutingSweep(cfg.StuckExecutingSweepIntervalSec, cfg.StuckExecutingRecoveryThresholdMin)
	orchestrator.Start()
	continuationHandler.SetOrchestrator(orchestrator)
	continuationHandler.SetBulkConfig(cfg.BulkMaxBatchCap, cfg.BulkDefaultBatch)
	h.SetOrchestrator(orchestrator)
	stuckSweepDesc := "disabled"
	if cfg.StuckExecutingSweepIntervalSec > 0 {
		stuckSweepDesc = fmt.Sprintf("interval=%ds threshold=%dmin", cfg.StuckExecutingSweepIntervalSec, cfg.StuckExecutingRecoveryThresholdMin)
	}
	log.Printf("execution orchestrator started (poll_interval=2s, stuck_sweep=%s, action_types=[shell, exec, git.push, git.pull, git.fetch, git.checkout, github.push, github.pr, github.merge, github.delete_branch, ci.trigger])", stuckSweepDesc)

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

	adminHandler := handlers.NewAdminHandler()
	adminHandler.SetContinuationStore(continuationStore)
	adminHandler.SetEventStore(eventStore)
	adminHandler.SetExecutionStore(execStore)
	adminHandler.SetContinuationSweeper(sweeper)

	continuationHandler.RegisterRoutes(mux)
	execHandler.RegisterRoutes(mux)
	adminHandler.RegisterRoutes(mux)

	authMw := auth.NewMiddleware(cfg.OperatorTokens, cfg.AuthEnabled)
	switch {
	case cfg.AuthEnabled && len(cfg.OperatorTokens) > 0:
		log.Printf("AUTH: auth_enabled=true with %d operator token(s) configured", len(cfg.OperatorTokens))
	case cfg.AuthEnabled && len(cfg.OperatorTokens) == 0:
		log.Printf("AUTH WARNING: auth_enabled=true but operator_tokens is empty — gateway will DENY ALL requests until operator_tokens is configured (fail-closed).")
	default:
		log.Printf("AUTH: auth_enabled=false — gateway open (set auth_enabled=true and configure operator_tokens to lock down)")
	}
	wrappedMux := authMw.Authenticate(mux)

	addr := ":" + cfg.ServerPort
	if cfg.ListenAddr != "" {
		addr = cfg.ListenAddr + ":" + cfg.ServerPort
	}
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

	shutdownDone := make(chan struct{})
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
		if capabilitiesHistoryStore != nil {
			capabilitiesHistoryStore.Close()
		}
		if sweeper != nil {
			sweeper.Stop()
		}
		if execSweeper != nil {
			execSweeper.Stop()
		}
		if orchestrator != nil {
			orchestrator.Stop()
		}
		wg.Wait()
		close(shutdownDone)
	}()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- http.ListenAndServe(addr, wrappedMux)
	}()

	select {
	case <-shutdownDone:
		return nil
	case err := <-serveErr:
		return fmt.Errorf("server error: %v", err)
	}
}

func init() {
	signal.Ignore(syscall.SIGPIPE)
}
