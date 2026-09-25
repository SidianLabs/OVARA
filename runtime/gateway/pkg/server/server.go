// Package server exposes the OVARA runtime gateway as an embeddable
// in-process server so that other binaries (e.g. a unified ovara CLI)
// can run it without shelling out to a separate executable.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"ovara.runtime.gateway/internal/anchor"
	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/auth"
	"ovara.runtime.gateway/internal/capabilities"
	"ovara.runtime.gateway/internal/config"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/enrollment"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/handlers"
	"ovara.runtime.gateway/internal/identity"
	"ovara.runtime.gateway/internal/idregistry"
	"ovara.runtime.gateway/internal/integrity"
	"ovara.runtime.gateway/internal/logging"
	"ovara.runtime.gateway/internal/metrics"
	"ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/receipt"
	"ovara.runtime.gateway/internal/receipts"
	"ovara.runtime.gateway/internal/record"
	"ovara.runtime.gateway/internal/replay"
	"ovara.runtime.gateway/internal/revocation"
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
	if err := cfg.ValidateStartup(); err != nil {
		return err
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

	// P2.3.1 cryptographic gateway identity: bind the enrollment gw_id
	// to a registered ed25519 key in the domain gateway registry and
	// prove possession before serving. Configured-but-failed trust
	// state fails startup (never silently untrusted); unconfigured →
	// in-memory registry (runtime-only trust, same convention as
	// identity_registry_file).
	gwTrust, err := initGatewayTrust(cfg, enrollmentSvc)
	if err != nil {
		return fmt.Errorf("gateway trust: %w", err)
	}

	// P2.3.4: the domain gateway registry IS the revocation authority —
	// one journal = one trust domain, so issuer/delegation/lease kills
	// share the hash-chain, the epoch (journal seq), and the anchor's
	// rollback protection. Durable when gateway_registry_file is set;
	// runtime-only (in-memory) otherwise, matching every other store.
	var revChecker revocation.Checker
	var revRegistry *gwidentity.Registry
	if gwTrust != nil && gwTrust.registry != nil {
		revChecker = gwTrust.registry
		revRegistry = gwTrust.registry
	}

	// P2.4 (C1/C5/C6): durable gateway trust signs every authority
	// journal — continuation, approval, execution, replay, receipts
	// (the decision journal), events, and the whole-file snapshots
	// (idregistry, capabilities). Signed mode requires BOTH a durable
	// registry AND a durable key file: a journal must still verify
	// against the same key after restart, so ephemeral-key deployments
	// keep the unsigned legacy format (documented trust level).
	// journal_signing_required=true refuses unsigned startup.
	durableSigning := gwTrust != nil && cfg.GatewayRegistryFile != "" && cfg.GatewayKeyFile != ""
	if cfg.JournalSigningRequired && !durableSigning {
		return fmt.Errorf("journal_signing_required=true but gateway trust is not durable (set gateway_registry_file AND gateway_key_file)")
	}
	var jsigner *record.Signer
	var jresolve record.ResolveFunc
	if durableSigning {
		jsigner = record.NewSigner(gwTrust.priv, gwTrust.registry.DomainID(), gwTrust.record.GatewayID, gwTrust.record.KeyID)
		resolver := receipt.RegistryResolver{Reg: gwTrust.registry}
		jresolve = resolver.ResolvePublicKey
		log.Printf("journal signing active: domain=%s key=%s — authority stores signed+chained+tip-ledgered", gwTrust.registry.DomainID(), gwTrust.record.KeyID)
	} else {
		log.Printf("journal signing inactive — authority stores unsigned (set gateway_registry_file+gateway_key_file, or journal_signing_required=true to enforce)")
	}
	var boundTips map[string]gwidentity.Tip
	if durableSigning && revRegistry != nil {
		boundTips = revRegistry.LatestTips(gwTrust.record.GatewayID)
	}
	bindWith := func(storeName string, s *record.Signer, rz record.ResolveFunc) *record.Binding {
		if s == nil || rz == nil {
			return nil
		}
		var floor record.Floor
		if t, ok := boundTips[storeName]; ok {
			floor = record.Floor{Known: true, Seq: t.Seq, Hash: t.Hash}
		}
		return &record.Binding{Signer: s, Resolve: rz, Floor: floor}
	}
	bind := func(storeName string) *record.Binding {
		if !durableSigning {
			return nil
		}
		return bindWith(storeName, jsigner, jresolve)
	}

	// C2-B A1: optional approver root — the approvals journal signs
	// under an INDEPENDENT key registered with role=approver, so a
	// stolen gateway.key alone can no longer manufacture claimable
	// authority. The pin (approver_pubkey, operator-held) is the
	// approver trust root — a C2-A bootstrap input.
	var approverBinding *record.Binding
	var approverKeys continuation.ApproverKeyChecker
	if cfg.ApproverKeyFile != "" || cfg.ApproverPubKey != "" {
		if cfg.ApproverKeyFile == "" || cfg.ApproverPubKey == "" {
			return fmt.Errorf("approver_key_file and approver_pubkey must be set together")
		}
		if !durableSigning {
			return fmt.Errorf("approver root configured but gateway trust is not durable (set gateway_registry_file AND gateway_key_file)")
		}
		privA, err := gwidentity.LoadOrCreateKey(cfg.ApproverKeyFile)
		if err != nil {
			return fmt.Errorf("approver key: %w", err)
		}
		pubA := privA.Public().(ed25519.PublicKey)
		if !strings.EqualFold(hex.EncodeToString(pubA), cfg.ApproverPubKey) {
			return fmt.Errorf("approver pin mismatch: approver_key_file does not match approver_pubkey")
		}
		if err := gwTrust.registry.SetApproverPin(pubA); err != nil {
			return fmt.Errorf("approver pin refused: %w", err)
		}
		recA, err := gwTrust.registry.AdmitApprover(pubA)
		if err != nil {
			return fmt.Errorf("approver admission refused: %w", err)
		}
		asigner := record.NewSigner(privA, gwTrust.registry.DomainID(), gwidentity.ApproverID, recA.KeyID)
		approverBinding = bindWith("approval", asigner, gwTrust.registry.ResolveApproverKey)
		approverKeys = gwTrust.registry
		log.Printf("approver-root active: approver_key_id=%s — approvals sign under an independent root", recA.KeyID)
	}
	// sinkFor returns the committed-floor hook: every fsynced journal
	// write ratchets the store's tip inside the anchored gwidentity
	// journal. A tip-ledger write failure must not succeed the append
	// — the store write is already durable; failing the caller keeps
	// the floor honest (the alternative is a floor that claims more
	// than the ledger recorded, which open-time fold would accept as
	// a tail-truncation signal).
	sinkFor := func(storeName string) func(seq uint64, hash string) error {
		if !durableSigning {
			return nil
		}
		return func(seq uint64, hash string) error {
			return revRegistry.RecordTips(gwTrust.record.GatewayID, map[string]gwidentity.Tip{
				storeName: {Seq: seq, Hash: hash},
			})
		}
	}
	// postOpenRatchet commits a store's current journal tip into the
	// ledger once, at startup — covers the store-ahead-of-ledger case
	// (crash between append fsync and tips write). seq==0 means an
	// empty journal — nothing to ratchet yet. Tip-of is used so every
	// binding-capable store shape (file stores, replay, idregistry)
	// needs no adapter.
	postOpenRatchet := func(storeName string, tipOf func() (uint64, string)) {
		if !durableSigning {
			return
		}
		seq, hash := tipOf()
		if seq == 0 {
			return
		}
		if err := revRegistry.RecordTips(gwTrust.record.GatewayID, map[string]gwidentity.Tip{
			storeName: {Seq: seq, Hash: hash},
		}); err != nil {
			log.Printf("warning: tip-ledger ratchet for %s failed: %v", storeName, err)
		}
	}

	policyStore := policy.NewStore(cfg.PolicyVersion)
	var watcher *policy.Watcher
	var wg sync.WaitGroup

	var eventStore events.Store
	if cfg.EventsFile != "" {
		store, err := events.NewFileBackedStoreWithRetention(cfg.EventsFile, cfg.EventsMaxSize, cfg.EventsRetentionDays, cfg.EventsMaxRecords, bind("events"))
		if err != nil {
			log.Printf("warning: failed to create file-backed event store: %v, using in-memory", err)
			eventStore = events.NewInMemoryStore(10000)
		} else {
			store.SetTipsSink(sinkFor("events"))
			postOpenRatchet("events", store.JournalTip)
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
			// Fail closed: a policy that can't be parsed must never
			// silently become the built-in default — the operator would
			// enforce a different policy than the one they deployed.
			return fmt.Errorf("failed to load policy file %s: %v", cfg.PolicyFile, err)
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
		store, err := receipts.NewFileBackedStore(cfg.ReceiptsFile, cfg.ReceiptsMaxSize, maxAge, bind("receipts"))
		if err != nil {
			log.Printf("warning: failed to create file-backed receipt store: %v, falling back to in-memory", err)
			receiptsStore = receipts.NewInMemoryStore()
		} else {
			store.SetTipsSink(sinkFor("receipts"))
			postOpenRatchet("receipts", store.JournalTip)
			receiptsStore = store
			log.Printf("receipts persisted to %s (max=%d, max_age=%dm)", cfg.ReceiptsFile, cfg.ReceiptsMaxSize, cfg.ReceiptsMaxAgeMinutes)
		}
	} else {
		receiptsStore = receipts.NewInMemoryStore()
		log.Printf("receipts in-memory (no persistence configured)")
	}

	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)

	// Durable replay protection (P2.1): a configured journal that cannot
	// be opened fails startup — silently falling back to process-local
	// replay would downgrade the security guarantee without the operator
	// knowing.
	if cfg.ReplayFile != "" {
		replayStore, err := replay.OpenFile(cfg.ReplayFile, cfg.ReplayMaxBytes, bind("replay"))
		if err != nil {
			return fmt.Errorf("replay store %s: %w", cfg.ReplayFile, err)
		}
		replayStore.SetTipsSink(sinkFor("replay"))
		postOpenRatchet("replay", replayStore.JournalTip)
		eval.SetReplayStore(replayStore)
		log.Printf("replay protection durable at %s", cfg.ReplayFile)
	} else {
		log.Printf("replay protection in-memory (process-local; set replay_file for durability)")
	}

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
		// Bind lease and delegation audience to THIS gateway identity —
		// a credential minted for another gateway can't be replayed here.
		if enrollmentSvc.GetIdentity() != nil {
			leaseValidator.SetExpectedAudience(enrollmentSvc.GetIdentity().ID)
		}
		eval.SetValidator(leaseValidator)
		log.Printf("trusted issuers configured (%d issuer key(s) for lease signature verification)", len(trustedKeys))
	} else {
		log.Printf("WARNING: trusted_issuers not configured; signed capability leases cannot be verified and will FAIL validation. Set trusted_issuers in config.json.")
	}
	// P2.3.4 shared revocation boundary — evaluation time: issuer,
	// delegation, lease checks on verified material + min_epoch + the
	// receipt's trust_epoch. Propagates into whichever validator is set.
	if revChecker != nil {
		eval.SetRevocation(revChecker)
		log.Printf("revocation boundary active (domain journal, epoch-monotonic)")
	}

	var approvalStore approval.Store
	if cfg.ApprovalsFile != "" {
		apprBind := bind("approval")
		if approverBinding != nil {
			apprBind = approverBinding
		}
		store, err := approval.NewFileBackedStore(cfg.ApprovalsFile, apprBind)
		if err != nil {
			log.Printf("warning: failed to create file-backed approval store: %v, falling back to in-memory", err)
			approvalStore = approval.NewInMemoryStore()
		} else {
			store.SetTipsSink(sinkFor("approval"))
			postOpenRatchet("approval", store.JournalTip)
			approvalStore = store
			log.Printf("approvals persisted to %s", cfg.ApprovalsFile)
		}
	} else {
		approvalStore = approval.NewInMemoryStore()
		log.Printf("approvals in-memory (no persistence configured)")
	}

	var continuationStore continuation.Store
	if cfg.ContinuationsFile != "" {
		store, err := continuation.NewFileBackedStoreWithRetention(cfg.ContinuationsFile, cfg.ContinuationsMaxSize, cfg.ContinuationRetentionDays, cfg.ContinuationMaxRecords, bind("continuation"))
		if err != nil {
			log.Printf("warning: failed to create file-backed continuation store: %v, using in-memory", err)
			continuationStore = continuation.NewInMemoryStore()
		} else {
			store.SetTipsSink(sinkFor("continuation"))
			postOpenRatchet("continuation", store.JournalTip)
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
		store, err := capabilities.NewFileBackedStore(cfg.CapabilitiesFile, cfg.CapabilitiesMaxSize, 0, bind("capabilities"))
		if err != nil {
			log.Printf("warning: failed to create file-backed capabilities store: %v, falling back to in-memory", err)
			capabilitiesStore = capabilities.NewInMemoryStore()
		} else {
			store.SetTipsSink(sinkFor("capabilities"))
			postOpenRatchet("capabilities", store.JournalTip)
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
	if revRegistry != nil {
		capabilitiesHandler.SetRevocationWriter(revRegistry)
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
	// P2.3.5 asymmetric receipt signatures: the gateway's registered
	// Ed25519 key signs every receipt. gwTrust.record is the admitted,
	// durably-registered (gateway_id, key_id) — key registration
	// precedes any receipt signing by construction. Without gateway
	// trust (open/dev mode) receipts keep the HMAC-only form.
	if gwTrust != nil {
		h.SetReceiptEdSigner(receipt.NewEdSigner(gwTrust.priv,
			gwTrust.record.GatewayID, gwTrust.record.KeyID))
		receiptHandler.SetKeyResolver(receipt.RegistryResolver{Reg: gwTrust.registry})
		log.Printf("receipt ed-signer configured (edsig_v1, gateway_key_id=%s)", gwTrust.record.KeyID)
	}

	approvalHandler.SetEventStore(eventStore)
	approvalHandler.SetGatewayID(enrollmentSvc.GetIdentity().ID)
	approvalHandler.SetContinuationStore(continuationStore)
	if revChecker != nil {
		approvalHandler.SetRevocation(revChecker)
	}
	// Approval provenance: /v1/approval/create resolves decision_id against
	// the decision cache — approvals exist only for gateway-produced
	// escalated decisions, bound to the exact recorded request.
	approvalHandler.SetDecisionLookup(h.LookupDecision)

	trustHandler.SetEventStore(eventStore)
	trustHandler.SetGatewayID(enrollmentSvc.GetIdentity().ID)

	eventHandler := handlers.NewEventHandler(eventStore)

	continuationHandler := handlers.NewContinuationHandler(continuationStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	policyHandler.RegisterRoutes(mux)
	capabilitiesHandler.RegisterRoutes(mux)
	approvalHandler.RegisterRoutes(mux)
	if revRegistry != nil {
		revocationsHandler := handlers.NewRevocationsHandler(revRegistry)
		revocationsHandler.SetEventStore(eventStore)
		revocationsHandler.SetGatewayID(enrollmentSvc.GetIdentity().ID)
		revocationsHandler.RegisterRoutes(mux)
	}
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
			bind("execution"),
		)
		if err != nil {
			log.Printf("warning: failed to create file-backed execution store: %v, using in-memory", err)
			execStore = execution.NewInMemoryStore()
		} else {
			store.SetTipsSink(sinkFor("execution"))
			postOpenRatchet("execution", store.JournalTip)
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

	execHandler := handlers.NewExecutionHandler(execStore)
	execHandler.SetContinuationStore(continuationStore)

	execRegistry := execution.NewExecutorRegistry()

	// Host executors run commands on the gateway host itself. They are
	// registered ONLY when explicitly enabled — the externally exposed API
	// must never reach arbitrary host execution by default.
	if cfg.EnableHostExecutors {
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

		execHandler.SetExecutor(shellExec)
		execRegistry.Register("shell", shellExec)

		directExec := execution.NewDirectExecutor(60)
		execRegistry.Register("exec", directExec)

		gitExec := execution.NewGitExecutor(60)
		execRegistry.Register("git.push", gitExec)
		execRegistry.Register("git.pull", gitExec)
		execRegistry.Register("git.fetch", gitExec)
		execRegistry.Register("git.checkout", gitExec)
		continuationHandler.SetExecutor(shellExec)
		log.Printf("host executors ENABLED (shell, exec, git.*) — enable_host_executors=true")
	} else {
		log.Printf("host executors DISABLED: shell/exec/git.* actions will never execute on the gateway host (set enable_host_executors=true to opt in)")
	}

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
	continuationHandler.SetEventStore(eventStore)
	continuationHandler.SetGatewayID(enrollmentSvc.GetIdentity().ID)

	orchestrator := continuation.NewOrchestrator(continuationStore, execStore, execRegistry)
	orchestrator.SetEventStore(eventStore)
	orchestrator.SetGatewayID(enrollmentSvc.GetIdentity().ID)
	orchestrator.SetApprovalStore(approvalStore, approverKeys)
	if revChecker != nil {
		orchestrator.SetRevocation(revChecker)
		continuationHandler.SetRevocation(revChecker)
	}
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

	authMw := auth.NewMiddlewareWithAgents(cfg.OperatorTokens, cfg.AgentTokens, cfg.AuthEnabled)

	// P2.2 stable identity + credential lifecycle. Config tokens seed
	// the registry: each gets identity id = its RC1 principal string, so
	// existing delegations/approvals/receipts keep their meaning.
	// Configured-but-unopenable registry fails startup (never silently
	// in-memory); unconfigured → in-memory (runtime revocation works,
	// dies at restart — RC1 parity).
	var idReg *idregistry.Registry
	if cfg.IdentityRegistryFile != "" {
		idReg, err = idregistry.Open(cfg.IdentityRegistryFile, bind("idregistry"))
		if err != nil {
			return fmt.Errorf("identity registry %s: %w", cfg.IdentityRegistryFile, err)
		}
		idReg.SetTipsSink(sinkFor("idregistry"))
		postOpenRatchet("idregistry", idReg.JournalTip)
		log.Printf("identity registry durable at %s", cfg.IdentityRegistryFile)
	} else {
		idReg = idregistry.NewInMemory()
		log.Printf("identity registry in-memory (revocation is runtime-only; set identity_registry_file for durability)")
	}
	if err := idReg.SeedConfig(cfg.OperatorTokens, "operator"); err != nil {
		return fmt.Errorf("identity registry seed (operator): %w", err)
	}
	if err := idReg.SeedConfig(cfg.AgentTokens, "agent"); err != nil {
		return fmt.Errorf("identity registry seed (agent): %w", err)
	}
	authMw.SetRegistry(idReg)
	identityHandler := handlers.NewIdentityHandler(idReg)
	identityHandler.RegisterRoutes(mux)
	// Suspended/retired identities' queued continuations never execute —
	// gated on both the orchestrator claim path and the synchronous
	// /continuations/{id}/execute endpoint.
	identityActive := func(agentID string) bool {
		st, ok := idReg.StatusOf(agentID)
		return ok && st == idregistry.StatusActive
	}
	orchestrator.SetIdentityChecker(identityActive)
	continuationHandler.SetIdentityChecker(identityActive)
	switch {
	case cfg.AuthEnabled && len(cfg.OperatorTokens) > 0:
		log.Printf("AUTH: auth_enabled=true with %d operator token(s) + %d agent token(s) configured", len(cfg.OperatorTokens), len(cfg.AgentTokens))
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

// gatewayTrust bundles the P2.3.1 cryptographic gateway identity:
// the domain key registry, this gateway's private key (never leaves
// this struct except to sign PoP), and its authenticated record.
type gatewayTrust struct {
	registry *gwidentity.Registry
	priv     ed25519.PrivateKey
	record   *gwidentity.KeyRecord
}

// initGatewayTrust binds the enrollment gateway_id to a registered
// ed25519 key and proves possession before the gateway serves.
//
// Flow: gw_id (enrollment, unchanged) → key file or ephemeral key →
// domain registry (durable or in-memory) → TOFU pins → register /
// adopt / rotate → usable-key check → PoP self-check. Every failure
// is fatal in durable mode; there is no silent fallback and no silent
// re-identity (a new gw_id is never generated here — enrollment owns
// the ID).
func initGatewayTrust(cfg *config.Config, svc enrollment.Service) (*gatewayTrust, error) {
	durable := cfg.GatewayRegistryFile != ""
	id := svc.GetIdentity()
	if id == nil || id.ID == "" {
		if durable {
			return nil, fmt.Errorf("enrollment produced no gateway_id — cannot bind trust state")
		}
		log.Printf("gateway trust: no gateway_id — running without cryptographic identity (in-memory mode)")
		return nil, nil
	}

	var priv ed25519.PrivateKey
	var err error
	if cfg.GatewayKeyFile != "" {
		priv, err = gwidentity.LoadOrCreateKey(cfg.GatewayKeyFile)
	} else {
		priv, err = gwidentity.GenerateKey()
	}
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)

	if (cfg.GatewayExpectedID == "") != (cfg.GatewayExpectedPubKey == "") {
		return nil, fmt.Errorf("gateway_expected_id and gateway_expected_pubkey must be set together")
	}
	if cfg.GatewayExpectedID != "" {
		if id.ID != cfg.GatewayExpectedID {
			return nil, fmt.Errorf("TOFU pin mismatch: enrollment id %s != expected %s", id.ID, cfg.GatewayExpectedID)
		}
		if !strings.EqualFold(hex.EncodeToString(pub), cfg.GatewayExpectedPubKey) {
			return nil, fmt.Errorf("TOFU pin mismatch: presented key does not match expected pubkey")
		}
	}

	var reg *gwidentity.Registry
	if durable {
		reg, err = gwidentity.Open(cfg.GatewayRegistryFile)
	} else {
		reg = gwidentity.NewInMemory()
	}
	if err != nil {
		return nil, err
	}

	// P2.3.3 anchor reconciliation: the local journal's chain tip is
	// compared against the oracle's monotonic record BEFORE admission.
	// The frozen table: L<A refuse, L==A+same tip accept, L==A+diff tip
	// refuse (equivocation), L>A refuse in strict (never auto-push —
	// a forged tail must not crown itself), empty journal refuses in
	// strict. Push failures inside mutate leave a durable unanchored
	// tail that this same path surfaces on the next boot.
	if err := reconcileAnchor(cfg, reg, priv, id.ID); err != nil {
		return nil, err
	}

	// Adopt / register / rotate. FindByPub is the restart path: our key
	// is already bound to this gw_id → reuse that record. force_rekey
	// with a NEW key rotates; with the same usable key it's a no-op.
	grace := time.Duration(cfg.GatewayKeyGraceSeconds) * time.Second
	if grace <= 0 {
		grace = 60 * time.Second
	}
	if grace > 24*time.Hour {
		return nil, fmt.Errorf("gateway_key_grace_seconds exceeds max 24h")
	}
	var rec *gwidentity.KeyRecord
	switch {
	case cfg.GatewayForceRekey && reg.FindByPub(id.ID, pub) == nil:
		rec, err = reg.Rotate(id.ID, pub, grace)
		if err != nil {
			return nil, fmt.Errorf("gateway rekey refused: %w", err)
		}
	default:
		// P2.3.2 admission: an existing same-key binding adopts (the
		// binding IS the earlier admission); a NEW identity requires an
		// authorized grant or TOFU pin when admission is required —
		// otherwise first-binding compat (open/dev mode).
		allowUngranted := !cfg.GatewayRequireAdmission || cfg.GatewayExpectedID != ""
		rec, err = reg.Admit(id.ID, pub, allowUngranted)
		if err != nil {
			return nil, fmt.Errorf("gateway admission refused: %w", err)
		}
	}
	if rec == nil || !gwidentity.Usable(rec) {
		st := "unknown"
		if rec != nil {
			st = string(rec.State)
		}
		return nil, fmt.Errorf("key file matches a %s key for %s — refusing to resurrect a dead key; generate a fresh key file",
			st, id.ID)
	}

	if !reg.HasUsableKey(id.ID) {
		return nil, fmt.Errorf("no usable gateway key for %s — a gateway with no active key cannot serve authenticated trust", id.ID)
	}

	// Proof-of-possession self-check: the registered key must actually
	// sign — catches key/registry desync and corrupt key material
	// before any traffic is served.
	challenge, err := gwidentity.Challenge()
	if err != nil {
		return nil, fmt.Errorf("gateway PoP challenge: %w", err)
	}
	sig := gwidentity.Prove(priv, rec.GatewayID, rec.KeyID, challenge)
	peer, err := reg.AuthenticatePeer(rec.GatewayID, rec.KeyID, challenge, sig)
	if err != nil {
		return nil, fmt.Errorf("gateway PoP self-check failed: %w", err)
	}

	mode := "in-memory (runtime-only)"
	if durable {
		mode = cfg.GatewayRegistryFile
	}
	admission := "open-first-binding (compat — NOT domain admission)"
	if cfg.GatewayRequireAdmission {
		admission = "required"
	}
	log.Printf("gateway identity authenticated: gateway_id=%s key_id=%s state=%s registry=%s admission=%s",
		peer.GatewayID, peer.KeyID, peer.State, mode, admission)
	return &gatewayTrust{registry: reg, priv: priv, record: rec}, nil
}

// reconcileAnchor enforces the frozen P2.3.3 reconciliation table
// before the gateway admits or serves. Returns nil when the gateway
// may proceed; any error is a refusal.
//
//	anchor_mode=off        → no-op (P2.3.2 behavior unchanged)
//	anchor_mode=strict     → every anomaly is fatal
//	anchor_mode=degraded   → rollback/equivocation fatal; unavailable
//	                         oracle and unanchored tail warn+proceed.
//	                         anchor_catchup=auto controls availability
//	                         tolerance only — it NEVER pushes a local-
//	                         ahead tail (operator catch-up is the only
//	                         authority-escalation path, both modes)
//
// The same routine also installs the mutation-time anchor hook:
// every committed journal record pushes a signed checkpoint through
// the registry's serialized mutation path.
func reconcileAnchor(cfg *config.Config, reg *gwidentity.Registry, priv ed25519.PrivateKey, gatewayID string) error {
	mode := cfg.GatewayAnchorMode
	if mode == "" || mode == "off" {
		return nil
	}
	if mode != "strict" && mode != "degraded" {
		return fmt.Errorf("gateway_anchor_mode %q unknown — want off|strict|degraded", mode)
	}
	strict := mode == "strict"
	if cfg.GatewayRegistryFile == "" {
		return fmt.Errorf("gateway_anchor_mode=%s requires gateway_registry_file — an in-memory journal has no history to anchor", mode)
	}
	if cfg.GatewayAnchorURL == "" || cfg.GatewayAnchorPin == "" {
		return fmt.Errorf("gateway_anchor_mode=%s requires gateway_anchor_url and gateway_anchor_pin", mode)
	}
	if strict && cfg.GatewayAnchorCatchup == "auto" {
		log.Printf("anchor: gateway_anchor_catchup=auto ignored in strict mode (strict never auto-pushes)")
	}
	if !strict && cfg.GatewayAnchorCatchup != "" && cfg.GatewayAnchorCatchup != "manual" && cfg.GatewayAnchorCatchup != "auto" {
		return fmt.Errorf("gateway_anchor_catchup %q unknown — want manual|auto", cfg.GatewayAnchorCatchup)
	}

	// The checkpoint signer: the dedicated anchor key (falls back to
	// the identity key). key_id is a provenance label derived from the
	// pubkey — no registry lookup (mutate pushes while holding the
	// registry lock; a lookup would self-deadlock). The same key is the
	// TLS client identity for Tier-2 mutual pinning.
	anchorPriv := priv
	if cfg.GatewayAnchorKeyFile != "" {
		var kerr error
		anchorPriv, kerr = gwidentity.LoadOrCreateKey(cfg.GatewayAnchorKeyFile)
		if kerr != nil {
			return kerr
		}
	}
	client, err := anchor.NewClient(cfg.GatewayAnchorURL, cfg.GatewayAnchorPin, "", anchorPriv)
	if err != nil {
		return fmt.Errorf("anchor client: %w", err)
	}
	anchorKeyID := "ext_" + hex.EncodeToString(anchorPriv.Public().(ed25519.PublicKey))[:16]
	signer := func(seq uint64, tip [32]byte) (*anchor.Checkpoint, error) {
		cp := anchor.Checkpoint{Version: anchor.CheckpointVersion, DomainID: reg.DomainID(),
			Seq: seq, TipHash: hex.EncodeToString(tip[:]), KeyID: anchorKeyID}
		s, err := anchor.Sign(anchorPriv, cp)
		if err != nil {
			return nil, err
		}
		return &s, nil
	}

	// Degraded semantics extend to the mutation path: a push failure
	// leaves the same unanchored tail either way — degraded logs and
	// continues (the tail surfaces at the next reconcile), strict
	// returns the error to the caller. Unavailable-oracle tolerance is
	// the point of degraded; the durable local record is never lost.
	var pusher anchor.Pusher = client
	if !strict {
		pusher = &warnPusher{inner: client}
	}

	res, acp, err := reg.ReconcileAnchor(context.Background(), client)
	switch {
	case err != nil:
		if errors.Is(err, anchor.ErrDomainUnregistered) {
			return fmt.Errorf("anchor domain %s not registered — run gwctl anchor-init first", reg.DomainID())
		}
		if strict {
			return fmt.Errorf("anchor reconcile failed (strict): %w", err)
		}
		log.Printf("anchor: oracle unreachable, continuing degraded: %v", err)
	case res == gwidentity.ReconcileOK:
		// local tip == oracle tip — authoritative agreement
	case res == gwidentity.ReconcileLocalBehind:
		return fmt.Errorf("local journal behind oracle (local seq < anchored seq %d) — history rolled back; refusing", acp.Seq)
	case res == gwidentity.ReconcileEquivocation:
		return fmt.Errorf("local journal equivocates at seq %d (tip hash differs from oracle) — refusing", acp.Seq)
	case res == gwidentity.ReconcileEmpty:
		if strict {
			return fmt.Errorf("anchor configured but journal is empty — run gwctl anchor-init first")
		}
	case res == gwidentity.ReconcileLocalAhead:
		_, seq, _ := reg.ChainTip()
		if strict {
			return fmt.Errorf("unanchored tail: local seq %d > oracle seq %d — refusing (run gwctl anchor-catchup)", seq, acp.Seq)
		}
		// F-C1 remediation: degraded mode NEVER auto-pushes a local-ahead
		// tail — a self-consistent forged tail is indistinguishable from a
		// crash window, so pushing it would convert an unverified journal
		// into authoritative oracle state. Unavailability tolerance is the
		// only thing degraded buys; authority escalation always requires
		// the operator's explicit out-of-band confirmation.
		if cfg.GatewayAnchorCatchup == "auto" {
			log.Printf("anchor: gateway_anchor_catchup=auto no longer auto-pushes (P2.3.3 remediation) — operator catch-up required")
		}
		log.Printf("anchor: unanchored tail (local seq %d > oracle %d) — degraded mode continuing WITHOUT anchoring; run gwctl anchor-catchup", seq, acp.Seq)
	}
	return reg.SetAnchor(pusher, signer)
}

// warnPusher degrades oracle UNAVAILABILITY to warnings — the local
// mutation is already durable (fsync before push), so an offline oracle
// leaves the same unanchored tail either way. F-D1 remediation: only
// availability errors are swallowed; integrity signals (equivocation,
// bad key, malformed response) propagate and fail the mutation — a fork
// is never masked as "oracle offline".
type warnPusher struct{ inner anchor.Pusher }

func (w *warnPusher) Commit(ctx context.Context, domain string, cp *anchor.Checkpoint) error {
	if err := w.inner.Commit(ctx, domain, cp); err != nil {
		if errors.Is(err, anchor.ErrUnavailable) {
			log.Printf("anchor: checkpoint push failed (degraded — unanchored tail, reconcile at next boot): %v", err)
			return nil
		}
		log.Printf("anchor: INTEGRITY failure on checkpoint push — refusing to mask it: %v", err)
		return err
	}
	return nil
}

func init() {
	signal.Ignore(syscall.SIGPIPE)
}
