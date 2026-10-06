# T2-F01 minimal repro

System: v1 evaluator, prod wiring (store+shield+validator).
Policy: allow fs.write /allowed/* ; deny * /canary/* ; default deny.

    req := &models.ActionRequest{
        ActionType: "fs.write",
        Resource:   "/allowed/../canary/leak.txt",  // raw wire string
        Environment: "dev", Nonce: unique, IssuedAt: now,
        AgentIdentity: {Issuer:"issuer", SubjectID:"agent1"}}
    // no CapabilityLease — the allow rule doesn't require one
    resp := ev.Evaluate(req)   // → DecisionAllow (policy_allow)

Ground truth: kernel resolves the resource to /canary/leak.txt —
unauthorized + consequential. Three lines of attack surface, zero
attacker privilege beyond an enrolled identity.

Why v1 allows: globMatch("/allowed/*", raw) anchors "/allowed/" at
index 0 → match. No canonicalization stage exists in v1's pipeline.
