import { describe, it, expect } from 'vitest';
import type {
  ActionType,
  Environment,
  Decision,
  TrustLevel,
  ApprovalState,
  ReasonCode,
  ActionRequest,
  AgentIdentity,
  CapabilityLease,
  DelegationChain,
  DecisionResponse,
  ReceiptStub,
  TrustContext,
  AnomalySignal,
  Approval,
  Receipt,
  Gateway,
  Policy,
  PolicyRule,
  HealthResponse,
  MetricsResponse,
} from '../index';

describe('Type exports', () => {
  it('ActionType is a string union of all action types', () => {
    const actions: ActionType[] = [
      'shell',
      'exec',
      'git.push',
      'git.pull',
      'git.fetch',
      'git.checkout',
      'git.force_push',
      'github.push',
      'github.pr',
      'github.merge',
      'github.delete_branch',
      'ci.deploy',
      'ci.build_trigger',
      'ci.approval',
    ];
    actions.forEach((action) => {
      const result: ActionType = action;
      expect(result).toBe(action);
    });
  });

  it('Environment is limited to 4 values', () => {
    const envs: Environment[] = ['local', 'dev', 'staging', 'production'];
    envs.forEach((env) => {
      const result: Environment = env;
      expect(result).toBe(env);
    });
  });

  it('Decision is allow | deny | escalate', () => {
    const decisions: Decision[] = ['allow', 'deny', 'escalate'];
    decisions.forEach((d) => {
      const result: Decision = d;
      expect(result).toBe(d);
    });
  });

  it('TrustLevel has 4 levels', () => {
    const levels: TrustLevel[] = ['none', 'low', 'medium', 'high'];
    levels.forEach((l) => {
      const result: TrustLevel = l;
      expect(result).toBe(l);
    });
  });

  it('ApprovalState has 4 states', () => {
    const states: ApprovalState[] = ['pending', 'approved', 'denied', 'expired'];
    states.forEach((s) => {
      const result: ApprovalState = s;
      expect(result).toBe(s);
    });
  });
});

describe('ActionRequest', () => {
  it('accepts minimal required fields', () => {
    const req: ActionRequest = {
      action_type: 'shell',
      resource: 'shell:ls',
      environment: 'local',
    };
    expect(req.action_type).toBe('shell');
    expect(req.environment).toBe('local');
  });

  it('accepts all optional fields', () => {
    const req: ActionRequest = {
      action_type: 'git.push',
      resource: 'git:origin/main',
      environment: 'staging',
      agent_identity: { issuer: 'ovara', subject_id: 'agent-001' },
      capability_lease: {
        lease_id: 'lease-001',
        issuer: 'ovara',
        subject: 'agent-001',
        allowed_actions: ['shell'],
        resource_scope: '*',
        expiry: '9999999999',
        delegation_depth: 0,
      },
      delegation_chain: {
        authorities: [{ issuer: 'ovara', subject_id: 'agent-001' }],
        depth: 1,
      },
      metadata: { trace_id: 'abc123' },
    };
    expect(req.agent_identity?.issuer).toBe('ovara');
    expect(req.capability_lease?.lease_id).toBe('lease-001');
    expect(req.delegation_chain?.depth).toBe(1);
    expect(req.metadata?.trace_id).toBe('abc123');
  });
});

describe('AgentIdentity', () => {
  it('required fields only', () => {
    const id: AgentIdentity = { issuer: 'ovara', subject_id: 'agent-001' };
    expect(id.issuer).toBe('ovara');
    expect(id.subject_id).toBe('agent-001');
  });

  it('all optional fields', () => {
    const id: AgentIdentity = {
      issuer: 'ovara',
      subject_id: 'agent-001',
      owner: 'team-a',
      lifecycle: 'active',
      verify_key: 'ed25519:abc123',
    };
    expect(id.owner).toBe('team-a');
    expect(id.lifecycle).toBe('active');
  });
});

describe('CapabilityLease', () => {
  it('required fields', () => {
    const lease: CapabilityLease = {
      lease_id: 'lease-001',
      issuer: 'ovara',
      subject: 'agent-001',
      allowed_actions: ['shell', 'exec'],
      resource_scope: '*',
      expiry: '9999999999',
      delegation_depth: 0,
    };
    expect(lease.allowed_actions).toContain('shell');
  });

  it('signature as number array', () => {
    const lease: CapabilityLease = {
      lease_id: 'lease-001',
      issuer: 'ovara',
      subject: 'agent-001',
      allowed_actions: ['shell'],
      resource_scope: '*',
      expiry: '9999999999',
      delegation_depth: 0,
      signature: [1, 2, 3, 4],
    };
    expect(lease.signature).toHaveLength(4);
  });
});

describe('DelegationChain', () => {
  it('authorities array', () => {
    const chain: DelegationChain = {
      authorities: [
        { issuer: 'root', subject_id: 'agent-001' },
        { issuer: 'agent-001', subject_id: 'agent-002', delegated_at: '2026-01-01T00:00:00Z' },
      ],
      depth: 2,
    };
    expect(chain.authorities).toHaveLength(2);
    expect(chain.depth).toBe(2);
  });
});

describe('DecisionResponse', () => {
  it('full structure', () => {
    const resp: DecisionResponse = {
      decision_id: 'dec-001',
      decision: 'allow',
      reason_codes: ['allowed'],
      trust_score: 0.95,
      trust_level: 'high',
      requires_approval: false,
      receipt_stub: {
        receipt_id: 'rcpt-001',
        action_digest: 'sha256:abc',
        action_type: 'shell',
        resource: 'shell:ls',
        policy_version: '1.0',
        trust_context_score: 0.95,
        issued_at: '2026-06-11T00:00:00Z',
      },
      trust_context: {
        score: 0.95,
        level: 'high',
        anomaly_signals: [{ code: 'risky_shell', severity: 'low', description: 'pattern detected' }],
        shield_active: false,
        restricted: false,
        risk_count: 0,
        evaluation_time: '2026-06-11T00:00:00Z',
      },
      evaluation_summary: 'All checks passed',
    };
    expect(resp.decision).toBe('allow');
    expect(resp.trust_level).toBe('high');
    expect(resp.receipt_stub?.receipt_id).toBe('rcpt-001');
    expect(resp.trust_context?.shield_active).toBe(false);
  });

  it('minimal structure', () => {
    const resp: DecisionResponse = {
      decision_id: 'dec-001',
      decision: 'deny',
      reason_codes: ['policy_deny'],
      trust_score: 0.1,
      trust_level: 'none',
      requires_approval: false,
    };
    expect(resp.decision).toBe('deny');
  });
});

describe('TrustContext', () => {
  it('anomaly signals array', () => {
    const ctx: TrustContext = {
      score: 0.5,
      level: 'medium',
      anomaly_signals: [
        { code: 'risky_shell', severity: 'medium', description: 'curl |sh detected' },
        { code: 'production_target', severity: 'high', description: 'production environment' },
      ],
      shield_active: true,
      restricted: true,
      risk_count: 2,
      evaluation_time: '2026-06-11T00:00:00Z',
    };
    expect(ctx.anomaly_signals).toHaveLength(2);
    expect(ctx.shield_active).toBe(true);
  });
});

describe('Approval', () => {
  it('pending approval', () => {
    const approval: Approval = {
      id: 'apr-001',
      decision_id: 'dec-001',
      action_type: 'git.push',
      resource: 'git:origin/main',
      agent_id: 'agent-001',
      gateway_id: 'gw-001',
      state: 'pending',
      requested_at: '2026-06-11T00:00:00Z',
    };
    expect(approval.state).toBe('pending');
  });

  it('resolved approval', () => {
    const approval: Approval = {
      id: 'apr-001',
      decision_id: 'dec-001',
      action_type: 'shell',
      resource: 'shell:ls',
      agent_id: 'agent-001',
      gateway_id: 'gw-001',
      state: 'approved',
      requested_at: '2026-06-11T00:00:00Z',
      resolved_at: '2026-06-11T01:00:00Z',
      resolved_by: 'admin@example.com',
      reason: 'Approved for deployment',
    };
    expect(approval.state).toBe('approved');
    expect(approval.resolved_by).toBe('admin@example.com');
  });
});

describe('Receipt', () => {
  it('full receipt', () => {
    const receipt: Receipt = {
      receipt_id: 'rcpt-001',
      decision_id: 'dec-001',
      action_type: 'shell',
      resource: 'shell:ls',
      decision: 'allow',
      agent_identity: 'agent-001',
      trust_score: 0.95,
      policy_version: '1.0',
      issued_at: '2026-06-11T00:00:00Z',
      signature: 'sig_v1:abc123',
      organization_id: 'org-001',
      gateway_id: 'gw-001',
    };
    expect(receipt.signature).toContain('sig_v1');
  });

  it('minimal receipt', () => {
    const receipt: Receipt = {
      receipt_id: 'rcpt-001',
      decision_id: 'dec-001',
      action_type: 'shell',
      resource: 'shell:ls',
      decision: 'allow',
      trust_score: 0.5,
      policy_version: '1.0',
      issued_at: '2026-06-11T00:00:00Z',
    };
    expect(receipt.agent_identity).toBeUndefined();
  });
});

describe('Gateway', () => {
  it('active gateway', () => {
    const gw: Gateway = {
      id: 'gw-001',
      name: 'us-east-gateway',
      organization_id: 'org-001',
      status: 'active',
      enrolled_at: '2026-01-01T00:00:00Z',
      last_heartbeat: '2026-06-11T00:00:00Z',
      version: '0.8.0',
    };
    expect(gw.status).toBe('active');
    expect(gw.version).toBe('0.8.0');
  });
});

describe('Policy', () => {
  it('policy with rules', () => {
    const policy: Policy = {
      version: '1.0',
      rules: [
        { action_type: 'shell', environment: 'local', allow: true },
        { action_type: 'shell', environment: 'production', deny: true },
        { action_type: 'git.push', environment: '*', escalate: true },
        { action_type: '*', environment: 'production', min_trust_score: 0.8 },
        { action_type: '*', environment: '*', min_trust_level: 'medium' },
      ],
      updated_at: '2026-06-01T00:00:00Z',
      updated_by: 'admin@example.com',
    };
    expect(policy.rules).toHaveLength(5);
    expect(policy.rules[3].min_trust_score).toBe(0.8);
    expect(policy.rules[4].min_trust_level).toBe('medium');
  });
});

describe('HealthResponse', () => {
  it('with SLA section', () => {
    const health: HealthResponse = {
      status: 'healthy',
      sla: {
        executing_total: 3,
        executing_breaching: 0,
        escalations_pending: 2,
        breaches: [],
      },
    };
    expect(health.sla?.executing_total).toBe(3);
  });

  it('without SLA section', () => {
    const health: HealthResponse = { status: 'healthy' };
    expect(health.sla).toBeUndefined();
  });
});

describe('MetricsResponse', () => {
  it('full metrics', () => {
    const metrics: MetricsResponse = {
      decisions_total: 1000,
      allow_count: 800,
      deny_count: 150,
      escalate_count: 50,
      avg_trust_score: 0.85,
      uptime_seconds: 3600,
    };
    expect(metrics.allow_count + metrics.deny_count + metrics.escalate_count).toBe(metrics.decisions_total);
  });
});