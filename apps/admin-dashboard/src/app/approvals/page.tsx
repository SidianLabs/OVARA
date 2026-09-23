'use client';

import { useState } from 'react';
import { CheckCircle2, XCircle, ShieldAlert, AlertTriangle } from 'lucide-react';
import { ovaraClient, ApprovalInfo } from '@/lib/api-client';
import { useApiData } from '@/lib/use-api';

const MOCK: ApprovalInfo[] = [
  {
    approvalId: 'ap_001', decisionId: 'dec_7741', actionType: 'shell.exec',
    resource: 'shell:rm -rf /var/cache/build', environment: 'production',
    status: 'pending', createdAt: '2026-01-15T14:31:12Z',
    agentId: 'agent-ci-runner-3', trustScore: 0.42, trustLevel: 'low',
    anomalyCodes: ['new_resource', 'after_hours'], gatewayId: 'gw_1', gatewayName: 'gw-prod-01',
  },
  {
    approvalId: 'ap_002', decisionId: 'dec_7735', actionType: 'git.push',
    resource: 'git:origin/main', environment: 'production',
    status: 'pending', createdAt: '2026-01-15T14:29:44Z',
    agentId: 'agent-release-bot', trustScore: 0.71, trustLevel: 'medium',
    gatewayId: 'gw_1', gatewayName: 'gw-prod-01',
  },
  {
    approvalId: 'ap_003', decisionId: 'dec_7720', actionType: 'http.request',
    resource: 'https://api.stripe.com/v1/charges', environment: 'production',
    status: 'approved', createdAt: '2026-01-15T13:58:02Z',
    resolvedAt: '2026-01-15T13:59:10Z', resolvedBy: 'operator:oncall',
    agentId: 'agent-billing', gatewayId: 'gw_2', gatewayName: 'gw-staging-01',
  },
];

const statusBadge: Record<string, string> = {
  pending: 'bg-yellow-900/40 text-yellow-500',
  approved: 'bg-green-900/40 text-green-500',
  denied: 'bg-red-900/40 text-red-500',
};

export default function ApprovalsPage() {
  const { data, live, reload } = useApiData(() => ovaraClient.listApprovals(), { approvals: MOCK, gatewayErrors: [] });
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const resolve = async (a: ApprovalInfo, action: 'approve' | 'deny') => {
    setBusy(`${a.approvalId}:${action}`);
    setActionError(null);
    try {
      await ovaraClient.resolveApproval(a.gatewayId, a.approvalId, action);
      reload();
    } catch (err) {
      setActionError(`${action} failed for ${a.approvalId}: ${(err as Error).message}`);
    } finally {
      setBusy(null);
    }
  };

  const pending = data.approvals.filter((a) => a.status === 'pending');

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Approvals</h1>
        <p className="text-slate-400 mt-1">
          Escalated actions waiting on a human — approve runs them, deny kills them
          {!live && <span className="ml-2 text-xs px-2 py-0.5 rounded-full bg-yellow-900/40 text-yellow-500">demo data — API offline</span>}
        </p>
      </div>

      {data.gatewayErrors.length > 0 && (
        <div className="flex items-start gap-3 p-4 bg-yellow-900/20 border border-yellow-800/50 rounded-lg text-sm text-yellow-500">
          <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
          <div>
            {data.gatewayErrors.map((e) => (
              <p key={e.gatewayName}>{e.gatewayName}: unreachable — {e.error}</p>
            ))}
          </div>
        </div>
      )}
      {actionError && (
        <div className="p-4 bg-red-900/20 border border-red-800/50 rounded-lg text-sm text-red-400">{actionError}</div>
      )}

      <div className="bg-surface border border-surface-border rounded-xl overflow-hidden">
        <div className="grid grid-cols-[1fr_1fr_120px_140px_180px] gap-4 px-6 py-3 border-b border-surface-border text-xs font-medium text-slate-500 uppercase tracking-wider">
          <span>Action</span><span>Agent · Gateway</span><span>Trust</span><span>Status</span><span className="text-right">Resolve</span>
        </div>
        {data.approvals.length === 0 && (
          <div className="px-6 py-10 text-center text-slate-500 text-sm">No approvals — nothing is waiting on a human.</div>
        )}
        {data.approvals.map((a) => (
          <div key={`${a.gatewayId}:${a.approvalId}`}
            className="grid grid-cols-[1fr_1fr_120px_140px_180px] gap-4 px-6 py-4 border-b border-surface-border last:border-0 items-center">
            <div>
              <p className="text-sm text-white font-mono">{a.actionType}</p>
              <p className="text-xs text-slate-500 font-mono truncate" title={a.resource}>{a.resource}</p>
              {a.anomalyCodes && a.anomalyCodes.length > 0 && (
                <p className="text-xs text-orange-400 mt-1 flex items-center gap-1">
                  <ShieldAlert className="h-3 w-3" /> {a.anomalyCodes.join(', ')}
                  {a.restricted && ' · restricted'}
                </p>
              )}
            </div>
            <div>
              <p className="text-sm text-slate-300">{a.agentId ?? '—'}</p>
              <p className="text-xs text-slate-500">{a.gatewayName} · {a.environment}</p>
            </div>
            <div>
              {a.trustScore != null ? (
                <>
                  <p className="text-sm text-white">{a.trustScore.toFixed(2)}</p>
                  <p className="text-xs text-slate-500">{a.trustLevel}</p>
                </>
              ) : <p className="text-sm text-slate-500">—</p>}
            </div>
            <div>
              <span className={`text-xs px-2 py-0.5 rounded-full ${statusBadge[a.status] ?? 'bg-surface-lighter text-slate-400'}`}>
                {a.status}
              </span>
              {a.resolvedBy && <p className="text-xs text-slate-500 mt-1">by {a.resolvedBy}</p>}
            </div>
            <div className="flex justify-end gap-2">
              {a.status === 'pending' && (
                <>
                  <button
                    disabled={busy !== null}
                    onClick={() => resolve(a, 'approve')}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-green-900/30 hover:bg-green-900/50 text-green-400 rounded-lg text-xs disabled:opacity-40"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" /> {busy === `${a.approvalId}:approve` ? '…' : 'Approve'}
                  </button>
                  <button
                    disabled={busy !== null}
                    onClick={() => resolve(a, 'deny')}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-red-900/30 hover:bg-red-900/50 text-red-400 rounded-lg text-xs disabled:opacity-40"
                  >
                    <XCircle className="h-3.5 w-3.5" /> {busy === `${a.approvalId}:deny` ? '…' : 'Deny'}
                  </button>
                </>
              )}
            </div>
          </div>
        ))}
      </div>
      <p className="text-xs text-slate-600">{pending.length} pending · resolutions route through the control plane to the owning gateway</p>
    </div>
  );
}
