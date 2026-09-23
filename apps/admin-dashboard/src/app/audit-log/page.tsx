'use client';

import { useState } from 'react';
import { Search, Filter, Download } from 'lucide-react';
import { ovaraClient, AuditEntry } from '@/lib/api-client';
import { useApiData } from '@/lib/use-api';

const MOCK_ENTRIES: AuditEntry[] = [
  { id: 'aud_001', timestamp: '2026-01-15T14:32:01Z', actor: 'apikey:gw-ops', action: 'policy.publish', resource: 'policy:pol_prod_lockdown', resourceId: 'pol_prod_lockdown' },
  { id: 'aud_002', timestamp: '2026-01-15T14:32:00Z', actor: 'apikey:ci-bot', action: 'gateway.enroll', resource: 'gateway:gw-prod-01', resourceId: 'gw-prod-01' },
  { id: 'aud_003', timestamp: '2026-01-15T14:31:58Z', actor: 'apikey:gw-ops', action: 'policy.create', resource: 'policy:pol_ci_pipeline', resourceId: 'pol_ci_pipeline' },
  { id: 'aud_004', timestamp: '2026-01-15T14:31:55Z', actor: 'apikey:admin', action: 'apikey.revoke', resource: 'apikey:k_old', resourceId: 'k_old' },
  { id: 'aud_005', timestamp: '2026-01-15T14:31:50Z', actor: 'apikey:ci-bot', action: 'revocation.execute', resource: 'revocation:rv_011', resourceId: 'rv_011' },
];

export default function AuditLogPage() {
  const { data: entries, live } = useApiData(() => ovaraClient.queryAuditLog(200), MOCK_ENTRIES);
  const [q, setQ] = useState('');
  const filtered = q
    ? entries.filter((e) =>
        [e.actor, e.action, e.resource, e.resourceId].some((f) => f?.toLowerCase().includes(q.toLowerCase())))
    : entries;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Audit Log</h1>
        <p className="text-slate-400 mt-1">
          Control-plane activity — every authenticated mutation, scoped to your organization
          {!live && <span className="ml-2 text-xs px-2 py-0.5 rounded-full bg-yellow-900/40 text-yellow-500">demo data — API offline</span>}
        </p>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by actor, action, or resource..."
            className="w-full pl-10 pr-4 py-2.5 bg-surface-light border border-surface-border rounded-lg text-sm text-white placeholder:text-slate-600 focus:outline-none focus:border-ovara-500"
          />
        </div>
        <button className="flex items-center gap-2 px-4 py-2.5 bg-surface-light border border-surface-border rounded-lg text-sm text-slate-300 hover:text-white transition-colors">
          <Filter className="h-4 w-4" />
          Filters
        </button>
        <button className="flex items-center gap-2 px-4 py-2.5 bg-surface-light border border-surface-border rounded-lg text-sm text-slate-300 hover:text-white transition-colors">
          <Download className="h-4 w-4" />
          Export
        </button>
      </div>

      <div className="bg-surface-light rounded-xl border border-surface-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-surface-border">
                <th className="text-left p-4 text-sm font-medium text-slate-400">Timestamp</th>
                <th className="text-left p-4 text-sm font-medium text-slate-400">Actor</th>
                <th className="text-left p-4 text-sm font-medium text-slate-400">Action</th>
                <th className="text-left p-4 text-sm font-medium text-slate-400">Resource</th>
                <th className="text-right p-4 text-sm font-medium text-slate-400">Resource ID</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e) => (
                <tr key={e.id} className="border-b border-surface-border last:border-0 hover:bg-surface-lighter/50 transition-colors">
                  <td className="p-4 text-sm text-slate-300 font-mono">{new Date(e.timestamp).toLocaleString()}</td>
                  <td className="p-4 text-sm text-slate-400 font-mono">{e.actor}</td>
                  <td className="p-4 text-sm text-white">{e.action}</td>
                  <td className="p-4 text-sm text-slate-300">{e.resource}</td>
                  <td className="p-4 text-sm text-slate-500 text-right font-mono">{e.resourceId ?? '—'}</td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-sm text-slate-500">
                    {live ? 'No audit entries yet — authenticated mutations will appear here.' : 'No matching entries.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
