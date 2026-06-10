'use client';

import { Search, Filter, Download } from 'lucide-react';

export default function AuditLogPage() {
  const entries = [
    { id: 'aud_001', timestamp: '2026-01-15T14:32:01Z', gateway: 'gw-prod-01', action: 'shell.execute', decision: 'deny', agent: 'agt_abc123' },
    { id: 'aud_002', timestamp: '2026-01-15T14:32:00Z', gateway: 'gw-prod-02', action: 'git.push', decision: 'allow', agent: 'agt_def456' },
    { id: 'aud_003', timestamp: '2026-01-15T14:31:58Z', gateway: 'gw-prod-01', action: 'git.pull', decision: 'allow', agent: 'agt_ghi789' },
    { id: 'aud_004', timestamp: '2026-01-15T14:31:55Z', gateway: 'gw-prod-03', action: 'shell.execute', decision: 'escalate', agent: 'agt_jkl012' },
    { id: 'aud_005', timestamp: '2026-01-15T14:31:50Z', gateway: 'gw-prod-01', action: 'git.fetch', decision: 'allow', agent: 'agt_mno345' },
    { id: 'aud_006', timestamp: '2026-01-15T14:31:47Z', gateway: 'gw-stage-01', action: 'shell.execute', decision: 'deny', agent: 'agt_pqr678' },
    { id: 'aud_007', timestamp: '2026-01-15T14:31:42Z', gateway: 'gw-prod-02', action: 'git.push', decision: 'allow', agent: 'agt_stu901' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Audit Log</h1>
        <p className="text-slate-400 mt-1">Immutable decision history with cryptographic receipts</p>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search by agent, action, or decision..."
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
                <th className="text-left p-4 text-sm font-medium text-slate-400">Gateway</th>
                <th className="text-left p-4 text-sm font-medium text-slate-400">Action</th>
                <th className="text-left p-4 text-sm font-medium text-slate-400">Decision</th>
                <th className="text-left p-4 text-sm font-medium text-slate-400">Agent</th>
                <th className="text-right p-4 text-sm font-medium text-slate-400">Receipt</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id} className="border-b border-surface-border last:border-0 hover:bg-surface-lighter/50 transition-colors">
                  <td className="p-4 text-sm text-slate-300 font-mono">{new Date(e.timestamp).toLocaleString()}</td>
                  <td className="p-4 text-sm text-slate-400">{e.gateway}</td>
                  <td className="p-4 text-sm text-white">{e.action}</td>
                  <td className="p-4">
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                      e.decision === 'allow' ? 'bg-green-900/50 text-green-400' :
                      e.decision === 'deny' ? 'bg-red-900/50 text-red-400' :
                      'bg-yellow-900/50 text-yellow-400'
                    }`}>
                      {e.decision}
                    </span>
                  </td>
                  <td className="p-4 text-sm text-slate-300 font-mono">{e.agent}</td>
                  <td className="p-4 text-right">
                    <button className="text-xs text-ovara-400 hover:text-ovara-300 font-mono">
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
