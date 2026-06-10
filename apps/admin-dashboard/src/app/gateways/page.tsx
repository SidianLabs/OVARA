'use client';

import { Shield, Plus, RefreshCw } from 'lucide-react';

export default function GatewaysPage() {
  const gateways = [
    { id: 'gw-prod-01', region: 'us-east-1', status: 'healthy', version: 'v1.0.0', decisions: 45231, lastHeartbeat: '2s ago' },
    { id: 'gw-prod-02', region: 'us-west-2', status: 'healthy', version: 'v1.0.0', decisions: 38921, lastHeartbeat: '5s ago' },
    { id: 'gw-prod-03', region: 'eu-west-1', status: 'degraded', version: 'v1.0.0', decisions: 29104, lastHeartbeat: '12s ago' },
    { id: 'gw-stage-01', region: 'us-east-1', status: 'healthy', version: 'v1.1.0-rc1', decisions: 5421, lastHeartbeat: '1s ago' },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Gateways</h1>
          <p className="text-slate-400 mt-1">Manage your Ovara runtime gateways</p>
        </div>
        <div className="flex gap-3">
          <button className="flex items-center gap-2 px-4 py-2 bg-surface-lighter border border-surface-border rounded-lg text-sm text-slate-300 hover:text-white transition-colors">
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-ovara-600 hover:bg-ovara-500 rounded-lg text-sm text-white font-medium transition-colors">
            <Plus className="h-4 w-4" />
            Register Gateway
          </button>
        </div>
      </div>

      <div className="bg-surface-light rounded-xl border border-surface-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-surface-border">
                <th className="text-left p-4 text-sm font-medium text-slate-400">Gateway ID</th>
                <th className="text-left p-4 text-sm font-medium text-slate-400">Region</th>
                <th className="text-left p-4 text-sm font-medium text-slate-400">Status</th>
                <th className="text-left p-4 text-sm font-medium text-slate-400">Version</th>
                <th className="text-right p-4 text-sm font-medium text-slate-400">Decisions</th>
                <th className="text-right p-4 text-sm font-medium text-slate-400">Heartbeat</th>
              </tr>
            </thead>
            <tbody>
              {gateways.map((gw) => (
                <tr key={gw.id} className="border-b border-surface-border last:border-0 hover:bg-surface-lighter/50 transition-colors">
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <Shield className={`h-4 w-4 ${gw.status === 'healthy' ? 'text-green-400' : 'text-yellow-400'}`} />
                      <span className="text-white font-mono text-sm">{gw.id}</span>
                    </div>
                  </td>
                  <td className="p-4 text-sm text-slate-300">{gw.region}</td>
                  <td className="p-4">
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                      gw.status === 'healthy' ? 'bg-green-900/50 text-green-400' : 'bg-yellow-900/50 text-yellow-400'
                    }`}>
                      {gw.status}
                    </span>
                  </td>
                  <td className="p-4 text-sm text-slate-300 font-mono">{gw.version}</td>
                  <td className="p-4 text-sm text-slate-300 text-right font-mono">{gw.decisions.toLocaleString()}</td>
                  <td className="p-4 text-sm text-slate-500 text-right">{gw.lastHeartbeat}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
