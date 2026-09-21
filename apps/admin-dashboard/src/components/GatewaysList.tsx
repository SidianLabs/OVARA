'use client';

import { Shield, MoreVertical } from 'lucide-react';

export function GatewaysList() {
  const gateways = [
    { id: 'gw-prod-01', region: 'us-east-1', status: 'healthy', uptime: '99.9%', load: '1.2k req/s' },
    { id: 'gw-prod-02', region: 'us-west-2', status: 'healthy', uptime: '99.8%', load: '847 req/s' },
    { id: 'gw-prod-03', region: 'eu-west-1', status: 'degraded', uptime: '98.2%', load: '623 req/s' },
    { id: 'gw-stage-01', region: 'us-east-1', status: 'healthy', uptime: '99.5%', load: '112 req/s' },
  ];

  return (
    <div className="space-y-3">
      {gateways.map((gw) => (
        <div key={gw.id} className="flex items-center justify-between py-2 border-b border-surface-border last:border-0">
          <div className="flex items-center gap-3">
            <Shield className={`h-4 w-4 ${
              gw.status === 'healthy' ? 'text-green-400' : 'text-yellow-400'
            }`} />
            <div>
              <p className="text-sm text-white font-medium">{gw.id}</p>
              <p className="text-xs text-slate-500">{gw.region}</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-xs text-slate-400">{gw.load}</span>
            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
              gw.status === 'healthy' ? 'bg-green-900/50 text-green-400' : 'bg-yellow-900/50 text-yellow-400'
            }`}>
              {gw.status}
            </span>
            <button className="text-slate-600 hover:text-slate-400">
              <MoreVertical className="h-4 w-4" />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
