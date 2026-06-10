'use client';

import { Users, Plus, Shield } from 'lucide-react';

export default function OrganizationsPage() {
  const orgs = [
    { domain: 'acme.com', name: 'Acme Corp', members: 12, gateways: 3, trustScore: 0.92, status: 'active' },
    { domain: 'widgetco.io', name: 'WidgetCo', members: 8, gateways: 2, trustScore: 0.87, status: 'active' },
    { domain: 'startup.dev', name: 'Startup Inc', members: 5, gateways: 1, trustScore: 0.75, status: 'probation' },
    { domain: 'enterprise.org', name: 'Enterprise Ltd', members: 45, gateways: 6, trustScore: 0.95, status: 'active' },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Organizations</h1>
          <p className="text-slate-400 mt-1">Manage federated organizations and trust relationships</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-ovara-600 hover:bg-ovara-500 rounded-lg text-sm text-white font-medium transition-colors">
          <Plus className="h-4 w-4" />
          Add Organization
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {orgs.map((org) => (
          <div key={org.domain} className="bg-surface-light rounded-xl border border-surface-border p-5 hover:border-surface-lighter transition-colors">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 rounded-lg bg-ovara-900 flex items-center justify-center">
                  <Shield className="h-5 w-5 text-ovara-400" />
                </div>
                <div>
                  <h3 className="text-white font-semibold">{org.name}</h3>
                  <p className="text-xs text-slate-500">{org.domain}</p>
                </div>
              </div>
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                org.status === 'active' ? 'bg-green-900/50 text-green-400' :
                'bg-yellow-900/50 text-yellow-400'
              }`}>
                {org.status}
              </span>
            </div>

            <div className="grid grid-cols-3 gap-4 mb-4">
              <div className="text-center p-3 bg-surface rounded-lg">
                <div className="text-xl font-bold text-white">{org.members}</div>
                <div className="text-xs text-slate-500">Members</div>
              </div>
              <div className="text-center p-3 bg-surface rounded-lg">
                <div className="text-xl font-bold text-white">{org.gateways}</div>
                <div className="text-xs text-slate-500">Gateways</div>
              </div>
              <div className="text-center p-3 bg-surface rounded-lg">
                <div className="text-xl font-bold text-white">{(org.trustScore * 100).toFixed(0)}%</div>
                <div className="text-xs text-slate-500">Trust</div>
              </div>
            </div>

            <button className="w-full py-2 bg-surface-lighter border border-surface-border rounded-lg text-sm text-slate-300 hover:text-white transition-colors">
              View Details
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
