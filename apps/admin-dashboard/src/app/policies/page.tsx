'use client';

import { Plus, Edit3, Trash2, Play, Copy } from 'lucide-react';

export default function PoliciesPage() {
  const policies = [
    { id: 'pol_default', name: 'Default Allow', rules: 3, status: 'active', lastModified: '2h ago' },
    { id: 'pol_prod_lockdown', name: 'Production Lockdown', rules: 8, status: 'active', lastModified: '1d ago' },
    { id: 'pol_ci_pipeline', name: 'CI Pipeline Access', rules: 5, status: 'active', lastModified: '3d ago' },
    { id: 'pol_experimental', name: 'Experimental Features', rules: 2, status: 'draft', lastModified: '5d ago' },
    { id: 'pol_deprecated', name: 'Deprecated: V1 Rules', rules: 12, status: 'archived', lastModified: '30d ago' },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Policies</h1>
          <p className="text-slate-400 mt-1">Manage policy rules and evaluation configuration</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-ovara-600 hover:bg-ovara-500 rounded-lg text-sm text-white font-medium transition-colors">
          <Plus className="h-4 w-4" />
          Create Policy
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {policies.map((pol) => (
          <div key={pol.id} className="bg-surface-light rounded-xl border border-surface-border p-5 hover:border-surface-lighter transition-colors">
            <div className="flex items-start justify-between mb-3">
              <div>
                <h3 className="text-white font-semibold">{pol.name}</h3>
                <p className="text-xs text-slate-500 font-mono">{pol.id}</p>
              </div>
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                pol.status === 'active' ? 'bg-green-900/50 text-green-400' :
                pol.status === 'draft' ? 'bg-blue-900/50 text-blue-400' :
                'bg-slate-800 text-slate-400'
              }`}>
                {pol.status}
              </span>
            </div>
            <div className="text-sm text-slate-400 mb-4">
              {pol.rules} rules · Modified {pol.lastModified}
            </div>
            <div className="flex items-center gap-2">
              <button className="flex items-center gap-1 px-2.5 py-1.5 bg-surface-lighter rounded-lg text-xs text-slate-300 hover:text-white transition-colors">
                <Edit3 className="h-3 w-3" /> Edit
              </button>
              <button className="flex items-center gap-1 px-2.5 py-1.5 bg-surface-lighter rounded-lg text-xs text-slate-300 hover:text-white transition-colors">
                <Play className="h-3 w-3" /> Simulate
              </button>
              <button className="flex items-center gap-1 px-2.5 py-1.5 bg-surface-lighter rounded-lg text-xs text-slate-300 hover:text-white transition-colors">
                <Copy className="h-3 w-3" /> Clone
              </button>
              <button className="flex items-center gap-1 px-2.5 py-1.5 bg-surface-lighter rounded-lg text-xs text-red-400 hover:text-red-300 transition-colors ml-auto">
                <Trash2 className="h-3 w-3" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
