'use client';

import { Settings, Save } from 'lucide-react';

export default function SettingsPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white">Settings</h1>
        <p className="text-slate-400 mt-1">Configure Ovara control plane settings</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* General Settings */}
        <div className="bg-surface-light rounded-xl border border-surface-border p-6">
          <h2 className="text-lg font-semibold text-white mb-4">General</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-1">Default Policy</label>
              <select className="w-full px-3 py-2 bg-surface border border-surface-border rounded-lg text-sm text-white">
                <option>Default Allow</option>
                <option>Default Deny</option>
                <option>Custom</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-1">Receipt Retention (days)</label>
              <input type="number" defaultValue={90} className="w-full px-3 py-2 bg-surface border border-surface-border rounded-lg text-sm text-white" />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-1">Max Delegation Depth</label>
              <input type="number" defaultValue={5} className="w-full px-3 py-2 bg-surface border border-surface-border rounded-lg text-sm text-white" />
            </div>
          </div>
        </div>

        {/* Security Settings */}
        <div className="bg-surface-light rounded-xl border border-surface-border p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Security</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-1">Enforce Signature Verification</label>
              <select className="w-full px-3 py-2 bg-surface border border-surface-border rounded-lg text-sm text-white">
                <option>Always</option>
                <option>Production only</option>
                <option>Per policy</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-1">Trust Score Threshold</label>
              <input type="number" defaultValue={0.5} step={0.05} min={0} max={1} className="w-full px-3 py-2 bg-surface border border-surface-border rounded-lg text-sm text-white" />
            </div>
            <div className="flex items-center justify-between py-1">
              <span className="text-sm text-slate-400">Audit Log Immutability</span>
              <span className="text-sm text-green-400 font-medium">Enabled</span>
            </div>
          </div>
        </div>

        {/* API Configuration */}
        <div className="bg-surface-light rounded-xl border border-surface-border p-6">
          <h2 className="text-lg font-semibold text-white mb-4">API Configuration</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-1">Gateway API Endpoint</label>
              <input type="text" defaultValue="https://api.ovara.dev/v1" className="w-full px-3 py-2 bg-surface border border-surface-border rounded-lg text-sm text-white" />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-1">API Key</label>
              <input type="password" defaultValue="••••••••••••••••" className="w-full px-3 py-2 bg-surface border border-surface-border rounded-lg text-sm text-white" />
            </div>
          </div>
        </div>

        {/* Notifications */}
        <div className="bg-surface-light rounded-xl border border-surface-border p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Alerting</h2>
          <div className="space-y-3">
            <div className="flex items-center justify-between py-1">
              <span className="text-sm text-slate-400">Escalation notifications</span>
              <span className="text-sm text-green-400 font-medium">Enabled</span>
            </div>
            <div className="flex items-center justify-between py-1">
              <span className="text-sm text-slate-400">Deny alerts</span>
              <span className="text-sm text-green-400 font-medium">Enabled</span>
            </div>
            <div className="flex items-center justify-between py-1">
              <span className="text-sm text-slate-400">Trust degradation alerts</span>
              <span className="text-sm text-green-400 font-medium">Enabled</span>
            </div>
            <div className="flex items-center justify-between py-1">
              <span className="text-sm text-slate-400">Gateway health alerts</span>
              <span className="text-sm text-green-400 font-medium">Enabled</span>
            </div>
          </div>
        </div>
      </div>

      <div className="flex justify-end">
        <button className="flex items-center gap-2 px-6 py-2.5 bg-ovara-600 hover:bg-ovara-500 rounded-lg text-sm text-white font-medium transition-colors">
          <Save className="h-4 w-4" />
          Save Settings
        </button>
      </div>
    </div>
  );
}
