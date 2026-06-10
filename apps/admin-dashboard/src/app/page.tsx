'use client';

import { Activity, Shield, FileText, Layers, Clock, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import { MetricCard } from '@/components/MetricCard';
import { TrustScoreChart } from '@/components/TrustScoreChart';
import { RecentDecisions } from '@/components/RecentDecisions';
import { GatewaysList } from '@/components/GatewaysList';

export default function DashboardPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white">Dashboard Overview</h1>
        <p className="text-slate-400 mt-1">Ovara Runtime Trust Infrastructure</p>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Decisions/sec"
          value="1,247"
          change="+12.3%"
          trend="up"
          icon={<Activity className="h-5 w-5" />}
        />
        <MetricCard
          title="Avg Latency"
          value="12.4ms"
          change="-3.2%"
          trend="down"
          icon={<Clock className="h-5 w-5" />}
        />
        <MetricCard
          title="Error Rate"
          value="0.03%"
          change="-0.01%"
          trend="down"
          icon={<AlertTriangle className="h-5 w-5" />}
        />
        <MetricCard
          title="Active Gateways"
          value="8"
          change="+2"
          trend="up"
          icon={<Shield className="h-5 w-5" />}
        />
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-surface-light rounded-xl border border-surface-border p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Trust Scores Over Time</h2>
          <TrustScoreChart />
        </div>
        <div className="bg-surface-light rounded-xl border border-surface-border p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Decision Outcomes</h2>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span className="text-slate-300">Allowed</span>
              </div>
              <span className="text-white font-mono">847</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <XCircle className="h-4 w-4 text-red-500" />
                <span className="text-slate-300">Denied</span>
              </div>
              <span className="text-white font-mono">312</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                <span className="text-slate-300">Escalated</span>
              </div>
              <span className="text-white font-mono">88</span>
            </div>
          </div>
        </div>
      </div>

      {/* Gateways & Recent Decisions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-surface-light rounded-xl border border-surface-border p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Gateways</h2>
          <GatewaysList />
        </div>
        <div className="bg-surface-light rounded-xl border border-surface-border p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Recent Decisions</h2>
          <RecentDecisions />
        </div>
      </div>
    </div>
  );
}
