'use client';

import clsx from 'clsx';
import { TrendingUp, TrendingDown } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string;
  change: string;
  trend: 'up' | 'down';
  icon: React.ReactNode;
}

export function MetricCard({ title, value, change, trend, icon }: MetricCardProps) {
  return (
    <div className="bg-surface-light rounded-xl border border-surface-border p-6">
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-medium text-slate-400">{title}</span>
        <span className="text-slate-500">{icon}</span>
      </div>
      <div className="text-2xl font-bold text-white mb-1">{value}</div>
      <div className={clsx(
        'flex items-center gap-1 text-sm',
        trend === 'up' ? 'text-green-400' : 'text-red-400'
      )}>
        {trend === 'up' ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
        {change}
      </div>
    </div>
  );
}
