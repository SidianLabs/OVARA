'use client';

export function RecentDecisions() {
  const decisions = [
    { id: 'dec_001', action: 'shell.execute', resource: 'sudo', decision: 'deny', time: '2s ago' },
    { id: 'dec_002', action: 'git.push', resource: 'main', decision: 'allow', time: '5s ago' },
    { id: 'dec_003', action: 'git.pull', resource: 'feature/*', decision: 'allow', time: '12s ago' },
    { id: 'dec_004', action: 'shell.execute', resource: 'kubectl', decision: 'escalate', time: '18s ago' },
    { id: 'dec_005', action: 'git.fetch', resource: 'origin', decision: 'allow', time: '23s ago' },
  ];

  return (
    <div className="space-y-3">
      {decisions.map((d) => (
        <div key={d.id} className="flex items-center justify-between py-2 border-b border-surface-border last:border-0">
          <div>
            <p className="text-sm text-white font-medium">{d.action}</p>
            <p className="text-xs text-slate-500">{d.resource}</p>
          </div>
          <div className="flex items-center gap-3">
            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
              d.decision === 'allow' ? 'bg-green-900/50 text-green-400' :
              d.decision === 'deny' ? 'bg-red-900/50 text-red-400' :
              'bg-yellow-900/50 text-yellow-400'
            }`}>
              {d.decision}
            </span>
            <span className="text-xs text-slate-600">{d.time}</span>
          </div>
        </div>
      ))}
    </div>
  );
}
