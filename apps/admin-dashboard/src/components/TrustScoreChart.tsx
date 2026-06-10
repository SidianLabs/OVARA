'use client';

export function TrustScoreChart() {
  // In production, this would use Recharts with real data
  return (
    <div className="h-64 flex items-end justify-between gap-2 px-2">
      {[0.85, 0.87, 0.82, 0.90, 0.88, 0.92, 0.89, 0.94, 0.91, 0.93, 0.90, 0.95].map((score, i) => (
        <div key={i} className="flex-1 flex flex-col items-center gap-1">
          <div
            className="w-full bg-ovara-500/80 rounded-t hover:bg-ovara-400 transition-colors"
            style={{ height: `${score * 100}%` }}
          />
          <span className="text-xs text-slate-500">
            {String(i * 2).padStart(2, '0')}:00
          </span>
        </div>
      ))}
    </div>
  );
}
