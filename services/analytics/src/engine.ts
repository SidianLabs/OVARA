import { DecisionEvent, MetricsSummary, TrendReport, TimeSeriesPoint } from "./types";

export class AnalyticsEngine {
  private events: DecisionEvent[] = [];
  private maxEvents: number;

  constructor(maxEvents = 100000) {
    this.maxEvents = maxEvents;
  }

  ingest(event: DecisionEvent): void {
    this.events.push(event);
    if (this.events.length > this.maxEvents) {
      this.events = this.events.slice(-this.maxEvents);
    }
  }

  ingestBatch(events: DecisionEvent[]): void {
    for (const e of events) this.ingest(e);
  }

  computeSummary(windowMinutes = 60): MetricsSummary {
    const cutoff = Date.now() - windowMinutes * 60 * 1000;
    const recent = this.events.filter(
      (e) => new Date(e.timestamp).getTime() >= cutoff
    );

    const total = recent.length;
    const allowCount = recent.filter((e) => e.decision === "allow").length;
    const denyCount = recent.filter((e) => e.decision === "deny").length;
    const pendingCount = total - allowCount - denyCount;

    const avgLatencyMs =
      total > 0
        ? recent.reduce((sum, e) => sum + e.latencyMs, 0) / total
        : 0;

    const avgTrustScore =
      total > 0
        ? recent.reduce((sum, e) => sum + e.trustScore, 0) / total
        : 0;

    const gatewaySet = new Set(recent.map((e) => e.gatewayId));
    const agentSet = new Set(
      recent.filter((e) => e.agentId).map((e) => e.agentId!)
    );

    const actionCounts = new Map<string, number>();
    const resourceCounts = new Map<string, number>();
    for (const e of recent) {
      actionCounts.set(e.actionType, (actionCounts.get(e.actionType) || 0) + 1);
      resourceCounts.set(
        e.resource.substring(0, 40),
        (resourceCounts.get(e.resource.substring(0, 40)) || 0) + 1
      );
    }

    const topActions = [...actionCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([action, count]) => ({ action, count }));

    const topResources = [...resourceCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([resource, count]) => ({ resource, count }));

    return {
      totalDecisions: total,
      allowCount,
      denyCount,
      pendingCount,
      allowRate: total > 0 ? allowCount / total : 0,
      denyRate: total > 0 ? denyCount / total : 0,
      avgLatencyMs: Math.round(avgLatencyMs * 100) / 100,
      avgTrustScore: Math.round(avgTrustScore * 1000) / 1000,
      activeGateways: gatewaySet.size,
      activeAgents: agentSet.size,
      decisionsPerMinute:
        windowMinutes > 0 ? Math.round(total / windowMinutes) : total,
      topActions,
      topResources,
    };
  }

  computeTrends(hours = 24): TrendReport {
    const cutoff = Date.now() - hours * 3600 * 1000;
    const recent = this.events.filter(
      (e) => new Date(e.timestamp).getTime() >= cutoff
    );

    const hourlyMap = new Map<string, TimeSeriesPoint>();
    const dailyMap = new Map<string, TimeSeriesPoint>();

    for (const e of recent) {
      const d = new Date(e.timestamp);
      const hourKey = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(d.getUTCDate()).padStart(2, "0")}T${String(d.getUTCHours()).padStart(2, "0")}:00`;
      const dayKey = hourKey.substring(0, 10);

      this.upsertPoint(hourlyMap, hourKey, e.decision);
      this.upsertPoint(dailyMap, dayKey, e.decision);
    }

    const hourly = [...hourlyMap.values()].sort(
      (a, b) => a.timestamp.localeCompare(b.timestamp)
    );
    const daily = [...dailyMap.values()].sort(
      (a, b) => a.timestamp.localeCompare(b.timestamp)
    );

    return { hourly, daily };
  }

  private upsertPoint(
    map: Map<string, TimeSeriesPoint>,
    key: string,
    decision: string
  ): void {
    const existing = map.get(key);
    if (existing) {
      existing.count++;
      if (decision === "allow") existing.allowCount++;
      if (decision === "deny") existing.denyCount++;
    } else {
      map.set(key, {
        timestamp: key,
        count: 1,
        allowCount: decision === "allow" ? 1 : 0,
        denyCount: decision === "deny" ? 1 : 0,
      });
    }
  }

  stats(): { totalEvents: number; oldestEvent: string | null; newestEvent: string | null } {
    return {
      totalEvents: this.events.length,
      oldestEvent: this.events[0]?.timestamp ?? null,
      newestEvent: this.events[this.events.length - 1]?.timestamp ?? null,
    };
  }

  clear(): void {
    this.events = [];
  }
}
