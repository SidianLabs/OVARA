import { describe, it, expect, beforeEach } from "vitest";
import { AnalyticsEngine } from "../engine";

describe("AnalyticsEngine", () => {
  let engine: AnalyticsEngine;

  const sampleEvents = [
    { decisionId: "d1", decision: "allow" as const, actionType: "shell.execute", resource: "npm install", gatewayId: "gw-1", agentId: "agt-1", trustScore: 0.95, latencyMs: 3, timestamp: new Date().toISOString() },
    { decisionId: "d2", decision: "allow" as const, actionType: "git.push", resource: "main", gatewayId: "gw-1", agentId: "agt-1", trustScore: 0.9, latencyMs: 5, timestamp: new Date().toISOString() },
    { decisionId: "d3", decision: "deny" as const, actionType: "shell.execute", resource: "sudo", gatewayId: "gw-2", agentId: "agt-2", trustScore: 0.15, latencyMs: 2, timestamp: new Date().toISOString() },
    { decisionId: "d4", decision: "deny" as const, actionType: "git.force_push", resource: "main", gatewayId: "gw-2", agentId: "agt-2", trustScore: 0.1, latencyMs: 7, timestamp: new Date().toISOString() },
    { decisionId: "d5", decision: "allow" as const, actionType: "http.request", resource: "api.example.com", gatewayId: "gw-1", agentId: "agt-3", trustScore: 0.8, latencyMs: 4, timestamp: new Date().toISOString() },
  ];

  beforeEach(() => {
    engine = new AnalyticsEngine(1000);
    for (const e of sampleEvents) engine.ingest(e);
  });

  it("computes summary with correct counts", () => {
    const summary = engine.computeSummary(60);
    expect(summary.totalDecisions).toBe(5);
    expect(summary.allowCount).toBe(3);
    expect(summary.denyCount).toBe(2);
    expect(summary.activeGateways).toBe(2);
    expect(summary.activeAgents).toBe(3);
  });

  it("computes correct rates", () => {
    const summary = engine.computeSummary(60);
    expect(summary.allowRate).toBeCloseTo(0.6, 1);
    expect(summary.denyRate).toBeCloseTo(0.4, 1);
  });

  it("computes average latency", () => {
    const summary = engine.computeSummary(60);
    expect(summary.avgLatencyMs).toBeGreaterThan(3);
    expect(summary.avgLatencyMs).toBeLessThan(6);
  });

  it("returns top actions sorted by count", () => {
    const summary = engine.computeSummary(60);
    expect(summary.topActions[0].action).toBe("shell.execute");
    expect(summary.topActions[0].count).toBe(2);
  });

  it("returns top resources sorted by count", () => {
    const summary = engine.computeSummary(60);
    const mainRes = summary.topResources.find((r) => r.resource.startsWith("main"));
    expect(mainRes?.count).toBe(2);
  });

  it("generates hourly trends", () => {
    const trends = engine.computeTrends(24);
    expect(trends.hourly.length).toBeGreaterThan(0);
    expect(trends.daily.length).toBe(1);
  });

  it("ingests batch events", () => {
    const engine2 = new AnalyticsEngine(500);
    engine2.ingestBatch([sampleEvents[0], sampleEvents[1]]);
    expect(engine2.stats().totalEvents).toBe(2);
  });

  it("caps at max events", () => {
    const small = new AnalyticsEngine(3);
    for (const e of sampleEvents) small.ingest(e);
    expect(small.stats().totalEvents).toBe(3);
  });

  it("clear removes all events", () => {
    engine.clear();
    expect(engine.stats().totalEvents).toBe(0);
    const summary = engine.computeSummary(60);
    expect(summary.totalDecisions).toBe(0);
  });

  it("handles empty engine gracefully", () => {
    const empty = new AnalyticsEngine();
    const summary = empty.computeSummary(60);
    expect(summary.totalDecisions).toBe(0);
    expect(summary.allowRate).toBe(0);
    expect(summary.avgLatencyMs).toBe(0);
  });

  it("returns stats metadata", () => {
    const stats = engine.stats();
    expect(stats.totalEvents).toBe(5);
    expect(stats.oldestEvent).toBeTruthy();
    expect(stats.newestEvent).toBeTruthy();
  });

  it("honors time window in summary", () => {
    const oldEvent = {
      decisionId: "d-old",
      decision: "allow" as const,
      actionType: "test",
      resource: "test",
      gatewayId: "gw-old",
      trustScore: 0.5,
      latencyMs: 10,
      timestamp: new Date(Date.now() - 120 * 60 * 1000).toISOString(),
    };
    engine.ingest(oldEvent);

    const summary1m = engine.computeSummary(1);
    expect(summary1m.totalDecisions).toBe(5);

    const summary3h = engine.computeSummary(180);
    expect(summary3h.totalDecisions).toBe(6);
  });
});
