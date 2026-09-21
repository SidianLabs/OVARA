CREATE DATABASE IF NOT EXISTS ovara_telemetry;

CREATE TABLE IF NOT EXISTS ovara_telemetry.events (
    event_id        String,
    event_type      LowCardinality(String),
    event_version   String,
    timestamp       DateTime64(3, 'UTC'),
    seq             Int64,
    gateway_id      String,
    agent_id        String,
    trace_id        String,
    decision_id     String,
    receipt_id      String,
    approval_id     String,
    continuation_id String,
    payload         String CODEC(ZSTD(3)),
    ingest_time     DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (gateway_id, event_type, timestamp)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS ovara_telemetry.event_hourly_agg (
    hour           DateTime,
    gateway_id     String,
    event_type     LowCardinality(String),
    count          UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, gateway_id, event_type)
TTL hour + INTERVAL 1 YEAR;

CREATE MATERIALIZED VIEW IF NOT EXISTS ovara_telemetry.event_hourly_mv
TO ovara_telemetry.event_hourly_agg AS
SELECT
    toStartOfHour(timestamp) AS hour,
    gateway_id,
    event_type,
    count() AS count
FROM ovara_telemetry.events
GROUP BY hour, gateway_id, event_type;

CREATE TABLE IF NOT EXISTS ovara_telemetry.decision_traces (
    trace_id        String,
    decision_id     String,
    action_type     LowCardinality(String),
    resource        String,
    decision        LowCardinality(String),
    latency_us      UInt32,
    gateway_id      String,
    agent_id        String,
    policy_id       String,
    rule_ids        Array(String),
    trust_score     Float32,
    anomaly_level   LowCardinality(String),
    timestamp       DateTime64(3, 'UTC'),
    ingest_time     DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (gateway_id, decision, timestamp)
TTL timestamp + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS ovara_telemetry.receipt_archive (
    receipt_id      String,
    decision_id     String,
    gateway_id      String,
    agent_id        String,
    action_type     LowCardinality(String),
    resource        String,
    result          String,
    signature       String,
    payload         String CODEC(ZSTD(3)),
    timestamp       DateTime64(3, 'UTC'),
    ingest_time     DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (gateway_id, timestamp)
TTL timestamp + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS ovara_telemetry.trust_scores (
    gateway_id      String,
    agent_id        String,
    score           Float32,
    dimensions      String CODEC(ZSTD(3)),
    degradation_pct Float32,
    drift_detected  UInt8,
    timestamp       DateTime64(3, 'UTC'),
    ingest_time     DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (gateway_id, agent_id, timestamp)
TTL timestamp + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;
