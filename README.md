# siem-lite

A small, fast SIEM in Go: ingests syslog, nginx and JSON logs, runs Sigma-style YAML detections over sliding windows, stores events in ClickHouse and alerts to webhooks and Slack.

[![CI](https://github.com/MahyarNemati/siem-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/MahyarNemati/siem-lite/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.24-00ADD8.svg)](go.mod)

## Features

- **Ingest**: syslog over UDP and TCP (RFC 5424 and RFC 3164, RFC 6587 octet counting or newline framing), JSON over HTTP (object, array or NDJSON), and `tail -F` style file following that survives rotation and truncation.
- **Parsers**: sshd authentication messages, nginx combined access logs, and generic JSON with ECS-style field aliases. Everything maps to one normalized event schema.
- **Detection engine**: YAML rules with a Sigma-inspired selection syntax (`field|modifier: value`) and four rule types:
  - `threshold`: N matching events per group in a window (brute force by IP or by user, sensitive path probing)
  - `distinct`: N distinct values of a field per group (password spray, 4xx content discovery bursts)
  - `impossible_travel`: consecutive logins implying a ground speed above a limit
  - `new_value`: a value an established account has not used recently (new country, new device)
- **State**: bounded in-memory sliding windows per rule with GC, LRU-style eviction under pressure and JSON snapshots on an interval and at shutdown, so a restart does not reset brute force counters or login baselines.
- **Storage**: ClickHouse via `clickhouse-go` v2 native batches into partitioned MergeTree tables with TTL retention. A bounded in-memory store backs tests and local runs.
- **Alerting**: webhook (HMAC-SHA256 signed) and Slack Block Kit sinks, per rule and group suppression windows, retry with backoff on 429 and 5xx, a non-blocking queue that drains on shutdown.
- **Geo**: MaxMind GeoLite2 City or a CIDR CSV behind one `Locator` interface. The demo ships a CSV that maps documentation IP ranges to cities.
- **Operations**: Prometheus metrics, health and readiness probes, structured JSON logs, env-only configuration with validation, provisioned Grafana dashboard and a log generator that replays real attack patterns.

## Architecture

```mermaid
flowchart LR
    subgraph Sources
        U[syslog UDP]
        T[syslog TCP]
        H[HTTP /v1/ingest]
        F[tailed files]
    end
    U -- drop when full --> Q
    T -- backpressure --> Q
    H -- backpressure --> Q
    F -- backpressure --> Q
    Q[sharded queues<br/>by sender] --> W[workers<br/>parse, enrich geo]
    W --> E[detection engine<br/>rules + sliding windows]
    E -- snapshot --> S[(state.json)]
    W --> B[batcher]
    E --> B
    B --> CH[(ClickHouse<br/>events, detections)]
    E --> D[alert dispatcher<br/>dedupe, retry]
    D --> WH[webhook]
    D --> SL[Slack]
    CH --> G[Grafana]
```

Records are sharded to workers by transport and sender, so every line from one TCP connection, HTTP request or file is processed in order. Stateful rules such as `new_value` depend on that ordering. Parsing and enrichment run in parallel across shards; each rule guards its own window state with a mutex.

## Quickstart

With Docker:

```bash
cp .env.example .env        # set CLICKHOUSE_PASSWORD and GRAFANA_ADMIN_PASSWORD
docker compose up -d --build
```

This starts ClickHouse, siem-lite, Grafana (http://localhost:3000, dashboard "siem-lite overview") and `loggen`, which streams benign traffic plus an attack scenario every 20 seconds.

```bash
curl -s 'localhost:8080/v1/detections?since=15m' | jq '.detections[] | {rule_id, group_key, summary}'
```

Without Docker, using the in-memory store:

```bash
make build
SIEM_GEO_CSV=deploy/geo/demo-geo.csv SIEM_LOG_FORMAT=text ./bin/siem-lite &
./bin/loggen -scenario all -once
curl -s 'localhost:8080/v1/detections?since=72h'
```

Ship real logs:

```bash
# rsyslog: forward auth logs over TCP with octet counting
echo 'auth,authpriv.* @@siem.internal:5514;RSYSLOG_SyslogProtocol23Format' > /etc/rsyslog.d/60-siem.conf

# or tail files directly
SIEM_TAIL_FILES=/var/log/auth.log,/var/log/nginx/access.log:nginx ./bin/siem-lite
```

## Configuration

All configuration is read from the environment and validated at startup; every invalid value is reported at once.

| Variable | Default | Description |
| --- | --- | --- |
| `SIEM_HTTP_ADDR` | `:8080` | API, ingest and metrics listener |
| `SIEM_SYSLOG_UDP_ADDR` | `:5514` | Syslog UDP listener, `off` to disable |
| `SIEM_SYSLOG_TCP_ADDR` | `:5514` | Syslog TCP listener, `off` to disable |
| `SIEM_TAIL_FILES` | | Comma separated `path[:format]`, format is `syslog`, `nginx` or `json` |
| `SIEM_INGEST_TOKEN` | | Bearer token required on `POST /v1/ingest` when set |
| `SIEM_MAX_BODY_BYTES` | `8388608` | Maximum HTTP ingest body |
| `SIEM_RULES_DIR` | `rules` | Directory of `*.yml` rule files |
| `SIEM_SNAPSHOT_PATH` | | Detector state file; empty disables snapshots |
| `SIEM_SNAPSHOT_INTERVAL` | `1m` | Snapshot period |
| `SIEM_MAX_KEYS_PER_RULE` | `100000` | Tracked groups per rule before eviction |
| `SIEM_CLICKHOUSE_DSN` | | `clickhouse://user:pass@host:9000/db`; empty uses the in-memory store |
| `SIEM_EVENT_TTL_DAYS` | `30` | Event retention |
| `SIEM_DETECTION_TTL_DAYS` | `365` | Detection retention |
| `SIEM_GEOIP_DB` | | Path to a GeoLite2 City `.mmdb` |
| `SIEM_GEO_CSV` | | Path to a `cidr,country,city,lat,lon` CSV |
| `SIEM_WORKERS` | `4` | Worker shards |
| `SIEM_QUEUE_SIZE` | `50000` | Total queued records across shards |
| `SIEM_BATCH_SIZE` | `5000` | Events per ClickHouse insert |
| `SIEM_FLUSH_INTERVAL` | `1s` | Maximum time an event waits before insert |
| `SIEM_WEBHOOK_URL` / `SIEM_WEBHOOK_SECRET` | | Generic webhook sink and its HMAC secret |
| `SIEM_SLACK_WEBHOOK_URL` | | Slack incoming webhook |
| `SIEM_ALERT_SUPPRESS` | `15m` | Suppression window for rules without `suppress` |
| `SIEM_ALERT_RETRIES` | `3` | Retries for 429 and 5xx responses |
| `SIEM_LOG_LEVEL` / `SIEM_LOG_FORMAT` | `info` / `json` | Logging |
| `SIEM_SHUTDOWN_TIMEOUT` | `15s` | Graceful shutdown budget |

## API

| Method and path | Description |
| --- | --- |
| `POST /v1/ingest` | JSON object, array or NDJSON. `?format=nginx` or `?format=syslog` for raw lines. Returns `202 {"accepted": n}` |
| `GET /v1/detections?since=1h&limit=100` | Recent detections, newest first |
| `GET /v1/rules` | Active rule IDs and tracked group counts |
| `GET /v1/stats` | Detector state sizes and alert counters |
| `GET /healthz`, `GET /readyz` | Liveness, and readiness including a store ping |
| `GET /metrics` | Prometheus metrics (`siem_records_received_total`, `siem_detections_total`, `siem_store_flush_seconds`, ...) |

`siem-lite validate-rules [dir]` checks a rule directory and exits non-zero on any error, which makes it easy to gate rule changes in CI.

### Writing rules

```yaml
id: auth-password-spray
title: Password spray
severity: high               # low | medium | high | critical
type: distinct
tags: [attack.credential_access, attack.t1110.003]
selection:                   # all keys must match; lists are any-of
  category: authentication
  outcome: failure
filter:                      # optional, same syntax, excludes matches
  src_ip|startswith: ["10.", "192.168."]
group_by: [src_ip]
field: user
threshold: 5
window: 10m
suppress: 1h
```

Modifiers: `contains`, `startswith`, `endswith`, `re`, `gt`, `gte`, `lt`, `lte`, `exists`, and `not` (combinable, e.g. `user|startswith|not`). String comparisons are case insensitive except `re`. Unknown YAML keys are rejected, so a typo in a threshold fails loudly instead of silently disabling a rule.

Shipped rules live in [`rules/`](rules): brute force per IP and per user, password spray, impossible travel, new country, new device, 4xx scan bursts and sensitive path probes. Each is mapped to MITRE ATT&CK tags.

## Testing

```bash
make test               # unit tests
make test-race          # with the race detector
make lint               # golangci-lint v2
make test-integration   # against a real ClickHouse (SIEM_TEST_CLICKHOUSE_DSN)
make bench
```

- Parsers are table tested against real sshd, nginx, RFC 5424 (including structured data escaping) and RFC 3164 lines, including year rollover.
- Every shipped rule has positive and negative tests driven by a fake clock: window expiry, out of order delivery, baseline learning and aging, and snapshot round trips.
- `internal/sim` feeds 2,000 benign events through the full pipeline and asserts zero detections, then asserts that each attack scenario triggers exactly the rule it was written for. `loggen` uses the same scenarios, so the demo and the tests cannot drift apart.
- Ingest tests run real UDP and TCP listeners, HTTP auth and size limits, and file rotation and truncation.
- The ClickHouse integration test sits behind the `integration` build tag and skips without a DSN. CI runs it against a ClickHouse service container. It was also run locally against ClickHouse 26.11.

### Benchmarks

Measured with `go test -bench . -benchmem -count 3` on a 2 vCPU Intel Xeon 2.8 GHz VM, Go 1.24.7, while the machine was shared with other builds (load average around 20). Treat them as upper bounds, not tuned figures.

| Benchmark | ns/op (3 runs) | B/op | allocs/op |
| --- | --- | --- | --- |
| `ProcessSSHD` (parse syslog + sshd, enrich, all 8 rules) | 20,458 to 25,253 | 1,028 | 6 |
| `ProcessNginx` (parse nginx, enrich, all 8 rules) | 21,498 to 32,199 | 727 | 8 |
| `EngineAuthFailures` (rules only, high fire rate) | 9,141 to 13,223 | 529 | 2 |

## Design decisions and trade-offs

- **Streaming detection instead of scheduled queries.** Rules run on the ingest path against in-memory windows, so a brute force alert fires on the tenth failure, not at the next query interval. The cost is that rules only see events after they are deployed; historical hunting belongs in ClickHouse SQL.
- **Event time, not arrival time.** Windows use the event timestamp and tolerate out of order delivery within a window, which matters for batched shippers. The clock is injected so every rule is tested deterministically.
- **Per-sender ordering.** Sharding queues by sender keeps `new_value` and `impossible_travel` correct without a global lock. A single very busy relay lands on one shard; run more relays or more instances behind a hash-by-source balancer if that becomes a bottleneck.
- **Bounded memory.** Every detector caps tracked groups, GCs idle state and evicts the least recently active group under pressure. The `new_value` baseline keeps at most 64 values per account.
- **UDP drops, TCP pushes back.** UDP senders cannot be slowed down, so a full queue drops and counts. TCP, HTTP and file inputs block, which applies backpressure to the sender instead of losing data.
- **Snapshots, not a WAL.** State is snapshotted every minute and at shutdown. A crash can lose up to one interval of window state, which at worst delays a threshold alert; it never loses stored events.
- **ClickHouse layout.** Events are partitioned by day and ordered by `(category, source, timestamp)` with bloom filter skip indexes on `src_ip` and `user`. `ttl_only_drop_parts` makes retention drop whole partitions instead of rewriting parts.
- **Dedupe at the alert layer.** Every detection is stored for analytics; only alerts are suppressed per rule and group key, so Slack stays quiet during a long attack while the dashboard still shows its full shape.

## Roadmap

- Sigma rule import (only the subset above is supported natively today)
- Correlation rules that chain detections (spray followed by a success from the same IP)
- TLS for syslog (RFC 5425) and mutual TLS on the HTTP ingest
- A write-ahead log for detector state instead of periodic snapshots
- Horizontal scaling with a shared state backend; today one instance owns all window state
- Grafana alerting rules and a detections explorer with drill-down links

## Project structure

```
cmd/siem-lite      server entrypoint and validate-rules subcommand
cmd/loggen         traffic and attack generator
internal/event     normalized event schema
internal/parser    syslog 5424/3164, sshd, nginx, JSON
internal/ingest    UDP, TCP, HTTP and file inputs
internal/detect    rule loading, matchers, detectors, snapshots
internal/pipeline  sharded workers, enrichment, batching
internal/store     ClickHouse and in-memory stores
internal/alert     dispatcher, dedupe, webhook and Slack sinks
internal/geo       MaxMind and CIDR locators, distance math
internal/sim       benign traffic and attack scenarios
internal/api       HTTP routes
internal/config    env configuration
rules/             shipped detection rules
deploy/            Grafana provisioning, dashboards and demo geo data
```

## License

[MIT](LICENSE)
