package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/mahyarnemati/siem-lite/internal/detect"
	"github.com/mahyarnemati/siem-lite/internal/event"
)

// ClickHouseConfig configures the ClickHouse store.
type ClickHouseConfig struct {
	DSN               string
	EventTTLDays      int
	DetectionTTLDays  int
	DialTimeout       time.Duration
	SkipSchemaMigrate bool
}

// ClickHouse stores events and detections in MergeTree tables with TTLs.
type ClickHouse struct {
	conn driver.Conn
}

// OpenClickHouse connects, verifies the server is reachable and applies the
// schema unless SkipSchemaMigrate is set.
func OpenClickHouse(ctx context.Context, cfg ClickHouseConfig) (*ClickHouse, error) {
	opts, err := clickhouse.ParseDSN(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("clickhouse dsn: %w", err)
	}
	if cfg.DialTimeout > 0 {
		opts.DialTimeout = cfg.DialTimeout
	}
	opts.Compression = &clickhouse.Compression{Method: clickhouse.CompressionLZ4}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}
	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}
	c := &ClickHouse{conn: conn}
	if !cfg.SkipSchemaMigrate {
		if err := c.Migrate(ctx, cfg.EventTTLDays, cfg.DetectionTTLDays); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return c, nil
}

// Schema returns the DDL statements for the given retention.
func Schema(eventTTLDays, detectionTTLDays int) []string {
	if eventTTLDays <= 0 {
		eventTTLDays = 30
	}
	if detectionTTLDays <= 0 {
		detectionTTLDays = 365
	}
	return []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS events (
    timestamp    DateTime64(3, 'UTC'),
    received     DateTime64(3, 'UTC'),
    source       LowCardinality(String),
    host         LowCardinality(String),
    category     LowCardinality(String),
    action       LowCardinality(String),
    outcome      LowCardinality(String),
    user         String,
    src_ip       String,
    src_port     UInt16,
    country      LowCardinality(String),
    city         String,
    lat          Float64,
    lon          Float64,
    device       LowCardinality(String),
    user_agent   String,
    http_method  LowCardinality(String),
    http_path    String,
    http_status  UInt16,
    bytes        UInt64,
    message      String CODEC(ZSTD(3)),
    fields       Map(String, String),
    INDEX idx_src_ip src_ip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_user user TYPE bloom_filter(0.01) GRANULARITY 4
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (category, source, timestamp)
TTL toDateTime(timestamp) + INTERVAL %d DAY DELETE
SETTINGS ttl_only_drop_parts = 1`, eventTTLDays),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS detections (
    detected_at  DateTime64(3, 'UTC'),
    rule_id      LowCardinality(String),
    title        String,
    severity     LowCardinality(String),
    tags         Array(LowCardinality(String)),
    group_key    String,
    count        UInt32,
    first_seen   DateTime64(3, 'UTC'),
    last_seen    DateTime64(3, 'UTC'),
    summary      String,
    values       Array(String),
    src_ip       String,
    user         String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(detected_at)
ORDER BY (rule_id, detected_at)
TTL toDateTime(detected_at) + INTERVAL %d DAY DELETE`, detectionTTLDays),
	}
}

// Migrate creates tables if missing and reconciles the TTL on existing ones.
func (c *ClickHouse) Migrate(ctx context.Context, eventTTLDays, detectionTTLDays int) error {
	for _, stmt := range Schema(eventTTLDays, detectionTTLDays) {
		if err := c.conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("clickhouse migrate: %w", err)
		}
	}
	if eventTTLDays > 0 {
		if err := c.conn.Exec(ctx, fmt.Sprintf(
			"ALTER TABLE events MODIFY TTL toDateTime(timestamp) + INTERVAL %d DAY DELETE", eventTTLDays)); err != nil {
			return fmt.Errorf("clickhouse ttl: %w", err)
		}
	}
	return nil
}

// InsertEvents implements Store using a single native batch.
func (c *ClickHouse) InsertEvents(ctx context.Context, evs []event.Event) error {
	if len(evs) == 0 {
		return nil
	}
	b, err := c.conn.PrepareBatch(ctx, "INSERT INTO events")
	if err != nil {
		return fmt.Errorf("prepare events batch: %w", err)
	}
	for i := range evs {
		e := &evs[i]
		fields := e.Fields
		if fields == nil {
			fields = map[string]string{}
		}
		if err := b.Append(
			e.Timestamp.UTC(), e.Received.UTC(), e.Source, e.Host, e.Category, e.Action, e.Outcome,
			e.User, e.SrcIP, clampU16(e.SrcPort), e.Country, e.City, e.Lat, e.Lon, e.Device,
			e.UserAgent, e.HTTPMethod, e.HTTPPath, clampU16(e.HTTPStatus), uint64(max(e.Bytes, 0)),
			e.Message, fields,
		); err != nil {
			_ = b.Abort()
			return fmt.Errorf("append event: %w", err)
		}
	}
	if err := b.Send(); err != nil {
		return fmt.Errorf("send events batch: %w", err)
	}
	return nil
}

// InsertDetections implements Store.
func (c *ClickHouse) InsertDetections(ctx context.Context, ds []detect.Detection) error {
	if len(ds) == 0 {
		return nil
	}
	b, err := c.conn.PrepareBatch(ctx, "INSERT INTO detections")
	if err != nil {
		return fmt.Errorf("prepare detections batch: %w", err)
	}
	for _, d := range ds {
		if err := b.Append(
			d.DetectedAt.UTC(), d.RuleID, d.Title, d.Severity, nonNil(d.Tags), d.GroupKey,
			uint32(max(d.Count, 0)), d.FirstSeen.UTC(), d.LastSeen.UTC(), d.Summary, nonNil(d.Values),
			d.SrcIP, d.User,
		); err != nil {
			_ = b.Abort()
			return fmt.Errorf("append detection: %w", err)
		}
	}
	if err := b.Send(); err != nil {
		return fmt.Errorf("send detections batch: %w", err)
	}
	return nil
}

// RecentDetections implements Store.
func (c *ClickHouse) RecentDetections(ctx context.Context, since time.Time, limit int) ([]detect.Detection, error) {
	if limit <= 0 || limit > 10_000 {
		limit = 100
	}
	rows, err := c.conn.Query(ctx, `
SELECT detected_at, rule_id, title, severity, tags, group_key, count, first_seen, last_seen, summary, values, src_ip, user
FROM detections WHERE detected_at >= ? ORDER BY detected_at DESC LIMIT ?`, since.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("query detections: %w", err)
	}
	defer rows.Close()
	var out []detect.Detection
	for rows.Next() {
		var d detect.Detection
		var count uint32
		if err := rows.Scan(&d.DetectedAt, &d.RuleID, &d.Title, &d.Severity, &d.Tags, &d.GroupKey, &count,
			&d.FirstSeen, &d.LastSeen, &d.Summary, &d.Values, &d.SrcIP, &d.User); err != nil {
			return nil, fmt.Errorf("scan detection: %w", err)
		}
		d.Count = int(count)
		out = append(out, d)
	}
	return out, rows.Err()
}

// Ping implements Store.
func (c *ClickHouse) Ping(ctx context.Context) error { return c.conn.Ping(ctx) }

// Close implements Store.
func (c *ClickHouse) Close() error { return c.conn.Close() }

func clampU16(n int) uint16 {
	switch {
	case n < 0:
		return 0
	case n > 65535:
		return 65535
	}
	return uint16(n)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// RedactDSN hides credentials for logging.
func RedactDSN(dsn string) string {
	at := strings.LastIndex(dsn, "@")
	scheme := strings.Index(dsn, "://")
	if at < 0 || scheme < 0 || at < scheme {
		return dsn
	}
	return dsn[:scheme+3] + "***" + dsn[at:]
}
