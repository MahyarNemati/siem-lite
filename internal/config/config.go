// Package config loads and validates runtime configuration from the
// environment.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/parser"
)

// TailFile is one file to follow and the format of its lines.
type TailFile struct {
	Path   string
	Format parser.Format
}

// Config is the full runtime configuration.
type Config struct {
	HTTPAddr      string
	SyslogUDPAddr string
	SyslogTCPAddr string
	TailFiles     []TailFile
	IngestToken   string
	MaxBodyBytes  int64

	RulesDir         string
	SnapshotPath     string
	SnapshotInterval time.Duration
	MaxKeysPerRule   int

	ClickHouseDSN    string
	EventTTLDays     int
	DetectionTTLDays int

	GeoIPDB  string
	GeoCSV   string
	Workers  int
	Queue    int
	Batch    int
	FlushInt time.Duration

	WebhookURL      string
	WebhookSecret   string
	SlackWebhookURL string
	DefaultSuppress time.Duration
	AlertRetries    int
	LogLevel        slog.Level
	LogFormat       string
	ShutdownTimeout time.Duration
}

// Load reads configuration using getenv (os.Getenv in production).
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	l := loader{get: getenv}
	c := Config{
		HTTPAddr:         l.str("SIEM_HTTP_ADDR", ":8080"),
		SyslogUDPAddr:    l.str("SIEM_SYSLOG_UDP_ADDR", ":5514"),
		SyslogTCPAddr:    l.str("SIEM_SYSLOG_TCP_ADDR", ":5514"),
		IngestToken:      l.str("SIEM_INGEST_TOKEN", ""),
		MaxBodyBytes:     int64(l.int("SIEM_MAX_BODY_BYTES", 8<<20, 1024, 256<<20)),
		RulesDir:         l.str("SIEM_RULES_DIR", "rules"),
		SnapshotPath:     l.str("SIEM_SNAPSHOT_PATH", ""),
		SnapshotInterval: l.dur("SIEM_SNAPSHOT_INTERVAL", time.Minute),
		MaxKeysPerRule:   l.int("SIEM_MAX_KEYS_PER_RULE", 100_000, 100, 10_000_000),
		ClickHouseDSN:    l.str("SIEM_CLICKHOUSE_DSN", ""),
		EventTTLDays:     l.int("SIEM_EVENT_TTL_DAYS", 30, 1, 3650),
		DetectionTTLDays: l.int("SIEM_DETECTION_TTL_DAYS", 365, 1, 3650),
		GeoIPDB:          l.str("SIEM_GEOIP_DB", ""),
		GeoCSV:           l.str("SIEM_GEO_CSV", ""),
		Workers:          l.int("SIEM_WORKERS", 4, 1, 256),
		Queue:            l.int("SIEM_QUEUE_SIZE", 50_000, 100, 10_000_000),
		Batch:            l.int("SIEM_BATCH_SIZE", 5_000, 1, 1_000_000),
		FlushInt:         l.dur("SIEM_FLUSH_INTERVAL", time.Second),
		WebhookURL:       l.str("SIEM_WEBHOOK_URL", ""),
		WebhookSecret:    l.str("SIEM_WEBHOOK_SECRET", ""),
		SlackWebhookURL:  l.str("SIEM_SLACK_WEBHOOK_URL", ""),
		DefaultSuppress:  l.dur("SIEM_ALERT_SUPPRESS", 15*time.Minute),
		AlertRetries:     l.int("SIEM_ALERT_RETRIES", 3, 0, 10),
		LogFormat:        strings.ToLower(l.str("SIEM_LOG_FORMAT", "json")),
		ShutdownTimeout:  l.dur("SIEM_SHUTDOWN_TIMEOUT", 15*time.Second),
	}
	if err := c.LogLevel.UnmarshalText([]byte(l.str("SIEM_LOG_LEVEL", "info"))); err != nil {
		l.errs = append(l.errs, fmt.Errorf("SIEM_LOG_LEVEL: %w", err))
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		l.errs = append(l.errs, fmt.Errorf("SIEM_LOG_FORMAT: must be json or text, got %q", c.LogFormat))
	}
	c.TailFiles = l.tails("SIEM_TAIL_FILES")
	for _, k := range []string{"SIEM_WEBHOOK_URL", "SIEM_SLACK_WEBHOOK_URL"} {
		if v := getenv(k); v != "" {
			if u, err := url.Parse(v); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				l.errs = append(l.errs, fmt.Errorf("%s: must be an http(s) URL", k))
			}
		}
	}
	if c.ClickHouseDSN != "" && !strings.HasPrefix(c.ClickHouseDSN, "clickhouse://") {
		l.errs = append(l.errs, errors.New("SIEM_CLICKHOUSE_DSN: must start with clickhouse://"))
	}
	if c.HTTPAddr == "" {
		l.errs = append(l.errs, errors.New("SIEM_HTTP_ADDR: required"))
	}
	return c, errors.Join(l.errs...)
}

type loader struct {
	get  func(string) string
	errs []error
}

func (l *loader) str(key, def string) string {
	if v := strings.TrimSpace(l.get(key)); v != "" {
		return v
	}
	return def
}

func (l *loader) int(key string, def, lo, hi int) int {
	v := strings.TrimSpace(l.get(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		l.errs = append(l.errs, fmt.Errorf("%s: must be an integer in [%d, %d], got %q", key, lo, hi, v))
		return def
	}
	return n
}

func (l *loader) dur(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(l.get(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		l.errs = append(l.errs, fmt.Errorf("%s: must be a positive duration, got %q", key, v))
		return def
	}
	return d
}

// tails parses "path[:format],path[:format]". Format defaults to syslog.
func (l *loader) tails(key string) []TailFile {
	v := strings.TrimSpace(l.get(key))
	if v == "" {
		return nil
	}
	var out []TailFile
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		path, format := item, "syslog"
		if i := strings.LastIndexByte(item, ':'); i > 0 {
			path, format = item[:i], item[i+1:]
		}
		f, err := parser.ParseFormat(format)
		if err != nil {
			l.errs = append(l.errs, fmt.Errorf("%s: %w", key, err))
			continue
		}
		out = append(out, TailFile{Path: path, Format: f})
	}
	return out
}
