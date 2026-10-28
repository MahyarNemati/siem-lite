package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/parser"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPAddr != ":8080" || c.Workers != 4 || c.FlushInt != time.Second || c.LogLevel != slog.LevelInfo || c.EventTTLDays != 30 {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestOverridesAndTails(t *testing.T) {
	c, err := Load(env(map[string]string{
		"SIEM_TAIL_FILES":     "/var/log/auth.log, /var/log/nginx/access.log:nginx,/tmp/app.json:json",
		"SIEM_WORKERS":        "8",
		"SIEM_LOG_LEVEL":      "debug",
		"SIEM_CLICKHOUSE_DSN": "clickhouse://u:p@ch:9000/siem",
		"SIEM_WEBHOOK_URL":    "https://hooks.example.com/x",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := []TailFile{{"/var/log/auth.log", parser.FormatSyslog}, {"/var/log/nginx/access.log", parser.FormatNginx}, {"/tmp/app.json", parser.FormatJSON}}
	if len(c.TailFiles) != 3 {
		t.Fatalf("tails %+v", c.TailFiles)
	}
	for i := range want {
		if c.TailFiles[i] != want[i] {
			t.Fatalf("tail %d: %+v", i, c.TailFiles[i])
		}
	}
	if c.Workers != 8 || c.LogLevel != slog.LevelDebug {
		t.Fatalf("overrides: %+v", c)
	}
}

func TestValidationCollectsAllErrors(t *testing.T) {
	_, err := Load(env(map[string]string{
		"SIEM_WORKERS":           "0",
		"SIEM_FLUSH_INTERVAL":    "soon",
		"SIEM_LOG_LEVEL":         "loud",
		"SIEM_LOG_FORMAT":        "xml",
		"SIEM_TAIL_FILES":        "/x:yaml",
		"SIEM_WEBHOOK_URL":       "ftp://x",
		"SIEM_SLACK_WEBHOOK_URL": "not a url",
		"SIEM_CLICKHOUSE_DSN":    "tcp://ch:9000",
	}))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, key := range []string{"SIEM_WORKERS", "SIEM_FLUSH_INTERVAL", "SIEM_LOG_LEVEL", "SIEM_LOG_FORMAT", "SIEM_TAIL_FILES", "SIEM_WEBHOOK_URL", "SIEM_SLACK_WEBHOOK_URL", "SIEM_CLICKHOUSE_DSN"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("missing error for %s in %v", key, err)
		}
	}
}
