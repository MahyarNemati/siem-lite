//go:build integration

package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/detect"
	"github.com/mahyarnemati/siem-lite/internal/event"
)

// Run with: SIEM_TEST_CLICKHOUSE_DSN=clickhouse://default:@localhost:9000/default go test -tags integration ./internal/store
func TestClickHouseRoundTrip(t *testing.T) {
	dsn := os.Getenv("SIEM_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("SIEM_TEST_CLICKHOUSE_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ch, err := OpenClickHouse(ctx, ClickHouseConfig{DSN: dsn, EventTTLDays: 1, DetectionTTLDays: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := ch.InsertEvents(ctx, []event.Event{{Timestamp: now, Received: now, Source: "sshd", Category: "authentication",
		Outcome: "failure", User: "root", SrcIP: "203.0.113.9", Fields: map[string]string{"method": "password"}}}); err != nil {
		t.Fatal(err)
	}
	marker := "it-" + now.Format("150405.000")
	if err := ch.InsertDetections(ctx, []detect.Detection{{RuleID: marker, Title: "t", Severity: "high", GroupKey: "k",
		Count: 3, DetectedAt: now, FirstSeen: now, LastSeen: now}}); err != nil {
		t.Fatal(err)
	}
	ds, err := ch.RecentDetections(ctx, now.Add(-time.Second), 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		if d.RuleID == marker && d.Count == 3 {
			return
		}
	}
	t.Fatalf("detection %s not found in %+v", marker, ds)
}
