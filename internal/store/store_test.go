package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/detect"
	"github.com/mahyarnemati/siem-lite/internal/event"
)

func TestMemoryBoundedAndOrdered(t *testing.T) {
	m := NewMemory(3)
	ctx := context.Background()
	t0 := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	for i := range 5 {
		_ = m.InsertEvents(ctx, []event.Event{{Message: string(rune('a' + i))}})
		_ = m.InsertDetections(ctx, []detect.Detection{{RuleID: "r", DetectedAt: t0.Add(time.Duration(i) * time.Minute)}})
	}
	evs := m.Events()
	if len(evs) != 3 || evs[0].Message != "c" {
		t.Fatalf("events %+v", evs)
	}
	ds, _ := m.RecentDetections(ctx, t0.Add(3*time.Minute), 10)
	if len(ds) != 2 || !ds[0].DetectedAt.After(ds[1].DetectedAt) {
		t.Fatalf("detections %+v", ds)
	}
	ds, _ = m.RecentDetections(ctx, t0, 1)
	if len(ds) != 1 {
		t.Fatalf("limit not applied: %d", len(ds))
	}
}

func TestSchemaTTL(t *testing.T) {
	s := Schema(7, 90)
	if !strings.Contains(s[0], "INTERVAL 7 DAY") || !strings.Contains(s[1], "INTERVAL 90 DAY") {
		t.Fatalf("ttl not rendered: %v", s)
	}
	d := Schema(0, 0)
	if !strings.Contains(d[0], "INTERVAL 30 DAY") || !strings.Contains(d[1], "INTERVAL 365 DAY") {
		t.Fatal("defaults not applied")
	}
}

func TestRedactDSN(t *testing.T) {
	cases := map[string]string{
		"clickhouse://siem:secret@ch:9000/siem": "clickhouse://***@ch:9000/siem",
		"clickhouse://ch:9000/siem":             "clickhouse://ch:9000/siem",
	}
	for in, want := range cases {
		if got := RedactDSN(in); got != want {
			t.Errorf("%s: got %s", in, got)
		}
	}
}

func TestClampU16(t *testing.T) {
	if clampU16(-1) != 0 || clampU16(70000) != 65535 || clampU16(443) != 443 {
		t.Fatal("clamp")
	}
}
