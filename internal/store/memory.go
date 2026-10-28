package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/detect"
	"github.com/mahyarnemati/siem-lite/internal/event"
)

// Memory is a bounded in-process store for tests and local runs without
// ClickHouse. When full, the oldest records are dropped.
type Memory struct {
	mu         sync.RWMutex
	max        int
	events     []event.Event
	detections []detect.Detection
}

// NewMemory keeps at most max events and max detections.
func NewMemory(max int) *Memory {
	if max <= 0 {
		max = 100_000
	}
	return &Memory{max: max}
}

// InsertEvents implements Store.
func (m *Memory) InsertEvents(_ context.Context, evs []event.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = appendBounded(m.events, evs, m.max)
	return nil
}

// InsertDetections implements Store.
func (m *Memory) InsertDetections(_ context.Context, ds []detect.Detection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.detections = appendBounded(m.detections, ds, m.max)
	return nil
}

// RecentDetections implements Store.
func (m *Memory) RecentDetections(_ context.Context, since time.Time, limit int) ([]detect.Detection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []detect.Detection
	for _, d := range m.detections {
		if !d.DetectedAt.Before(since) {
			out = append(out, d)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].DetectedAt.After(out[j].DetectedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Events returns a copy of stored events.
func (m *Memory) Events() []event.Event {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]event.Event(nil), m.events...)
}

// Ping implements Store.
func (m *Memory) Ping(context.Context) error { return nil }

// Close implements Store.
func (m *Memory) Close() error { return nil }

func appendBounded[T any](dst, src []T, limit int) []T {
	dst = append(dst, src...)
	if over := len(dst) - limit; over > 0 {
		dst = append(dst[:0], dst[over:]...)
	}
	return dst
}
