package pipeline

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mahyarnemati/siem-lite/internal/clock"
	"github.com/mahyarnemati/siem-lite/internal/detect"
	"github.com/mahyarnemati/siem-lite/internal/event"
	"github.com/mahyarnemati/siem-lite/internal/geo"
	"github.com/mahyarnemati/siem-lite/internal/ingest"
	"github.com/mahyarnemati/siem-lite/internal/metrics"
	"github.com/mahyarnemati/siem-lite/internal/parser"
	"github.com/mahyarnemati/siem-lite/internal/store"
)

type alerts struct {
	mu  sync.Mutex
	got []detect.Detection
}

func (a *alerts) Submit(d detect.Detection) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got = append(a.got, d)
	return true
}

func engine(t *testing.T) *detect.Engine {
	t.Helper()
	rules, err := detect.LoadDir(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := detect.NewEngine(rules, detect.WithClock(clock.NewFake(time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC))))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestPipelineEndToEnd(t *testing.T) {
	mem := store.NewMemory(0)
	al := &alerts{}
	g := geo.NewStatic()
	_ = g.Add("203.0.113.0/24", geo.Location{Country: "RU", City: "Moscow", Lat: 55.75, Lon: 37.62})
	m := metrics.New(nil)
	p, err := New(Config{Engine: engine(t), Store: mem, Alerter: al, Geo: g, Metrics: m, Workers: 2, FlushInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	for i := range 10 {
		line := fmt.Sprintf("<38>Mar 15 12:00:%02d bastion sshd[1]: Failed password for root from 203.0.113.9 port %d ssh2", i, 40000+i)
		if err := p.Handle(ctx, ingest.Record{Format: parser.FormatSyslog, Data: line, Received: now, Transport: "tcp"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = p.Handle(ctx, ingest.Record{Format: parser.FormatJSON, Data: "{not json", Received: now, Transport: "http"})

	deadline := time.Now().Add(3 * time.Second)
	for len(mem.Events()) < 10 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	evs := mem.Events()
	if len(evs) != 10 {
		t.Fatalf("stored %d events", len(evs))
	}
	if evs[0].Country != "RU" || evs[0].City != "Moscow" || evs[0].Received.IsZero() {
		t.Fatalf("enrichment: %+v", evs[0])
	}
	ds, _ := mem.RecentDetections(context.Background(), time.Time{}, 10)
	if len(ds) != 1 || ds[0].RuleID != "auth-bruteforce-ip" {
		t.Fatalf("detections %+v", ds)
	}
	if len(al.got) != 1 {
		t.Fatalf("alerts %d", len(al.got))
	}
	if got := testutil.ToFloat64(m.ParseErrors.WithLabelValues("json")); got != 1 {
		t.Fatalf("parse errors %v", got)
	}
	if got := testutil.ToFloat64(m.Received.WithLabelValues("tcp")); got != 10 {
		t.Fatalf("received %v", got)
	}
	if err := p.Handle(context.Background(), ingest.Record{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("handle after close: %v", err)
	}
	if p.TryHandle(ingest.Record{}) {
		t.Fatal("try handle after close")
	}
}

type flakyStore struct {
	*store.Memory
	mu    sync.Mutex
	fails int
}

func (f *flakyStore) InsertEvents(ctx context.Context, evs []event.Event) error {
	f.mu.Lock()
	if f.fails > 0 {
		f.fails--
		f.mu.Unlock()
		return errors.New("clickhouse down")
	}
	f.mu.Unlock()
	return f.Memory.InsertEvents(ctx, evs)
}

func TestPipelineRetriesFailedFlush(t *testing.T) {
	fs := &flakyStore{Memory: store.NewMemory(0), fails: 2}
	m := metrics.New(nil)
	p, _ := New(Config{Engine: engine(t), Store: fs, Metrics: m, Workers: 1, FlushInterval: 5 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	for i := range 3 {
		_ = p.Handle(ctx, ingest.Record{Format: parser.FormatJSON, Data: fmt.Sprintf(`{"msg":"m%d"}`, i), Received: time.Now(), Transport: "http"})
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(fs.Events()) < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if len(fs.Events()) != 3 {
		t.Fatalf("events lost across store failures: %d", len(fs.Events()))
	}
	if got := testutil.ToFloat64(m.StoreErrors.WithLabelValues("events")); got < 1 {
		t.Fatalf("store errors %v", got)
	}
}

func TestTryHandleDropsWhenFull(t *testing.T) {
	m := metrics.New(nil)
	p, _ := New(Config{Engine: engine(t), Store: store.NewMemory(0), Metrics: m, QueueSize: 1})
	if !p.TryHandle(ingest.Record{Transport: "udp"}) {
		t.Fatal("first should fit")
	}
	if p.TryHandle(ingest.Record{Transport: "udp"}) {
		t.Fatal("queue should be full")
	}
	if got := testutil.ToFloat64(m.Dropped.WithLabelValues("queue_full")); got != 1 {
		t.Fatalf("dropped %v", got)
	}
	if p.QueueDepth() != 1 {
		t.Fatal("queue depth")
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error")
	}
}

func BenchmarkProcessSSHD(b *testing.B) {
	rules, _ := detect.LoadDir(filepath.Join("..", "..", "rules"))
	e, _ := detect.NewEngine(rules)
	p, _ := New(Config{Engine: e, Store: store.NewMemory(1)})
	now := time.Now()
	recs := make([]ingest.Record, 256)
	for i := range recs {
		recs[i] = ingest.Record{Format: parser.FormatSyslog, Received: now, Transport: "udp",
			Data: fmt.Sprintf("<38>Mar 15 12:00:00 bastion sshd[1]: Failed password for user%d from 198.51.100.%d port 4000 ssh2", i%50, i%200)}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		if _, _, err := p.Process(recs[i%len(recs)]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProcessNginx(b *testing.B) {
	rules, _ := detect.LoadDir(filepath.Join("..", "..", "rules"))
	e, _ := detect.NewEngine(rules)
	p, _ := New(Config{Engine: e, Store: store.NewMemory(1)})
	now := time.Now()
	recs := make([]ingest.Record, 256)
	for i := range recs {
		recs[i] = ingest.Record{Format: parser.FormatNginx, Received: now, Transport: "file",
			Data: fmt.Sprintf(`198.51.100.%d - - [15/Mar/2026:10:00:01 +0000] "GET /p/%d HTTP/1.1" 404 153 "-" "Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0"`, i%200, i)}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		if _, _, err := p.Process(recs[i%len(recs)]); err != nil {
			b.Fatal(err)
		}
	}
}
