package alert

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/clock"
	"github.com/mahyarnemati/siem-lite/internal/detect"
)

var t0 = time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)

func det(rule, key string, suppress time.Duration) detect.Detection {
	return detect.Detection{RuleID: rule, Title: "T", Severity: "high", GroupKey: key, Count: 3, Suppress: suppress, FirstSeen: t0, LastSeen: t0}
}

func TestDeduperSuppression(t *testing.T) {
	clk := clock.NewFake(t0)
	d := NewDeduper(clk, time.Minute)
	if !d.Allow(det("r", "a", 10*time.Minute)) {
		t.Fatal("first should pass")
	}
	clk.Advance(9 * time.Minute)
	if d.Allow(det("r", "a", 10*time.Minute)) {
		t.Fatal("inside suppress window")
	}
	if !d.Allow(det("r", "b", 10*time.Minute)) || !d.Allow(det("r2", "a", 10*time.Minute)) {
		t.Fatal("different key or rule must pass")
	}
	clk.Advance(time.Minute)
	if !d.Allow(det("r", "a", 10*time.Minute)) {
		t.Fatal("window elapsed")
	}
	// Fallback window applies when the rule has none.
	if !d.Allow(det("r3", "a", 0)) {
		t.Fatal("first")
	}
	clk.Advance(59 * time.Second)
	if d.Allow(det("r3", "a", 0)) {
		t.Fatal("fallback window")
	}
	clk.Advance(time.Hour)
	if n := d.GC(30 * time.Minute); n != 4 {
		t.Fatalf("gc removed %d", n)
	}
}

type recordSink struct {
	mu    sync.Mutex
	got   []detect.Detection
	fails int32
}

func (r *recordSink) Name() string { return "rec" }
func (r *recordSink) Send(_ context.Context, d detect.Detection) error {
	if atomic.AddInt32(&r.fails, -1) >= 0 {
		return io.ErrUnexpectedEOF
	}
	r.mu.Lock()
	r.got = append(r.got, d)
	r.mu.Unlock()
	return nil
}

func TestDispatcherDedupeRetryAndDrain(t *testing.T) {
	clk := clock.NewFake(t0)
	sink := &recordSink{fails: 2}
	disp := NewDispatcher(DispatcherConfig{Sinks: []Sink{sink}, Dedupe: NewDeduper(clk, time.Minute), Retries: 2, Backoff: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	go disp.Run(ctx)

	if !disp.Submit(det("r", "a", time.Hour)) {
		t.Fatal("submit")
	}
	if disp.Submit(det("r", "a", time.Hour)) {
		t.Fatal("duplicate should be suppressed")
	}
	disp.Submit(det("r", "b", time.Hour))
	cancel()
	disp.Wait()

	if len(sink.got) != 2 {
		t.Fatalf("delivered %d", len(sink.got))
	}
	st := disp.Stats()
	if st["sent"] != 2 || st["suppressed"] != 1 || st["failed"] != 0 {
		t.Fatalf("stats %v", st)
	}
}

func TestDispatcherQueueFull(t *testing.T) {
	disp := NewDispatcher(DispatcherConfig{QueueSize: 1})
	disp.Submit(det("r", "a", 0))
	if disp.Submit(det("r", "b", 0)) {
		t.Fatal("queue should be full")
	}
	if disp.Stats()["dropped"] != 1 {
		t.Fatal("drop not counted")
	}
}

func TestWebhookSigned(t *testing.T) {
	var gotSig string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Signature-256")
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	wh := &Webhook{URL: srv.URL, Secret: "s3cret", Client: srv.Client()}
	if err := wh.Send(context.Background(), det("r", "a", 0)); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(body)
	if gotSig != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("bad signature %q", gotSig)
	}
	var decoded detect.Detection
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.RuleID != "r" {
		t.Fatalf("body %s", body)
	}
}

func TestWebhookStatusHandling(t *testing.T) {
	var calls atomic.Int32
	status := http.StatusBadRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(status)
	}))
	defer srv.Close()

	disp := NewDispatcher(DispatcherConfig{Sinks: []Sink{&Webhook{URL: srv.URL}}, Retries: 3, Backoff: time.Millisecond})
	disp.deliver(context.Background(), det("r", "a", 0))
	if calls.Load() != 1 {
		t.Fatalf("4xx must not be retried, calls=%d", calls.Load())
	}
	status = http.StatusServiceUnavailable
	calls.Store(0)
	disp.deliver(context.Background(), det("r", "a", 0))
	if calls.Load() != 4 {
		t.Fatalf("5xx should retry, calls=%d", calls.Load())
	}
	if disp.Stats()["failed"] != 2 {
		t.Fatalf("stats %v", disp.Stats())
	}
}

func TestSlackPayload(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	d := det("auth-password-spray", "203.0.113.5", 0)
	d.Summary = "5 distinct user values"
	if err := (&Slack{URL: srv.URL}).Send(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	text, _ := got["text"].(string)
	if !strings.Contains(text, "[HIGH]") || len(got["blocks"].([]any)) != 2 {
		t.Fatalf("payload %v", got)
	}
}
