// Package alert delivers detections to external sinks with deduplication
// and suppression.
package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/clock"
	"github.com/mahyarnemati/siem-lite/internal/detect"
)

// Sink delivers a detection somewhere.
type Sink interface {
	Name() string
	Send(ctx context.Context, d detect.Detection) error
}

// Deduper suppresses repeats of the same rule+group inside a window.
type Deduper struct {
	mu       sync.Mutex
	clock    clock.Clock
	fallback time.Duration
	last     map[string]time.Time
}

// NewDeduper uses fallback when a detection carries no suppress window.
func NewDeduper(c clock.Clock, fallback time.Duration) *Deduper {
	return &Deduper{clock: c, fallback: fallback, last: map[string]time.Time{}}
}

// Allow reports whether d should be delivered and records it if so.
func (d *Deduper) Allow(det detect.Detection) bool {
	window := det.Suppress
	if window <= 0 {
		window = d.fallback
	}
	key := det.RuleID + "\x00" + det.GroupKey
	now := d.clock.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.last[key]; ok && now.Sub(t) < window {
		return false
	}
	d.last[key] = now
	return true
}

// GC forgets entries older than maxAge.
func (d *Deduper) GC(maxAge time.Duration) int {
	cut := d.clock.Now().Add(-maxAge)
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for k, t := range d.last {
		if t.Before(cut) {
			delete(d.last, k)
			n++
		}
	}
	return n
}

// Dispatcher fans detections out to sinks on a background worker.
type Dispatcher struct {
	sinks   []Sink
	dedupe  *Deduper
	log     *slog.Logger
	queue   chan detect.Detection
	retries int
	backoff time.Duration
	wg      sync.WaitGroup

	mu         sync.Mutex
	suppressed int64
	dropped    int64
	failed     int64
	sent       int64
}

// DispatcherConfig configures a Dispatcher.
type DispatcherConfig struct {
	Sinks     []Sink
	Dedupe    *Deduper
	Logger    *slog.Logger
	QueueSize int
	Retries   int
	Backoff   time.Duration
}

// NewDispatcher creates a dispatcher; call Run to start delivering.
func NewDispatcher(cfg DispatcherConfig) *Dispatcher {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = 500 * time.Millisecond
	}
	d := &Dispatcher{
		sinks: cfg.Sinks, dedupe: cfg.Dedupe, log: cfg.Logger,
		queue: make(chan detect.Detection, cfg.QueueSize), retries: cfg.Retries, backoff: cfg.Backoff,
	}
	d.wg.Add(1)
	return d
}

// Submit enqueues a detection. It returns false if it was suppressed or the
// queue is full; neither blocks the ingest path.
func (d *Dispatcher) Submit(det detect.Detection) bool {
	if d.dedupe != nil && !d.dedupe.Allow(det) {
		d.count(&d.suppressed)
		return false
	}
	select {
	case d.queue <- det:
		return true
	default:
		d.count(&d.dropped)
		d.log.Warn("alert queue full, dropping", "rule", det.RuleID, "key", det.GroupKey)
		return false
	}
}

// Run delivers until ctx is cancelled, then drains what is queued. In-flight
// and drained deliveries get a grace period after cancellation instead of
// failing immediately. It must be called exactly once.
func (d *Dispatcher) Run(ctx context.Context) {
	defer d.wg.Done()
	sendCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	stop := context.AfterFunc(ctx, func() { time.AfterFunc(drainTimeout, cancel) })
	defer stop()
	for {
		select {
		case det := <-d.queue:
			d.deliver(sendCtx, det)
		case <-ctx.Done():
			for {
				select {
				case det := <-d.queue:
					d.deliver(sendCtx, det)
				default:
					return
				}
			}
		}
	}
}

const drainTimeout = 5 * time.Second

// Wait blocks until Run has returned.
func (d *Dispatcher) Wait() { d.wg.Wait() }

// Stats returns delivery counters.
func (d *Dispatcher) Stats() map[string]int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return map[string]int64{"sent": d.sent, "failed": d.failed, "suppressed": d.suppressed, "dropped": d.dropped}
}

func (d *Dispatcher) count(c *int64) {
	d.mu.Lock()
	*c++
	d.mu.Unlock()
}

func (d *Dispatcher) deliver(ctx context.Context, det detect.Detection) {
	for _, s := range d.sinks {
		var err error
		for attempt := 0; attempt <= d.retries; attempt++ {
			if attempt > 0 {
				select {
				case <-time.After(d.backoff << (attempt - 1)):
				case <-ctx.Done():
				}
			}
			sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = s.Send(sendCtx, det)
			cancel()
			if err == nil || errors.Is(err, errPermanent) || ctx.Err() != nil {
				break
			}
		}
		if err != nil {
			d.count(&d.failed)
			d.log.Error("alert delivery failed", "sink", s.Name(), "rule", det.RuleID, "err", err)
			continue
		}
		d.count(&d.sent)
	}
}

var errPermanent = errors.New("permanent delivery failure")

// LogSink writes detections to the structured log.
type LogSink struct{ Logger *slog.Logger }

// Name implements Sink.
func (LogSink) Name() string { return "log" }

// Send implements Sink.
func (s LogSink) Send(_ context.Context, d detect.Detection) error {
	s.Logger.Warn("detection", "rule", d.RuleID, "severity", d.Severity, "key", d.GroupKey,
		"count", d.Count, "summary", d.Summary)
	return nil
}

// Webhook posts the detection as JSON. When Secret is set the body is signed
// with HMAC-SHA256 in the X-Signature-256 header.
type Webhook struct {
	URL    string
	Secret string
	Client *http.Client
}

// Name implements Sink.
func (w *Webhook) Name() string { return "webhook" }

// Send implements Sink.
func (w *Webhook) Send(ctx context.Context, d detect.Detection) error {
	body, err := json.Marshal(d)
	if err != nil {
		return err
	}
	hdr := http.Header{"Content-Type": {"application/json"}}
	if w.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.Secret))
		mac.Write(body)
		hdr.Set("X-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	return post(ctx, w.Client, w.URL, hdr, body)
}

// Slack posts to an incoming webhook.
type Slack struct {
	URL    string
	Client *http.Client
}

// Name implements Sink.
func (s *Slack) Name() string { return "slack" }

// Send implements Sink.
func (s *Slack) Send(ctx context.Context, d detect.Detection) error {
	body, err := json.Marshal(SlackPayload(d))
	if err != nil {
		return err
	}
	return post(ctx, s.Client, s.URL, http.Header{"Content-Type": {"application/json"}}, body)
}

var severityEmoji = map[string]string{"low": ":information_source:", "medium": ":warning:", "high": ":rotating_light:", "critical": ":fire:"}

// SlackPayload renders a detection as Slack Block Kit.
func SlackPayload(d detect.Detection) map[string]any {
	header := fmt.Sprintf("%s [%s] %s", severityEmoji[d.Severity], strings.ToUpper(d.Severity), d.Title)
	fields := []map[string]string{
		{"type": "mrkdwn", "text": "*Rule*\n`" + d.RuleID + "`"},
		{"type": "mrkdwn", "text": "*Key*\n`" + d.GroupKey + "`"},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Count*\n%d", d.Count)},
		{"type": "mrkdwn", "text": "*Window*\n" + d.FirstSeen.UTC().Format(time.RFC3339) + " to " + d.LastSeen.UTC().Format(time.RFC3339)},
	}
	return map[string]any{
		"text": header,
		"blocks": []any{
			map[string]any{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": "*" + header + "*\n" + d.Summary}},
			map[string]any{"type": "section", "fields": fields},
		},
	}
}

func post(ctx context.Context, c *http.Client, url string, hdr http.Header, body []byte) error {
	if c == nil {
		c = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: %w", errPermanent, err)
	}
	req.Header = hdr
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	default:
		return fmt.Errorf("%w: webhook status %d", errPermanent, resp.StatusCode)
	}
}

// GCDedupe forgets suppression state older than maxAge.
func (d *Dispatcher) GCDedupe(maxAge time.Duration) int {
	if d.dedupe == nil {
		return 0
	}
	return d.dedupe.GC(maxAge)
}
