// Package pipeline wires parsing, enrichment, detection, storage and
// alerting together.
package pipeline

import (
	"context"
	"errors"
	"hash/fnv"
	"log/slog"
	"sync"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/detect"
	"github.com/mahyarnemati/siem-lite/internal/event"
	"github.com/mahyarnemati/siem-lite/internal/geo"
	"github.com/mahyarnemati/siem-lite/internal/ingest"
	"github.com/mahyarnemati/siem-lite/internal/metrics"
	"github.com/mahyarnemati/siem-lite/internal/parser"
	"github.com/mahyarnemati/siem-lite/internal/store"
)

// Alerter receives detections. *alert.Dispatcher satisfies it.
type Alerter interface {
	Submit(d detect.Detection) bool
}

// Config configures a Pipeline.
type Config struct {
	Engine        *detect.Engine
	Store         store.Store
	Alerter       Alerter
	Geo           geo.Locator
	Metrics       *metrics.Metrics
	Logger        *slog.Logger
	Workers       int
	QueueSize     int
	BatchSize     int
	FlushInterval time.Duration
	// MaxBuffered caps events held in memory while the store is failing.
	MaxBuffered int
}

// Pipeline is an ingest.Handler that processes records on a worker pool.
type Pipeline struct {
	cfg    Config
	in     []chan ingest.Record
	out    chan event.Event
	dets   chan detect.Detection
	closed chan struct{}
	once   sync.Once
}

// ErrClosed is returned by Handle after shutdown has begun.
var ErrClosed = errors.New("pipeline closed")

// New validates cfg and fills defaults.
func New(cfg Config) (*Pipeline, error) {
	if cfg.Engine == nil || cfg.Store == nil {
		return nil, errors.New("pipeline: engine and store are required")
	}
	if cfg.Geo == nil {
		cfg.Geo = geo.Nop{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 10_000
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 5_000
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}
	if cfg.MaxBuffered <= 0 {
		cfg.MaxBuffered = 20 * cfg.BatchSize
	}
	p := &Pipeline{
		cfg:    cfg,
		in:     make([]chan ingest.Record, cfg.Workers),
		out:    make(chan event.Event, cfg.BatchSize),
		dets:   make(chan detect.Detection, 1024),
		closed: make(chan struct{}),
	}
	for i := range p.in {
		p.in[i] = make(chan ingest.Record, max(cfg.QueueSize/cfg.Workers, 1))
	}
	if cfg.Metrics == nil {
		p.cfg.Metrics = metrics.New(p.QueueDepth)
	}
	return p, nil
}

// QueueDepth reports records waiting for a worker.
func (p *Pipeline) QueueDepth() float64 {
	n := 0
	for _, q := range p.in {
		n += len(q)
	}
	return float64(n)
}

// shard pins every record from one sender to one worker so per-source order
// survives the worker pool. Stateful rules such as new_value depend on it.
func (p *Pipeline) shard(r ingest.Record) chan ingest.Record {
	if len(p.in) == 1 {
		return p.in[0]
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(r.Transport))
	_, _ = h.Write([]byte(r.Remote))
	return p.in[h.Sum32()%uint32(len(p.in))]
}

// Handle implements ingest.Handler, blocking until there is room.
func (p *Pipeline) Handle(ctx context.Context, r ingest.Record) error {
	select {
	case <-p.closed:
		return ErrClosed
	default:
	}
	p.cfg.Metrics.Received.WithLabelValues(r.Transport).Inc()
	select {
	case p.shard(r) <- r:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-p.closed:
		return ErrClosed
	}
}

// TryHandle implements ingest.Handler without blocking.
func (p *Pipeline) TryHandle(r ingest.Record) bool {
	select {
	case <-p.closed:
		return false
	default:
	}
	p.cfg.Metrics.Received.WithLabelValues(r.Transport).Inc()
	select {
	case p.shard(r) <- r:
		return true
	default:
		p.cfg.Metrics.Dropped.WithLabelValues("queue_full").Inc()
		return false
	}
}

// Run processes records until ctx is cancelled, then drains the queue and
// flushes buffered events before returning.
func (p *Pipeline) Run(ctx context.Context) {
	var workers sync.WaitGroup
	for _, q := range p.in {
		workers.Add(1)
		go func() {
			defer workers.Done()
			p.work(ctx, q)
		}()
	}
	flushed := make(chan struct{})
	go func() {
		defer close(flushed)
		p.batch()
	}()

	<-ctx.Done()
	p.once.Do(func() { close(p.closed) })
	workers.Wait()
	close(p.out)
	close(p.dets)
	<-flushed
}

func (p *Pipeline) work(ctx context.Context, in <-chan ingest.Record) {
	for {
		select {
		case r := <-in:
			p.process(r)
		case <-ctx.Done():
			for {
				select {
				case r := <-in:
					p.process(r)
				default:
					return
				}
			}
		}
	}
}

// Process parses, enriches and evaluates one record synchronously. It is
// exported for benchmarks and replay tools.
func (p *Pipeline) Process(r ingest.Record) (event.Event, []detect.Detection, error) {
	ev, err := parser.Line(r.Format, r.Data, r.Received)
	if err != nil {
		return event.Event{}, nil, err
	}
	ev.Received = r.Received
	if ev.Host == "" && r.Transport != "file" {
		ev.Host = r.Remote
	}
	p.enrich(&ev)
	return ev, p.cfg.Engine.Process(&ev), nil
}

func (p *Pipeline) process(r ingest.Record) {
	ev, ds, err := p.Process(r)
	if err != nil {
		p.cfg.Metrics.ParseErrors.WithLabelValues(string(r.Format)).Inc()
		p.cfg.Logger.Debug("parse failed", "format", r.Format, "transport", r.Transport, "err", err)
		return
	}
	p.out <- ev
	for _, d := range ds {
		p.cfg.Metrics.Detections.WithLabelValues(d.RuleID, d.Severity).Inc()
		p.cfg.Logger.Debug("detection", "rule", d.RuleID, "severity", d.Severity, "key", d.GroupKey, "summary", d.Summary)
		if p.cfg.Alerter != nil {
			p.cfg.Alerter.Submit(d)
		}
		p.dets <- d
	}
}

func (p *Pipeline) enrich(ev *event.Event) {
	if ev.SrcIP == "" || ev.HasGeo() {
		return
	}
	loc, ok := p.cfg.Geo.Lookup(ev.SrcIP)
	if !ok {
		return
	}
	if ev.Country == "" {
		ev.Country = loc.Country
	}
	if ev.City == "" {
		ev.City = loc.City
	}
	ev.Lat, ev.Lon = loc.Lat, loc.Lon
}

// batch accumulates events and detections and writes them in batches. It
// returns once both input channels are closed and the final flush is done.
func (p *Pipeline) batch() {
	ticker := time.NewTicker(p.cfg.FlushInterval)
	defer ticker.Stop()
	evs := make([]event.Event, 0, p.cfg.BatchSize)
	var dets []detect.Detection
	out, detIn := p.out, p.dets

	flush := func(final bool) {
		evs = p.flushEvents(evs, final)
		dets = p.flushDetections(dets)
	}
	for out != nil || detIn != nil {
		select {
		case ev, ok := <-out:
			if !ok {
				out = nil
				continue
			}
			evs = append(evs, ev)
			if len(evs) >= p.cfg.BatchSize {
				flush(false)
			}
		case d, ok := <-detIn:
			if !ok {
				detIn = nil
				continue
			}
			dets = append(dets, d)
		case <-ticker.C:
			flush(false)
		}
	}
	flush(true)
}

func (p *Pipeline) flushEvents(evs []event.Event, final bool) []event.Event {
	if len(evs) == 0 {
		return evs
	}
	timeout := 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	err := p.cfg.Store.InsertEvents(ctx, evs)
	p.cfg.Metrics.FlushDuration.Observe(time.Since(start).Seconds())
	if err == nil {
		p.cfg.Metrics.EventsStored.Add(float64(len(evs)))
		return evs[:0]
	}
	p.cfg.Metrics.StoreErrors.WithLabelValues("events").Inc()
	p.cfg.Logger.Error("store events", "count", len(evs), "err", err)
	if final {
		p.cfg.Metrics.Dropped.WithLabelValues("store_unavailable").Add(float64(len(evs)))
		return evs[:0]
	}
	if over := len(evs) - p.cfg.MaxBuffered; over > 0 {
		p.cfg.Metrics.Dropped.WithLabelValues("store_backlog").Add(float64(over))
		evs = append(evs[:0], evs[over:]...)
	}
	return evs
}

func (p *Pipeline) flushDetections(ds []detect.Detection) []detect.Detection {
	if len(ds) == 0 {
		return ds
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.cfg.Store.InsertDetections(ctx, ds); err != nil {
		p.cfg.Metrics.StoreErrors.WithLabelValues("detections").Inc()
		p.cfg.Logger.Error("store detections", "count", len(ds), "err", err)
		if len(ds) > 10_000 {
			return ds[len(ds)-10_000:]
		}
		return ds
	}
	return ds[:0]
}
