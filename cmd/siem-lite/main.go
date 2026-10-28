// Command siem-lite ingests logs, runs detection rules and stores events.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/alert"
	"github.com/mahyarnemati/siem-lite/internal/api"
	"github.com/mahyarnemati/siem-lite/internal/clock"
	"github.com/mahyarnemati/siem-lite/internal/config"
	"github.com/mahyarnemati/siem-lite/internal/detect"
	"github.com/mahyarnemati/siem-lite/internal/geo"
	"github.com/mahyarnemati/siem-lite/internal/ingest"
	"github.com/mahyarnemati/siem-lite/internal/metrics"
	"github.com/mahyarnemati/siem-lite/internal/pipeline"
	"github.com/mahyarnemati/siem-lite/internal/store"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "validate-rules" {
		os.Exit(validateRules(os.Args[2:]))
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid configuration:\n"+err.Error())
		os.Exit(2)
	}
	log := newLogger(cfg)
	if err := runWithSignals(cfg, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func runWithSignals(cfg config.Config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, cfg, log)
}

func validateRules(args []string) int {
	dir := "rules"
	if len(args) > 0 {
		dir = args[0]
	}
	rules, err := detect.LoadDir(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := detect.NewEngine(rules); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("%d rules OK\n", len(rules))
	return 0
}

func newLogger(cfg config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func run(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	log.Info("starting siem-lite", "version", version)

	rules, err := detect.LoadDir(cfg.RulesDir)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	engine, err := detect.NewEngine(rules, detect.WithMaxKeys(cfg.MaxKeysPerRule), detect.WithLogger(log))
	if err != nil {
		return err
	}
	log.Info("rules loaded", "count", len(engine.Rules()), "dir", cfg.RulesDir)
	if cfg.SnapshotPath != "" {
		if err := engine.LoadSnapshot(cfg.SnapshotPath); err != nil {
			log.Warn("snapshot restore failed, starting cold", "path", cfg.SnapshotPath, "err", err)
		}
	}

	st, err := openStore(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer st.Close()

	locator, closeGeo, err := openGeo(cfg, log)
	if err != nil {
		return err
	}
	defer closeGeo()

	dispatcher := alert.NewDispatcher(alert.DispatcherConfig{
		Sinks:   sinks(cfg, log),
		Dedupe:  alert.NewDeduper(clock.Real{}, cfg.DefaultSuppress),
		Logger:  log,
		Retries: cfg.AlertRetries,
	})

	var pl *pipeline.Pipeline
	m := metrics.New(func() float64 { return pl.QueueDepth() })
	pl, err = pipeline.New(pipeline.Config{
		Engine: engine, Store: st, Alerter: dispatcher, Geo: locator, Metrics: m, Logger: log,
		Workers: cfg.Workers, QueueSize: cfg.Queue, BatchSize: cfg.Batch, FlushInterval: cfg.FlushInt,
	})
	if err != nil {
		return err
	}

	procCtx, cancelProc := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelProc()
	var bg sync.WaitGroup
	bg.Add(2)
	go func() { defer bg.Done(); pl.Run(procCtx) }()
	go func() { defer bg.Done(); dispatcher.Run(procCtx) }()

	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: api.New(api.Deps{
			Ingest: api.IngestHandler(pl, cfg.IngestToken, cfg.MaxBodyBytes),
			Store:  st, Engine: engine, Registry: m.Registry, AlertStats: dispatcher.Stats, Logger: log,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	ingestCtx, cancelIngest := context.WithCancel(ctx)
	defer cancelIngest()
	var listeners sync.WaitGroup
	errc := make(chan error, 4)
	start := func(name string, fn func() error) {
		listeners.Add(1)
		go func() {
			defer listeners.Done()
			if err := fn(); err != nil {
				errc <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}
	start("http", func() error {
		log.Info("http listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	if cfg.SyslogUDPAddr != "" && cfg.SyslogUDPAddr != "off" {
		udp := &ingest.UDPServer{Addr: cfg.SyslogUDPAddr, Handler: pl, Logger: log}
		start("syslog-udp", func() error {
			log.Info("syslog udp listening", "addr", cfg.SyslogUDPAddr)
			return udp.ListenAndServe(ingestCtx)
		})
	}
	if cfg.SyslogTCPAddr != "" && cfg.SyslogTCPAddr != "off" {
		tcp := &ingest.TCPServer{Addr: cfg.SyslogTCPAddr, Handler: pl, Logger: log}
		start("syslog-tcp", func() error {
			log.Info("syslog tcp listening", "addr", cfg.SyslogTCPAddr)
			return tcp.ListenAndServe(ingestCtx)
		})
	}
	for _, tf := range cfg.TailFiles {
		t := &ingest.Tailer{Path: tf.Path, Format: tf.Format, Handler: pl, Logger: log}
		start("tail "+tf.Path, func() error { return t.Run(ingestCtx) })
	}

	maintenance(ingestCtx, cfg, engine, dispatcher, log, &bg)

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutdown requested")
	case runErr = <-errc:
		log.Error("component failed, shutting down", "err", runErr)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	cancelIngest()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Warn("http shutdown", "err", err)
	}
	listeners.Wait()
	cancelProc()
	bg.Wait()
	dispatcher.Wait()
	if cfg.SnapshotPath != "" {
		if err := engine.SaveSnapshot(cfg.SnapshotPath); err != nil {
			log.Error("final snapshot", "err", err)
		}
	}
	log.Info("stopped", "alerts", dispatcher.Stats())
	return runErr
}

// maintenance runs periodic GC and snapshots until ctx is done.
func maintenance(ctx context.Context, cfg config.Config, e *detect.Engine, d *alert.Dispatcher, log *slog.Logger, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		gc := time.NewTicker(time.Minute)
		defer gc.Stop()
		var snap <-chan time.Time
		if cfg.SnapshotPath != "" {
			t := time.NewTicker(cfg.SnapshotInterval)
			defer t.Stop()
			snap = t.C
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-gc.C:
				n := e.GC()
				m := d.GCDedupe(24 * time.Hour)
				log.Debug("gc", "detector_groups", n, "dedupe_keys", m)
			case <-snap:
				if err := e.SaveSnapshot(cfg.SnapshotPath); err != nil {
					log.Error("snapshot", "err", err)
				}
			}
		}
	}()
}

func openStore(ctx context.Context, cfg config.Config, log *slog.Logger) (store.Store, error) {
	if cfg.ClickHouseDSN == "" {
		log.Warn("SIEM_CLICKHOUSE_DSN not set, using bounded in-memory store")
		return store.NewMemory(200_000), nil
	}
	var lastErr error
	for attempt := range 10 {
		connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ch, err := store.OpenClickHouse(connectCtx, store.ClickHouseConfig{
			DSN: cfg.ClickHouseDSN, EventTTLDays: cfg.EventTTLDays, DetectionTTLDays: cfg.DetectionTTLDays,
			DialTimeout: 5 * time.Second,
		})
		cancel()
		if err == nil {
			log.Info("clickhouse connected", "dsn", store.RedactDSN(cfg.ClickHouseDSN))
			return ch, nil
		}
		lastErr = err
		log.Warn("clickhouse not ready", "attempt", attempt+1, "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * time.Second):
		}
	}
	return nil, fmt.Errorf("clickhouse: %w", lastErr)
}

func openGeo(cfg config.Config, log *slog.Logger) (geo.Locator, func(), error) {
	var chain geo.Chain
	closer := func() {}
	if cfg.GeoCSV != "" {
		s, err := geo.LoadCSVFile(cfg.GeoCSV)
		if err != nil {
			return nil, nil, err
		}
		chain = append(chain, s)
		log.Info("geo csv loaded", "path", cfg.GeoCSV)
	}
	if cfg.GeoIPDB != "" {
		mm, err := geo.OpenMaxMind(cfg.GeoIPDB)
		if err != nil {
			return nil, nil, err
		}
		chain = append(chain, mm)
		closer = func() { _ = mm.Close() }
		log.Info("geoip database loaded", "path", cfg.GeoIPDB)
	}
	if len(chain) == 0 {
		log.Warn("no geolocation source configured; impossible travel and new-country rules need one")
		return geo.Nop{}, closer, nil
	}
	return chain, closer, nil
}

func sinks(cfg config.Config, log *slog.Logger) []alert.Sink {
	client := &http.Client{Timeout: 10 * time.Second}
	out := []alert.Sink{alert.LogSink{Logger: log}}
	if cfg.WebhookURL != "" {
		out = append(out, &alert.Webhook{URL: cfg.WebhookURL, Secret: cfg.WebhookSecret, Client: client})
	}
	if cfg.SlackWebhookURL != "" {
		out = append(out, &alert.Slack{URL: cfg.SlackWebhookURL, Client: client})
	}
	return out
}
