// Package api exposes the HTTP surface: ingest, detections, health and metrics.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mahyarnemati/siem-lite/internal/detect"
	"github.com/mahyarnemati/siem-lite/internal/ingest"
	"github.com/mahyarnemati/siem-lite/internal/store"
)

// Deps are the collaborators the API needs.
type Deps struct {
	Ingest     http.Handler
	Store      store.Store
	Engine     *detect.Engine
	Registry   *prometheus.Registry
	AlertStats func() map[string]int64
	Logger     *slog.Logger
	// Now is overridable for tests.
	Now func() time.Time
}

// New builds the router.
func New(d Deps) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	mux := http.NewServeMux()
	mux.Handle("POST /v1/ingest", d.Ingest)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := d.Store.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": "store unreachable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /v1/detections", func(w http.ResponseWriter, r *http.Request) {
		since := time.Hour
		if s := r.URL.Query().Get("since"); s != "" {
			v, err := time.ParseDuration(s)
			if err != nil || v <= 0 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "since must be a positive duration like 1h"})
				return
			}
			since = v
		}
		limit := 100
		if s := r.URL.Query().Get("limit"); s != "" {
			v, err := strconv.Atoi(s)
			if err != nil || v < 1 || v > 1000 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be 1..1000"})
				return
			}
			limit = v
		}
		ds, err := d.Store.RecentDetections(r.Context(), d.Now().Add(-since), limit)
		if err != nil {
			d.Logger.Error("list detections", "err", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "store query failed"})
			return
		}
		if ds == nil {
			ds = []detect.Detection{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"detections": ds})
	})
	mux.HandleFunc("GET /v1/rules", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"rules": d.Engine.Rules(), "tracked_groups": d.Engine.Stats()})
	})
	mux.HandleFunc("GET /v1/stats", func(w http.ResponseWriter, _ *http.Request) {
		out := map[string]any{"tracked_groups": d.Engine.Stats()}
		if d.AlertStats != nil {
			out["alerts"] = d.AlertStats()
		}
		writeJSON(w, http.StatusOK, out)
	})
	if d.Registry != nil {
		mux.Handle("GET /metrics", promhttp.HandlerFor(d.Registry, promhttp.HandlerOpts{}))
	}
	return mux
}

// IngestHandler adapts an ingest.Handler for HTTP intake.
func IngestHandler(h ingest.Handler, token string, maxBody int64) http.Handler {
	return &ingest.HTTPHandler{Handler: h, Token: token, MaxBody: maxBody}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
