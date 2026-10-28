// Package metrics defines the Prometheus instruments exported by siem-lite.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics groups every instrument so it can be injected and tested with a
// private registry.
type Metrics struct {
	Registry      *prometheus.Registry
	Received      *prometheus.CounterVec
	Dropped       *prometheus.CounterVec
	ParseErrors   *prometheus.CounterVec
	EventsStored  prometheus.Counter
	StoreErrors   *prometheus.CounterVec
	Detections    *prometheus.CounterVec
	QueueDepth    prometheus.GaugeFunc
	FlushDuration prometheus.Histogram
}

// New registers all instruments on a fresh registry. queueDepth may be nil.
func New(queueDepth func() float64) *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := &Metrics{
		Registry: reg,
		Received: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "siem_records_received_total", Help: "Raw records received by transport.",
		}, []string{"transport"}),
		Dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "siem_records_dropped_total", Help: "Records dropped before processing.",
		}, []string{"reason"}),
		ParseErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "siem_parse_errors_total", Help: "Records that failed to parse.",
		}, []string{"format"}),
		EventsStored: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "siem_events_stored_total", Help: "Events written to the store.",
		}),
		StoreErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "siem_store_errors_total", Help: "Failed store writes.",
		}, []string{"kind"}),
		Detections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "siem_detections_total", Help: "Rule detections.",
		}, []string{"rule", "severity"}),
		FlushDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "siem_store_flush_seconds", Help: "Store batch flush latency.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 14),
		}),
	}
	reg.MustRegister(m.Received, m.Dropped, m.ParseErrors, m.EventsStored, m.StoreErrors, m.Detections, m.FlushDuration)
	if queueDepth != nil {
		m.QueueDepth = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "siem_pipeline_queue_depth", Help: "Records waiting to be processed.",
		}, queueDepth)
		reg.MustRegister(m.QueueDepth)
	}
	return m
}
