package sim_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/clock"
	"github.com/mahyarnemati/siem-lite/internal/detect"
	"github.com/mahyarnemati/siem-lite/internal/geo"
	"github.com/mahyarnemati/siem-lite/internal/ingest"
	"github.com/mahyarnemati/siem-lite/internal/parser"
	"github.com/mahyarnemati/siem-lite/internal/pipeline"
	"github.com/mahyarnemati/siem-lite/internal/sim"
	"github.com/mahyarnemati/siem-lite/internal/store"
)

var start = time.Date(2026, 3, 15, 8, 0, 0, 0, time.UTC)

func newPipeline(t *testing.T) *pipeline.Pipeline {
	t.Helper()
	rules, err := detect.LoadDir(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := detect.NewEngine(rules, detect.WithClock(clock.NewFake(start)))
	if err != nil {
		t.Fatal(err)
	}
	g, err := geo.LoadCSVFile(filepath.Join("..", "..", "deploy", "geo", "demo-geo.csv"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := pipeline.New(pipeline.Config{Engine: e, Store: store.NewMemory(1), Geo: g})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func feed(t *testing.T, p *pipeline.Pipeline, lines []sim.Line) map[string]int {
	t.Helper()
	hits := map[string]int{}
	for _, l := range lines {
		f := parser.FormatSyslog
		if l.Kind == sim.JSON {
			f = parser.FormatJSON
		}
		_, ds, err := p.Process(ingest.Record{Format: f, Data: l.Data, Received: l.At, Transport: "test"})
		if err != nil {
			t.Fatalf("generated line failed to parse: %v\n%s", err, l.Data)
		}
		for _, d := range ds {
			hits[d.RuleID]++
		}
	}
	return hits
}

func TestBaselineIsQuiet(t *testing.T) {
	p := newPipeline(t)
	hits := feed(t, p, sim.New(1).Baseline(start, 24*time.Hour, 2000))
	if len(hits) != 0 {
		t.Fatalf("benign traffic produced detections: %v", hits)
	}
}

func TestEveryScenarioTriggersItsRule(t *testing.T) {
	for _, sc := range sim.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			p := newPipeline(t)
			g := sim.New(7)
			feed(t, p, g.Baseline(start, 6*time.Hour, 300))
			hits := feed(t, p, sc.Gen(g, start.Add(time.Minute)))
			if hits[sc.Rule] == 0 {
				t.Fatalf("scenario %s did not trigger %s (got %v)", sc.Name, sc.Rule, hits)
			}
		})
	}
}

func TestFind(t *testing.T) {
	if _, ok := sim.Find("web-scan"); !ok {
		t.Fatal("missing")
	}
	if _, ok := sim.Find("nope"); ok {
		t.Fatal("unexpected")
	}
}
