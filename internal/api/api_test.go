package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mahyarnemati/siem-lite/internal/detect"
	"github.com/mahyarnemati/siem-lite/internal/store"
)

type downStore struct{ *store.Memory }

func (downStore) Ping(context.Context) error { return errors.New("down") }
func (downStore) RecentDetections(context.Context, time.Time, int) ([]detect.Detection, error) {
	return nil, errors.New("down")
}

func newServer(t *testing.T, s store.Store) *httptest.Server {
	t.Helper()
	rules, err := detect.ParseRules(strings.NewReader("id: r\ntype: threshold\nthreshold: 2\nwindow: 1m\ngroup_by: [src_ip]"))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := detect.NewEngine(rules)
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	h := New(Deps{
		Ingest: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }),
		Store:  s, Engine: e, Registry: prometheus.NewRegistry(),
		AlertStats: func() map[string]int64 { return map[string]int64{"sent": 1} },
		Now:        func() time.Time { return now },
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func TestRoutes(t *testing.T) {
	mem := store.NewMemory(0)
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	_ = mem.InsertDetections(context.Background(), []detect.Detection{
		{RuleID: "recent", DetectedAt: now.Add(-10 * time.Minute)},
		{RuleID: "old", DetectedAt: now.Add(-2 * time.Hour)},
	})
	srv := newServer(t, mem)

	if code, _ := get(t, srv.URL+"/healthz"); code != 200 {
		t.Fatal("healthz")
	}
	if code, _ := get(t, srv.URL+"/readyz"); code != 200 {
		t.Fatal("readyz")
	}
	code, body := get(t, srv.URL+"/v1/detections")
	if code != 200 || len(body["detections"].([]any)) != 1 {
		t.Fatalf("detections default window: %d %v", code, body)
	}
	_, body = get(t, srv.URL+"/v1/detections?since=3h&limit=5")
	if len(body["detections"].([]any)) != 2 {
		t.Fatalf("since=3h: %v", body)
	}
	for _, q := range []string{"since=x", "since=-1h", "limit=0", "limit=5000"} {
		if code, _ := get(t, srv.URL+"/v1/detections?"+q); code != 400 {
			t.Errorf("%s: %d", q, code)
		}
	}
	_, body = get(t, srv.URL+"/v1/rules")
	if len(body["rules"].([]any)) != 1 {
		t.Fatalf("rules %v", body)
	}
	_, body = get(t, srv.URL+"/v1/stats")
	if body["alerts"].(map[string]any)["sent"].(float64) != 1 {
		t.Fatalf("stats %v", body)
	}
	resp, err := http.Post(srv.URL+"/v1/ingest", "application/json", strings.NewReader("{}"))
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("ingest %v %v", resp, err)
	}
	resp.Body.Close()
	if code, _ := get(t, srv.URL+"/metrics"); code != 200 {
		t.Fatal("metrics")
	}
}

func TestStoreDown(t *testing.T) {
	srv := newServer(t, downStore{store.NewMemory(0)})
	if code, _ := get(t, srv.URL+"/readyz"); code != 503 {
		t.Fatalf("readyz %d", code)
	}
	if code, _ := get(t, srv.URL+"/v1/detections"); code != 502 {
		t.Fatalf("detections %d", code)
	}
}
