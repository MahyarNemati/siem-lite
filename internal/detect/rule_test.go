package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mahyarnemati/siem-lite/internal/event"
)

func TestRuleValidation(t *testing.T) {
	cases := map[string]string{
		"missing id":       "type: threshold\nthreshold: 1\nwindow: 1m\ngroup_by: [src_ip]",
		"bad type":         "id: x\ntype: magic\nwindow: 1m",
		"bad severity":     "id: x\ntype: threshold\nseverity: urgent\nthreshold: 1\nwindow: 1m\ngroup_by: [a]",
		"no window":        "id: x\ntype: threshold\nthreshold: 1\ngroup_by: [a]",
		"bad duration":     "id: x\ntype: threshold\nthreshold: 1\nwindow: soon\ngroup_by: [a]",
		"distinct field":   "id: x\ntype: distinct\nthreshold: 5\nwindow: 1m\ngroup_by: [a]",
		"bad modifier":     "id: x\ntype: threshold\nthreshold: 1\nwindow: 1m\ngroup_by: [a]\nselection: {user|fuzzy: x}",
		"bad regex":        "id: x\ntype: threshold\nthreshold: 1\nwindow: 1m\ngroup_by: [a]\nselection: {user|re: '('}",
		"bad number":       "id: x\ntype: threshold\nthreshold: 1\nwindow: 1m\ngroup_by: [a]\nselection: {bytes|gte: lots}",
		"unknown key":      "id: x\ntype: threshold\nthreshold: 1\nwindow: 1m\ngroup_by: [a]\nthreshhold: 2",
		"new_value fields": "id: x\ntype: new_value\nwindow: 1m",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRules(strings.NewReader(doc)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRuleDefaults(t *testing.T) {
	rules, err := ParseRules(strings.NewReader("id: travel\ntype: impossible_travel\nwindow: 1h"))
	if err != nil {
		t.Fatal(err)
	}
	r := rules[0]
	if r.MaxSpeedKmh != 900 || r.GroupBy[0] != "user" || r.Severity != "medium" || r.Title != "travel" {
		t.Fatalf("defaults: %+v", r)
	}
}

func TestSelectionModifiers(t *testing.T) {
	sel, err := compileSelection(map[string]any{
		"user|startswith":  []any{"adm", "root"},
		"http_path|re":     `^/api/v\d+/`,
		"http_status|gte":  400,
		"bytes|lt":         1000,
		"host|endswith":    ".prod",
		"src_ip|not":       "10.0.0.1",
		"fields.tenant":    "acme",
		"message|contains": "DENIED",
		"country|exists":   false,
		"http_method":      []any{"POST", "PUT"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ev := &event.Event{User: "administrator", HTTPPath: "/api/v2/users", HTTPStatus: 403, Bytes: 12,
		Host: "web.prod", SrcIP: "10.0.0.2", Fields: map[string]string{"tenant": "acme"},
		Message: "access denied", HTTPMethod: "post"}
	if !sel.matches(ev) {
		t.Fatal("expected match")
	}
	mut := []func(e *event.Event){
		func(e *event.Event) { e.User = "guest" },
		func(e *event.Event) { e.HTTPPath = "/api/latest" },
		func(e *event.Event) { e.HTTPStatus = 200 },
		func(e *event.Event) { e.Bytes = 5000 },
		func(e *event.Event) { e.Host = "web.dev" },
		func(e *event.Event) { e.SrcIP = "10.0.0.1" },
		func(e *event.Event) { e.Fields = nil },
		func(e *event.Event) { e.Message = "ok" },
		func(e *event.Event) { e.Country = "CA" },
		func(e *event.Event) { e.HTTPMethod = "GET" },
	}
	for i, m := range mut {
		cp := *ev
		m(&cp)
		if sel.matches(&cp) {
			t.Errorf("mutation %d should break the match", i)
		}
	}
}

func TestLoadDirDuplicate(t *testing.T) {
	dir := t.TempDir()
	doc := "id: dup\ntype: threshold\nthreshold: 1\nwindow: 1m\ngroup_by: [src_ip]\n"
	for _, name := range []string{"a.yml", "b.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestDisabledRuleSkipped(t *testing.T) {
	rules, err := ParseRules(strings.NewReader("id: off\ndisabled: true\ntype: threshold\nthreshold: 1\nwindow: 1m\ngroup_by: [src_ip]"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Rules()) != 0 {
		t.Fatal("disabled rule loaded")
	}
}

func TestMultiFieldGroupKey(t *testing.T) {
	rules, err := ParseRules(strings.NewReader("id: g\ntype: threshold\nthreshold: 2\nwindow: 1m\ngroup_by: [src_ip, user]"))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := NewEngine(rules)
	ev := &event.Event{SrcIP: "1.1.1.1", User: "a", Timestamp: t0}
	e.Process(ev)
	ds := e.Process(ev)
	if len(ds) != 1 || ds[0].GroupKey != "1.1.1.1|a" {
		t.Fatalf("got %+v", ds)
	}
	if ds := e.Process(&event.Event{SrcIP: "1.1.1.1", Timestamp: t0}); len(ds) != 0 {
		t.Fatal("partial key must be skipped")
	}
}
