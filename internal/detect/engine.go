package detect

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/clock"
	"github.com/mahyarnemati/siem-lite/internal/event"
)

// Detection is a rule hit produced by the engine.
type Detection struct {
	RuleID      string        `json:"rule_id"`
	Title       string        `json:"title"`
	Severity    string        `json:"severity"`
	Tags        []string      `json:"tags,omitempty"`
	GroupKey    string        `json:"group_key"`
	Count       int           `json:"count"`
	FirstSeen   time.Time     `json:"first_seen"`
	LastSeen    time.Time     `json:"last_seen"`
	DetectedAt  time.Time     `json:"detected_at"`
	Summary     string        `json:"summary"`
	Values      []string      `json:"values,omitempty"`
	SrcIP       string        `json:"src_ip,omitempty"`
	User        string        `json:"user,omitempty"`
	Suppress    time.Duration `json:"-"`
	Description string        `json:"description,omitempty"`
}

type compiledRule struct {
	Rule
	sel    selection
	filter selection

	mu  sync.Mutex
	det detector
}

// Engine evaluates events against a rule set.
type Engine struct {
	rules   []*compiledRule
	clock   clock.Clock
	maxKeys int
	log     *slog.Logger

	evicted atomic.Int64
}

// Option configures an Engine.
type Option func(*Engine)

// WithClock overrides the wall clock.
func WithClock(c clock.Clock) Option { return func(e *Engine) { e.clock = c } }

// WithMaxKeys bounds the number of tracked groups per rule.
func WithMaxKeys(n int) Option { return func(e *Engine) { e.maxKeys = n } }

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option { return func(e *Engine) { e.log = l } }

// NewEngine compiles rules. Disabled rules are skipped.
func NewEngine(rules []Rule, opts ...Option) (*Engine, error) {
	e := &Engine{clock: clock.Real{}, maxKeys: 100_000, log: slog.New(slog.DiscardHandler)}
	for _, o := range opts {
		o(e)
	}
	for i := range rules {
		r := rules[i]
		if err := r.Validate(); err != nil {
			return nil, err
		}
		if r.Disabled {
			continue
		}
		sel, _ := compileSelection(r.Selection)
		filter, _ := compileSelection(r.Filter)
		cr := &compiledRule{Rule: r, sel: sel, filter: filter}
		cr.det = newDetector(&cr.Rule)
		e.rules = append(e.rules, cr)
	}
	return e, nil
}

// Rules returns the IDs of active rules.
func (e *Engine) Rules() []string {
	out := make([]string, len(e.rules))
	for i, r := range e.rules {
		out[i] = r.ID
	}
	return out
}

// Process evaluates one event and returns any detections.
func (e *Engine) Process(ev *event.Event) []Detection {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = e.clock.Now()
	}
	var out []Detection
	for _, r := range e.rules {
		if !r.sel.matches(ev) {
			continue
		}
		if len(r.filter) > 0 && r.filter.matches(ev) {
			continue
		}
		key, ok := groupKey(ev, r.GroupBy)
		if !ok {
			continue
		}
		r.mu.Lock()
		if r.det.size() >= e.maxKeys {
			if r.det.gc(e.clock.Now()) == 0 {
				r.det.evictOldest()
				e.evicted.Add(1)
			}
		}
		d, fired := r.det.observe(ev, key)
		r.mu.Unlock()
		if !fired {
			continue
		}
		d.RuleID, d.Title, d.Severity, d.Tags = r.ID, r.Title, r.Severity, r.Tags
		d.Description = r.Description
		d.GroupKey = key
		d.DetectedAt = e.clock.Now()
		d.Suppress = time.Duration(r.Suppress)
		d.SrcIP, d.User = ev.SrcIP, ev.User
		out = append(out, d)
	}
	return out
}

// GC drops idle state across all rules and returns the number of groups removed.
func (e *Engine) GC() int {
	now := e.clock.Now()
	n := 0
	for _, r := range e.rules {
		r.mu.Lock()
		n += r.det.gc(now)
		r.mu.Unlock()
	}
	return n
}

// Stats reports per-rule tracked groups.
func (e *Engine) Stats() map[string]int {
	out := make(map[string]int, len(e.rules))
	for _, r := range e.rules {
		r.mu.Lock()
		out[r.ID] = r.det.size()
		r.mu.Unlock()
	}
	return out
}

func groupKey(ev *event.Event, fields []string) (string, bool) {
	if len(fields) == 1 {
		return ev.Get(fields[0])
	}
	parts := make([]string, len(fields))
	for i, f := range fields {
		v, ok := ev.Get(f)
		if !ok {
			return "", false
		}
		parts[i] = v
	}
	return strings.Join(parts, "|"), true
}

const snapshotVersion = 1

type snapshot struct {
	Version int                     `json:"version"`
	TakenAt time.Time               `json:"taken_at"`
	Rules   map[string]ruleSnapshot `json:"rules"`
}

type ruleSnapshot struct {
	Type  string          `json:"type"`
	State json.RawMessage `json:"state"`
}

// Snapshot writes the in-memory window state as JSON.
func (e *Engine) Snapshot(w io.Writer) error {
	s := snapshot{Version: snapshotVersion, TakenAt: e.clock.Now(), Rules: map[string]ruleSnapshot{}}
	for _, r := range e.rules {
		r.mu.Lock()
		b, err := r.det.marshal()
		r.mu.Unlock()
		if err != nil {
			return fmt.Errorf("snapshot %s: %w", r.ID, err)
		}
		s.Rules[r.ID] = ruleSnapshot{Type: r.Type, State: b}
	}
	return json.NewEncoder(w).Encode(s)
}

// Restore loads state written by Snapshot. Rules that no longer exist or
// changed type are skipped; idle state is dropped via GC afterwards.
func (e *Engine) Restore(r io.Reader) error {
	var s snapshot
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if s.Version != snapshotVersion {
		return fmt.Errorf("restore: unsupported snapshot version %d", s.Version)
	}
	for _, cr := range e.rules {
		rs, ok := s.Rules[cr.ID]
		if !ok || rs.Type != cr.Type {
			continue
		}
		fresh := newDetector(&cr.Rule)
		if err := fresh.unmarshal(rs.State); err != nil {
			return fmt.Errorf("restore %s: %w", cr.ID, err)
		}
		cr.mu.Lock()
		cr.det = fresh
		cr.mu.Unlock()
	}
	e.GC()
	return nil
}

// SaveSnapshot atomically writes a snapshot to path.
func (e *Engine) SaveSnapshot(path string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".snapshot-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := e.Snapshot(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// LoadSnapshot restores from path. A missing file is not an error.
func (e *Engine) LoadSnapshot(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	return e.Restore(f)
}
