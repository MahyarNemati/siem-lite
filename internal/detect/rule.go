// Package detect implements the streaming detection engine: YAML rules,
// field matchers, and windowed detectors with snapshot support.
package detect

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mahyarnemati/siem-lite/internal/event"
)

// Rule types.
const (
	TypeThreshold        = "threshold"
	TypeDistinct         = "distinct"
	TypeImpossibleTravel = "impossible_travel"
	TypeNewValue         = "new_value"
)

// Severity levels, ordered.
var severities = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// Duration is a time.Duration that unmarshals from strings like "5m".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// Rule is the on-disk rule definition. The selection syntax borrows from
// Sigma: keys are field names with optional |modifiers, values are a scalar
// or a list (any-of). All keys must match. Filter uses the same syntax and
// excludes events that match it.
type Rule struct {
	ID            string         `yaml:"id"`
	Title         string         `yaml:"title"`
	Description   string         `yaml:"description"`
	Severity      string         `yaml:"severity"`
	Type          string         `yaml:"type"`
	Tags          []string       `yaml:"tags"`
	Selection     map[string]any `yaml:"selection"`
	Filter        map[string]any `yaml:"filter"`
	GroupBy       []string       `yaml:"group_by"`
	Field         string         `yaml:"field"`
	Threshold     int            `yaml:"threshold"`
	Window        Duration       `yaml:"window"`
	Suppress      Duration       `yaml:"suppress"`
	MaxSpeedKmh   float64        `yaml:"max_speed_kmh"`
	MinDistanceKm float64        `yaml:"min_distance_km"`
	MinHistory    int            `yaml:"min_history"`
	Disabled      bool           `yaml:"disabled"`
}

// Validate checks the rule for consistency and fills defaults.
func (r *Rule) Validate() error {
	var errs []error
	if r.ID == "" {
		errs = append(errs, errors.New("id is required"))
	}
	if r.Title == "" {
		r.Title = r.ID
	}
	if r.Severity == "" {
		r.Severity = "medium"
	}
	if _, ok := severities[r.Severity]; !ok {
		errs = append(errs, fmt.Errorf("unknown severity %q", r.Severity))
	}
	if r.Window <= 0 {
		errs = append(errs, errors.New("window must be > 0"))
	}
	switch r.Type {
	case TypeThreshold:
		if r.Threshold < 1 {
			errs = append(errs, errors.New("threshold must be >= 1"))
		}
		if len(r.GroupBy) == 0 {
			errs = append(errs, errors.New("group_by is required"))
		}
	case TypeDistinct:
		if r.Threshold < 2 {
			errs = append(errs, errors.New("threshold must be >= 2"))
		}
		if r.Field == "" || len(r.GroupBy) == 0 {
			errs = append(errs, errors.New("field and group_by are required"))
		}
	case TypeImpossibleTravel:
		if r.MaxSpeedKmh <= 0 {
			r.MaxSpeedKmh = 900
		}
		if len(r.GroupBy) == 0 {
			r.GroupBy = []string{"user"}
		}
	case TypeNewValue:
		if r.Field == "" || len(r.GroupBy) == 0 {
			errs = append(errs, errors.New("field and group_by are required"))
		}
	default:
		errs = append(errs, fmt.Errorf("unknown type %q", r.Type))
	}
	if _, err := compileSelection(r.Selection); err != nil {
		errs = append(errs, fmt.Errorf("selection: %w", err))
	}
	if _, err := compileSelection(r.Filter); err != nil {
		errs = append(errs, fmt.Errorf("filter: %w", err))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("rule %q: %w", r.ID, err)
	}
	return nil
}

// ParseRules decodes one or more YAML documents into rules.
func ParseRules(r io.Reader) ([]Rule, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var out []Rule
	for {
		var rule Rule
		err := dec.Decode(&rule)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if err := rule.Validate(); err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
}

// LoadDir reads every *.yml / *.yaml file in dir.
func LoadDir(dir string) ([]Rule, error) {
	var files []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return nil, err
		}
		files = append(files, m...)
	}
	sort.Strings(files)
	seen := map[string]string{}
	var out []Rule
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		rules, err := ParseRules(fh)
		fh.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, r := range rules {
			if prev, dup := seen[r.ID]; dup {
				return nil, fmt.Errorf("%s: duplicate rule id %q (first in %s)", f, r.ID, prev)
			}
			seen[r.ID] = f
		}
		out = append(out, rules...)
	}
	return out, nil
}

type matcher struct {
	field string
	match func(string) bool
	// negate is set by the "|not" modifier.
	negate bool
}

type selection []matcher

func (s selection) matches(ev *event.Event) bool {
	for _, m := range s {
		v, _ := ev.Get(m.field)
		if m.match(v) == m.negate {
			return false
		}
	}
	return true
}

func compileSelection(sel map[string]any) (selection, error) {
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(selection, 0, len(sel))
	for _, key := range keys {
		parts := strings.Split(key, "|")
		field, mods := parts[0], parts[1:]
		values, err := toStrings(sel[key])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		m := matcher{field: field}
		op := "eq"
		for _, mod := range mods {
			if mod == "not" {
				m.negate = true
				continue
			}
			op = mod
		}
		preds := make([]func(string) bool, 0, len(values))
		for _, v := range values {
			p, err := predicate(op, v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			preds = append(preds, p)
		}
		m.match = func(s string) bool {
			for _, p := range preds {
				if p(s) {
					return true
				}
			}
			return false
		}
		out = append(out, m)
	}
	return out, nil
}

func predicate(op, want string) (func(string) bool, error) {
	switch op {
	case "eq":
		return func(s string) bool { return strings.EqualFold(s, want) }, nil
	case "contains":
		w := strings.ToLower(want)
		return func(s string) bool { return strings.Contains(strings.ToLower(s), w) }, nil
	case "startswith":
		w := strings.ToLower(want)
		return func(s string) bool { return strings.HasPrefix(strings.ToLower(s), w) }, nil
	case "endswith":
		w := strings.ToLower(want)
		return func(s string) bool { return strings.HasSuffix(strings.ToLower(s), w) }, nil
	case "re":
		re, err := regexp.Compile(want)
		if err != nil {
			return nil, err
		}
		return re.MatchString, nil
	case "gte", "lte", "gt", "lt":
		n, err := strconv.ParseFloat(want, 64)
		if err != nil {
			return nil, fmt.Errorf("numeric modifier needs a number: %w", err)
		}
		return func(s string) bool {
			v, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return false
			}
			switch op {
			case "gte":
				return v >= n
			case "lte":
				return v <= n
			case "gt":
				return v > n
			default:
				return v < n
			}
		}, nil
	case "exists":
		exists := strings.EqualFold(want, "true")
		return func(s string) bool { return (s != "") == exists }, nil
	}
	return nil, fmt.Errorf("unknown modifier %q", op)
}

func toStrings(v any) ([]string, error) {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, err := scalar(e)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	default:
		s, err := scalar(t)
		if err != nil {
			return nil, err
		}
		return []string{s}, nil
	}
}

func scalar(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case int:
		return strconv.Itoa(t), nil
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(t), nil
	}
	return "", fmt.Errorf("unsupported value %v (%T)", v, v)
}
