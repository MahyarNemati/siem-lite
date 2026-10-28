package detect

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/event"
	"github.com/mahyarnemati/siem-lite/internal/geo"
)

// detector holds per-rule state. Implementations are not safe for concurrent
// use; the engine serializes access per rule.
type detector interface {
	observe(ev *event.Event, key string) (Detection, bool)
	// gc drops state that has been idle for longer than the rule retains it.
	gc(now time.Time) int
	size() int
	evictOldest()
	marshal() ([]byte, error)
	unmarshal([]byte) error
}

func newDetector(r *Rule) detector {
	switch r.Type {
	case TypeThreshold:
		return &thresholdDetector{rule: r, keys: map[string][]time.Time{}}
	case TypeDistinct:
		return &distinctDetector{rule: r, keys: map[string]map[string]time.Time{}}
	case TypeImpossibleTravel:
		return &travelDetector{rule: r, last: map[string]travelPoint{}}
	case TypeNewValue:
		return &newValueDetector{rule: r, keys: map[string]*valueHistory{}}
	}
	panic("unreachable: rule type validated at load")
}

// thresholdDetector fires when a group sees at least Threshold matching
// events inside a sliding window.
type thresholdDetector struct {
	rule *Rule
	keys map[string][]time.Time
}

func (d *thresholdDetector) observe(ev *event.Event, key string) (Detection, bool) {
	win := time.Duration(d.rule.Window)
	ts := insertSorted(d.keys[key], ev.Timestamp)
	ts = trimBefore(ts, ev.Timestamp.Add(-win))
	if len(ts) >= d.rule.Threshold {
		delete(d.keys, key)
		return Detection{
			Count:     len(ts),
			FirstSeen: ts[0],
			LastSeen:  ts[len(ts)-1],
			Summary:   fmt.Sprintf("%d matching events in %s", len(ts), win),
		}, true
	}
	d.keys[key] = ts
	return Detection{}, false
}

func (d *thresholdDetector) gc(now time.Time) int {
	cut := now.Add(-time.Duration(d.rule.Window))
	n := 0
	for k, ts := range d.keys {
		if len(ts) == 0 || ts[len(ts)-1].Before(cut) {
			delete(d.keys, k)
			n++
		}
	}
	return n
}

func (d *thresholdDetector) size() int { return len(d.keys) }

func (d *thresholdDetector) evictOldest() {
	evictBy(d.keys, func(ts []time.Time) time.Time { return ts[len(ts)-1] })
}

func (d *thresholdDetector) marshal() ([]byte, error) { return json.Marshal(d.keys) }
func (d *thresholdDetector) unmarshal(b []byte) error { return json.Unmarshal(b, &d.keys) }

// distinctDetector fires when a group sees at least Threshold distinct
// values of Field inside the window, e.g. one IP trying many usernames.
type distinctDetector struct {
	rule *Rule
	keys map[string]map[string]time.Time
}

func (d *distinctDetector) observe(ev *event.Event, key string) (Detection, bool) {
	val, ok := ev.Get(d.rule.Field)
	if !ok {
		return Detection{}, false
	}
	vals := d.keys[key]
	if vals == nil {
		vals = map[string]time.Time{}
		d.keys[key] = vals
	}
	if prev, seen := vals[val]; !seen || ev.Timestamp.After(prev) {
		vals[val] = ev.Timestamp
	}
	cut := ev.Timestamp.Add(-time.Duration(d.rule.Window))
	first := ev.Timestamp
	for v, t := range vals {
		if t.Before(cut) {
			delete(vals, v)
			continue
		}
		if t.Before(first) {
			first = t
		}
	}
	if len(vals) < d.rule.Threshold {
		return Detection{}, false
	}
	sample := make([]string, 0, len(vals))
	for v := range vals {
		sample = append(sample, v)
	}
	sort.Strings(sample)
	if len(sample) > 10 {
		sample = sample[:10]
	}
	delete(d.keys, key)
	return Detection{
		Count:     len(vals),
		FirstSeen: first,
		LastSeen:  ev.Timestamp,
		Summary:   fmt.Sprintf("%d distinct %s values in %s", len(vals), d.rule.Field, time.Duration(d.rule.Window)),
		Values:    sample,
	}, true
}

func (d *distinctDetector) gc(now time.Time) int {
	cut := now.Add(-time.Duration(d.rule.Window))
	n := 0
	for k, vals := range d.keys {
		if latest(vals).Before(cut) {
			delete(d.keys, k)
			n++
		}
	}
	return n
}

func (d *distinctDetector) size() int { return len(d.keys) }
func (d *distinctDetector) evictOldest() {
	evictBy(d.keys, latest)
}
func (d *distinctDetector) marshal() ([]byte, error) { return json.Marshal(d.keys) }
func (d *distinctDetector) unmarshal(b []byte) error { return json.Unmarshal(b, &d.keys) }

// travelPoint is the last geolocated successful login for a group.
type travelPoint struct {
	TS      time.Time `json:"ts"`
	IP      string    `json:"ip"`
	Country string    `json:"country"`
	City    string    `json:"city"`
	Lat     float64   `json:"lat"`
	Lon     float64   `json:"lon"`
}

// travelDetector fires when two consecutive logins imply a ground speed
// above MaxSpeedKmh. Window bounds how long a previous login is remembered.
type travelDetector struct {
	rule *Rule
	last map[string]travelPoint
}

func (d *travelDetector) observe(ev *event.Event, key string) (Detection, bool) {
	if !ev.HasGeo() {
		return Detection{}, false
	}
	cur := travelPoint{TS: ev.Timestamp, IP: ev.SrcIP, Country: ev.Country, City: ev.City, Lat: ev.Lat, Lon: ev.Lon}
	prev, ok := d.last[key]
	if !ok || cur.TS.After(prev.TS) {
		d.last[key] = cur
	}
	if !ok || ev.Timestamp.Sub(prev.TS).Abs() > time.Duration(d.rule.Window) {
		return Detection{}, false
	}
	dist := geo.DistanceKm(prev.Lat, prev.Lon, cur.Lat, cur.Lon)
	if dist < d.rule.MinDistanceKm || dist == 0 {
		return Detection{}, false
	}
	hours := ev.Timestamp.Sub(prev.TS).Abs().Hours()
	speed := math.Inf(1)
	if hours > 0 {
		speed = dist / hours
	}
	if speed <= d.rule.MaxSpeedKmh {
		return Detection{}, false
	}
	first, last := prev, cur
	if cur.TS.Before(prev.TS) {
		first, last = cur, prev
	}
	speedText := "instantaneous"
	if !math.IsInf(speed, 1) {
		speedText = fmt.Sprintf("%.0f km/h", speed)
	}
	return Detection{
		Count:     2,
		FirstSeen: first.TS,
		LastSeen:  last.TS,
		Summary: fmt.Sprintf("%s (%s) -> %s (%s): %.0f km in %s, %s",
			first.IP, place(first), last.IP, place(last), dist,
			last.TS.Sub(first.TS).Round(time.Second), speedText),
		Values: []string{first.Country, last.Country},
	}, true
}

func place(p travelPoint) string {
	if p.City != "" {
		return p.City + ", " + p.Country
	}
	return p.Country
}

func (d *travelDetector) gc(now time.Time) int {
	cut := now.Add(-time.Duration(d.rule.Window))
	n := 0
	for k, p := range d.last {
		if p.TS.Before(cut) {
			delete(d.last, k)
			n++
		}
	}
	return n
}

func (d *travelDetector) size() int { return len(d.last) }
func (d *travelDetector) evictOldest() {
	evictBy(d.last, func(p travelPoint) time.Time { return p.TS })
}
func (d *travelDetector) marshal() ([]byte, error) { return json.Marshal(d.last) }
func (d *travelDetector) unmarshal(b []byte) error { return json.Unmarshal(b, &d.last) }

// valueHistory is the baseline of values seen for one group.
type valueHistory struct {
	Seen  map[string]time.Time `json:"seen"`
	Count int                  `json:"count"`
}

const maxValuesPerKey = 64

// newValueDetector fires when a group with an established baseline (at least
// MinHistory prior events) produces a value it has not been seen with inside
// the retention window, such as a login from a new country or device.
type newValueDetector struct {
	rule *Rule
	keys map[string]*valueHistory
}

func (d *newValueDetector) observe(ev *event.Event, key string) (Detection, bool) {
	val, ok := ev.Get(d.rule.Field)
	if !ok {
		return Detection{}, false
	}
	h := d.keys[key]
	if h == nil {
		h = &valueHistory{Seen: map[string]time.Time{}}
		d.keys[key] = h
	}
	cut := ev.Timestamp.Add(-time.Duration(d.rule.Window))
	for v, t := range h.Seen {
		if t.Before(cut) {
			delete(h.Seen, v)
		}
	}
	_, known := h.Seen[val]
	fire := !known && len(h.Seen) > 0 && h.Count >= d.rule.MinHistory

	h.Count++
	if prev, ok := h.Seen[val]; !ok || ev.Timestamp.After(prev) {
		h.Seen[val] = ev.Timestamp
	}
	if len(h.Seen) > maxValuesPerKey {
		evictBy(h.Seen, func(t time.Time) time.Time { return t })
	}
	if !fire {
		return Detection{}, false
	}
	known2 := make([]string, 0, len(h.Seen))
	for v := range h.Seen {
		if v != val {
			known2 = append(known2, v)
		}
	}
	sort.Strings(known2)
	return Detection{
		Count:     1,
		FirstSeen: ev.Timestamp,
		LastSeen:  ev.Timestamp,
		Summary:   fmt.Sprintf("new %s %q (previously: %v)", d.rule.Field, val, known2),
		Values:    []string{val},
	}, true
}

func (d *newValueDetector) gc(now time.Time) int {
	cut := now.Add(-time.Duration(d.rule.Window))
	n := 0
	for k, h := range d.keys {
		if latest(h.Seen).Before(cut) {
			delete(d.keys, k)
			n++
		}
	}
	return n
}

func (d *newValueDetector) size() int { return len(d.keys) }
func (d *newValueDetector) evictOldest() {
	evictBy(d.keys, func(h *valueHistory) time.Time { return latest(h.Seen) })
}
func (d *newValueDetector) marshal() ([]byte, error) { return json.Marshal(d.keys) }
func (d *newValueDetector) unmarshal(b []byte) error { return json.Unmarshal(b, &d.keys) }

func insertSorted(ts []time.Time, t time.Time) []time.Time {
	i := sort.Search(len(ts), func(i int) bool { return ts[i].After(t) })
	ts = append(ts, time.Time{})
	copy(ts[i+1:], ts[i:])
	ts[i] = t
	return ts
}

func trimBefore(ts []time.Time, cut time.Time) []time.Time {
	i := sort.Search(len(ts), func(i int) bool { return !ts[i].Before(cut) })
	if i == 0 {
		return ts
	}
	return append(ts[:0], ts[i:]...)
}

func latest(m map[string]time.Time) time.Time {
	var out time.Time
	for _, t := range m {
		if t.After(out) {
			out = t
		}
	}
	return out
}

func evictBy[V any](m map[string]V, at func(V) time.Time) {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, v := range m {
		if t := at(v); first || t.Before(oldest) {
			oldestKey, oldest, first = k, t, false
		}
	}
	if !first {
		delete(m, oldestKey)
	}
}
