package detect

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/clock"
	"github.com/mahyarnemati/siem-lite/internal/event"
)

var t0 = time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)

// shippedEngine loads the production rule set so tests cover the rules
// that actually ship, not copies of them.
func shippedEngine(t *testing.T, ids ...string) (*Engine, *clock.Fake) {
	t.Helper()
	rules, err := LoadDir(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) > 0 {
		want := map[string]bool{}
		for _, id := range ids {
			want[id] = true
		}
		var keep []Rule
		for _, r := range rules {
			if want[r.ID] {
				keep = append(keep, r)
			}
		}
		if len(keep) != len(ids) {
			t.Fatalf("rules %v not all found", ids)
		}
		rules = keep
	}
	clk := clock.NewFake(t0)
	e, err := NewEngine(rules, WithClock(clk))
	if err != nil {
		t.Fatal(err)
	}
	return e, clk
}

func authFail(clk *clock.Fake, ip, user string) *event.Event {
	return &event.Event{Timestamp: clk.Now(), Source: "sshd", Category: event.CategoryAuth, Outcome: event.OutcomeFailure, SrcIP: ip, User: user}
}

func authOK(clk *clock.Fake, user, ip, country, device string, lat, lon float64) *event.Event {
	return &event.Event{Timestamp: clk.Now(), Source: "json", Category: event.CategoryAuth, Outcome: event.OutcomeSuccess,
		User: user, SrcIP: ip, Country: country, Device: device, Lat: lat, Lon: lon}
}

func web(clk *clock.Fake, ip, path string, status int) *event.Event {
	return &event.Event{Timestamp: clk.Now(), Source: "nginx", Category: event.CategoryWeb, SrcIP: ip, HTTPPath: path, HTTPStatus: status}
}

func fired(ds []Detection, id string) *Detection {
	for i := range ds {
		if ds[i].RuleID == id {
			return &ds[i]
		}
	}
	return nil
}

func TestShippedRulesLoad(t *testing.T) {
	e, _ := shippedEngine(t)
	if got := len(e.Rules()); got != 8 {
		t.Fatalf("expected 8 rules, got %d: %v", got, e.Rules())
	}
}

func TestBruteforceIP(t *testing.T) {
	e, clk := shippedEngine(t, "auth-bruteforce-ip")
	for i := range 9 {
		if ds := e.Process(authFail(clk, "203.0.113.9", fmt.Sprintf("u%d", i%2))); len(ds) != 0 {
			t.Fatalf("fired early at %d", i)
		}
		clk.Advance(20 * time.Second)
	}
	ds := e.Process(authFail(clk, "203.0.113.9", "root"))
	d := fired(ds, "auth-bruteforce-ip")
	if d == nil {
		t.Fatal("expected detection on 10th failure")
	}
	if d.Count != 10 || d.GroupKey != "203.0.113.9" || d.Severity != "high" {
		t.Fatalf("detection: %+v", d)
	}
	if !d.FirstSeen.Equal(t0) || !d.LastSeen.Equal(clk.Now()) {
		t.Fatalf("window bounds: %v - %v", d.FirstSeen, d.LastSeen)
	}
	// Window resets after firing.
	if ds := e.Process(authFail(clk, "203.0.113.9", "root")); len(ds) != 0 {
		t.Fatal("should not refire immediately")
	}
}

func TestBruteforceIPSlidingWindowExpires(t *testing.T) {
	e, clk := shippedEngine(t, "auth-bruteforce-ip")
	for range 30 {
		if ds := e.Process(authFail(clk, "198.51.100.1", "root")); len(ds) != 0 {
			t.Fatal("slow attempts must not fire")
		}
		clk.Advance(35 * time.Second) // any 10 attempts span > 5m
	}
}

func TestBruteforceIPIgnoresSuccessAndOtherIPs(t *testing.T) {
	e, clk := shippedEngine(t, "auth-bruteforce-ip")
	for i := range 20 {
		ev := authFail(clk, fmt.Sprintf("192.0.2.%d", i), "root")
		if ds := e.Process(ev); len(ds) != 0 {
			t.Fatal("distinct IPs must not aggregate")
		}
		ok := authOK(clk, "root", "192.0.2.200", "", "", 0, 0)
		if ds := e.Process(ok); len(ds) != 0 {
			t.Fatal("successes must not count")
		}
	}
}

func TestBruteforceUser(t *testing.T) {
	e, clk := shippedEngine(t, "auth-bruteforce-user")
	var hit *Detection
	for i := range 20 {
		ds := e.Process(authFail(clk, fmt.Sprintf("192.0.2.%d", i), "admin"))
		hit = fired(ds, "auth-bruteforce-user")
		clk.Advance(10 * time.Second)
	}
	if hit == nil || hit.GroupKey != "admin" || hit.Count != 20 {
		t.Fatalf("expected per-user detection, got %+v", hit)
	}
	// Events without a user cannot be attributed.
	for range 50 {
		if ds := e.Process(authFail(clk, "192.0.2.1", "")); len(ds) != 0 {
			t.Fatal("empty user must be filtered")
		}
	}
}

func TestPasswordSpray(t *testing.T) {
	e, clk := shippedEngine(t, "auth-password-spray")
	users := []string{"alice", "bob", "carol", "dave"}
	for _, u := range users {
		for range 2 { // repeats of the same user do not count twice
			if ds := e.Process(authFail(clk, "203.0.113.50", u)); len(ds) != 0 {
				t.Fatalf("fired early on %s", u)
			}
			clk.Advance(30 * time.Second)
		}
	}
	ds := e.Process(authFail(clk, "203.0.113.50", "erin"))
	d := fired(ds, "auth-password-spray")
	if d == nil {
		t.Fatal("expected spray detection")
	}
	if d.Count != 5 || strings.Join(d.Values, ",") != "alice,bob,carol,dave,erin" {
		t.Fatalf("detection: %+v", d)
	}
}

func TestPasswordSprayWindow(t *testing.T) {
	e, clk := shippedEngine(t, "auth-password-spray")
	for i := range 12 {
		if ds := e.Process(authFail(clk, "203.0.113.51", fmt.Sprintf("user%d", i))); len(ds) != 0 {
			t.Fatalf("spread-out attempts must not fire (i=%d)", i)
		}
		clk.Advance(3 * time.Minute) // only ~4 distinct users per 10m window
	}
}

func TestImpossibleTravel(t *testing.T) {
	e, clk := shippedEngine(t, "auth-impossible-travel")
	if ds := e.Process(authOK(clk, "alice", "198.51.100.10", "CA", "", 43.65, -79.38)); len(ds) != 0 {
		t.Fatal("first login cannot be impossible")
	}
	clk.Advance(2 * time.Hour)
	ds := e.Process(authOK(clk, "alice", "203.0.113.20", "AU", "", -33.87, 151.21))
	d := fired(ds, "auth-impossible-travel")
	if d == nil {
		t.Fatal("Toronto to Sydney in 2h should fire")
	}
	if d.GroupKey != "alice" || !strings.Contains(d.Summary, "km/h") || strings.Join(d.Values, ">") != "CA>AU" {
		t.Fatalf("detection: %+v", d)
	}
}

func TestImpossibleTravelPlausible(t *testing.T) {
	e, clk := shippedEngine(t, "auth-impossible-travel")
	e.Process(authOK(clk, "bob", "198.51.100.10", "CA", "", 43.65, -79.38))
	clk.Advance(20 * time.Hour) // ~777 km/h, a long-haul flight
	if ds := e.Process(authOK(clk, "bob", "203.0.113.20", "AU", "", -33.87, 151.21)); len(ds) != 0 {
		t.Fatalf("plausible travel fired: %+v", ds)
	}
	// Short hops below min_distance_km never fire, even instantly.
	e.Process(authOK(clk, "bob", "203.0.113.21", "AU", "", -33.80, 151.10))
	clk.Advance(time.Second)
	if ds := e.Process(authOK(clk, "bob", "203.0.113.22", "AU", "", -34.0, 151.0)); len(ds) != 0 {
		t.Fatal("short hop fired")
	}
	// Logins without geo are ignored.
	if ds := e.Process(authOK(clk, "bob", "10.0.0.1", "", "", 0, 0)); len(ds) != 0 {
		t.Fatal("no-geo login fired")
	}
}

func TestImpossibleTravelForgetsAfterWindow(t *testing.T) {
	e, clk := shippedEngine(t, "auth-impossible-travel")
	e.Process(authOK(clk, "carol", "198.51.100.10", "CA", "", 43.65, -79.38))
	clk.Advance(25 * time.Hour)
	if n := e.GC(); n != 1 {
		t.Fatalf("gc removed %d", n)
	}
	if ds := e.Process(authOK(clk, "carol", "203.0.113.20", "AU", "", -33.87, 151.21)); len(ds) != 0 {
		t.Fatal("expired baseline must not fire")
	}
}

func TestNewCountry(t *testing.T) {
	e, clk := shippedEngine(t, "auth-new-country")
	// Building the baseline (min_history: 3) never fires, even on new values.
	for _, c := range []string{"CA", "CA", "US"} {
		if ds := e.Process(authOK(clk, "dave", "198.51.100.1", c, "", 0, 0)); len(ds) != 0 {
			t.Fatalf("fired during learning on %s", c)
		}
		clk.Advance(time.Hour)
	}
	if ds := e.Process(authOK(clk, "dave", "198.51.100.1", "US", "", 0, 0)); len(ds) != 0 {
		t.Fatal("known country fired")
	}
	ds := e.Process(authOK(clk, "dave", "203.0.113.1", "RU", "", 0, 0))
	d := fired(ds, "auth-new-country")
	if d == nil || d.Values[0] != "RU" || !strings.Contains(d.Summary, "[CA US]") {
		t.Fatalf("expected new country detection, got %+v", d)
	}
	// Missing country does not match the selection.
	if ds := e.Process(authOK(clk, "dave", "10.0.0.1", "", "", 0, 0)); len(ds) != 0 {
		t.Fatal("no-country event fired")
	}
}

func TestNewCountryBaselineAgesOut(t *testing.T) {
	e, clk := shippedEngine(t, "auth-new-country")
	for range 4 {
		e.Process(authOK(clk, "erin", "198.51.100.1", "CA", "", 0, 0))
	}
	e.Process(authOK(clk, "erin", "198.51.100.1", "FR", "", 0, 0))
	clk.Advance(31 * 24 * time.Hour)
	e.Process(authOK(clk, "erin", "198.51.100.1", "CA", "", 0, 0))
	clk.Advance(time.Hour)
	// FR aged out of the 30-day window so it is new again.
	if ds := e.Process(authOK(clk, "erin", "198.51.100.1", "FR", "", 0, 0)); fired(ds, "auth-new-country") == nil {
		t.Fatal("aged-out value should be new")
	}
}

func TestNewDevice(t *testing.T) {
	e, clk := shippedEngine(t, "auth-new-device")
	for range 3 {
		e.Process(authOK(clk, "frank", "198.51.100.1", "CA", "macos/safari", 0, 0))
		clk.Advance(time.Hour)
	}
	ds := e.Process(authOK(clk, "frank", "198.51.100.1", "CA", "linux/python", 0, 0))
	if d := fired(ds, "auth-new-device"); d == nil || d.Values[0] != "linux/python" || d.Severity != "low" {
		t.Fatalf("expected new device detection, got %+v", ds)
	}
	if ds := e.Process(authOK(clk, "frank", "198.51.100.1", "CA", "linux/python", 0, 0)); len(ds) != 0 {
		t.Fatal("device is known now")
	}
}

func TestWebScan4xxBurst(t *testing.T) {
	e, clk := shippedEngine(t, "web-scan-4xx-burst")
	for i := range 19 {
		if ds := e.Process(web(clk, "203.0.113.77", fmt.Sprintf("/admin%d", i), 404)); len(ds) != 0 {
			t.Fatalf("fired early at %d", i)
		}
		// Successful and 5xx responses never count.
		e.Process(web(clk, "203.0.113.77", fmt.Sprintf("/ok%d", i), 200))
		e.Process(web(clk, "203.0.113.77", fmt.Sprintf("/err%d", i), 502))
		clk.Advance(2 * time.Second)
	}
	ds := e.Process(web(clk, "203.0.113.77", "/backup.zip", 403))
	if d := fired(ds, "web-scan-4xx-burst"); d == nil || d.Count != 20 {
		t.Fatalf("expected scan detection, got %+v", ds)
	}
}

func TestWebScanSamePathDoesNotFire(t *testing.T) {
	e, clk := shippedEngine(t, "web-scan-4xx-burst")
	for range 100 {
		if ds := e.Process(web(clk, "203.0.113.78", "/favicon.ico", 404)); len(ds) != 0 {
			t.Fatal("a single missing asset is not a scan")
		}
		clk.Advance(100 * time.Millisecond)
	}
}

func TestSensitivePathProbe(t *testing.T) {
	e, clk := shippedEngine(t, "web-sensitive-path-probe")
	e.Process(web(clk, "203.0.113.90", "/.env", 404))
	e.Process(web(clk, "203.0.113.90", "/index.html", 200))
	e.Process(web(clk, "203.0.113.90", "/.git/config", 404))
	ds := e.Process(web(clk, "203.0.113.90", "/WP-LOGIN.php", 200))
	if fired(ds, "web-sensitive-path-probe") == nil {
		t.Fatal("expected probe detection (case-insensitive contains)")
	}
}

func TestSnapshotRestore(t *testing.T) {
	e, clk := shippedEngine(t, "auth-bruteforce-ip", "auth-new-country")
	for range 9 {
		e.Process(authFail(clk, "203.0.113.9", "root"))
	}
	for range 3 {
		e.Process(authOK(clk, "gina", "198.51.100.1", "CA", "", 0, 0))
	}
	var buf bytes.Buffer
	if err := e.Snapshot(&buf); err != nil {
		t.Fatal(err)
	}

	e2, _ := shippedEngine(t, "auth-bruteforce-ip", "auth-new-country")
	e2.clock = clk
	if err := e2.Restore(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if ds := e2.Process(authFail(clk, "203.0.113.9", "root")); fired(ds, "auth-bruteforce-ip") == nil {
		t.Fatal("restored window should complete the threshold")
	}
	if ds := e2.Process(authOK(clk, "gina", "198.51.100.1", "JP", "", 0, 0)); fired(ds, "auth-new-country") == nil {
		t.Fatal("restored baseline should flag JP")
	}

	if err := e2.Restore(strings.NewReader(`{"version":99}`)); err == nil {
		t.Fatal("expected version error")
	}
}

func TestSnapshotFileRoundTrip(t *testing.T) {
	e, clk := shippedEngine(t, "auth-bruteforce-ip")
	path := filepath.Join(t.TempDir(), "state.json")
	if err := e.LoadSnapshot(path); err != nil {
		t.Fatalf("missing snapshot should be ignored: %v", err)
	}
	e.Process(authFail(clk, "203.0.113.9", "root"))
	if err := e.SaveSnapshot(path); err != nil {
		t.Fatal(err)
	}
	e2, _ := shippedEngine(t, "auth-bruteforce-ip")
	e2.clock = clk
	if err := e2.LoadSnapshot(path); err != nil {
		t.Fatal(err)
	}
	if e2.Stats()["auth-bruteforce-ip"] != 1 {
		t.Fatalf("state not restored: %v", e2.Stats())
	}
}

func TestGCAndMaxKeys(t *testing.T) {
	rules, err := ParseRules(strings.NewReader(`
id: t
type: threshold
selection: {outcome: failure}
group_by: [src_ip]
threshold: 100
window: 1m
`))
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(t0)
	e, err := NewEngine(rules, WithClock(clk), WithMaxKeys(3))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		e.Process(authFail(clk, fmt.Sprintf("192.0.2.%d", i), "x"))
		clk.Advance(time.Second)
	}
	if got := e.Stats()["t"]; got != 3 {
		t.Fatalf("max keys not enforced: %d", got)
	}
	if e.evicted.Load() != 2 {
		t.Fatalf("evicted=%d", e.evicted.Load())
	}
	clk.Advance(2 * time.Minute)
	if n := e.GC(); n != 3 {
		t.Fatalf("gc removed %d", n)
	}
}

func TestOutOfOrderEvents(t *testing.T) {
	e, clk := shippedEngine(t, "auth-bruteforce-ip")
	base := clk.Now()
	// Deliver 10 failures within 5 minutes in shuffled order.
	order := []int{9, 0, 5, 3, 1, 8, 2, 7, 4}
	for _, i := range order {
		ev := authFail(clk, "203.0.113.9", "root")
		ev.Timestamp = base.Add(time.Duration(i) * 20 * time.Second)
		if ds := e.Process(ev); len(ds) != 0 {
			t.Fatal("early fire")
		}
	}
	ev := authFail(clk, "203.0.113.9", "root")
	ev.Timestamp = base.Add(6 * 20 * time.Second)
	if ds := e.Process(ev); fired(ds, "auth-bruteforce-ip") == nil {
		t.Fatal("expected detection with out-of-order delivery")
	}
}

func BenchmarkEngineAuthFailures(b *testing.B) {
	rules, err := LoadDir(filepath.Join("..", "..", "rules"))
	if err != nil {
		b.Fatal(err)
	}
	e, _ := NewEngine(rules)
	base := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	evs := make([]event.Event, 1024)
	for i := range evs {
		evs[i] = event.Event{Source: "sshd", Category: event.CategoryAuth, Outcome: event.OutcomeFailure,
			SrcIP: fmt.Sprintf("198.51.100.%d", i%250), User: fmt.Sprintf("user%d", i%40)}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		ev := evs[i%len(evs)]
		ev.Timestamp = base.Add(time.Duration(i) * time.Millisecond)
		e.Process(&ev)
	}
}
