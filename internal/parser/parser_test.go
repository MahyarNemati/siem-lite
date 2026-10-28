package parser

import (
	"testing"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/event"
)

var refNow = time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)

func TestParseSyslog5424(t *testing.T) {
	raw := `<34>1 2026-03-15T10:14:15.003Z web-1 sshd 4123 ID47 [origin ip="10.0.0.1" note="a \"quoted\" \]"][meta seq="7"] Failed password for root from 203.0.113.9 port 50122 ssh2`
	msg, err := ParseSyslog(raw, refNow)
	if err != nil {
		t.Fatal(err)
	}
	if msg.RFC != 5424 || msg.Facility != 4 || msg.Severity != 2 {
		t.Fatalf("header: %+v", msg)
	}
	if msg.Hostname != "web-1" || msg.AppName != "sshd" || msg.ProcID != "4123" || msg.MsgID != "ID47" {
		t.Fatalf("fields: %+v", msg)
	}
	if got := msg.Structured["origin"]["note"]; got != `a "quoted" ]` {
		t.Fatalf("sd escape: %q", got)
	}
	if msg.Structured["meta"]["seq"] != "7" {
		t.Fatalf("second sd element missing: %+v", msg.Structured)
	}
	if msg.Message != "Failed password for root from 203.0.113.9 port 50122 ssh2" {
		t.Fatalf("message: %q", msg.Message)
	}
	if !msg.Timestamp.Equal(time.Date(2026, 3, 15, 10, 14, 15, 3e6, time.UTC)) {
		t.Fatalf("timestamp: %v", msg.Timestamp)
	}
}

func TestParseSyslog5424NilValues(t *testing.T) {
	msg, err := ParseSyslog(`<13>1 - - - - - -`, refNow)
	if err != nil {
		t.Fatal(err)
	}
	if !msg.Timestamp.IsZero() || msg.Hostname != "" || msg.Message != "" {
		t.Fatalf("expected nil values: %+v", msg)
	}
}

func TestParseSyslog3164(t *testing.T) {
	cases := []struct {
		name, raw, app, pid, msg string
		pri                      int
	}{
		{"with pri", "<38>Mar  5 09:01:02 bastion sshd[811]: Accepted publickey for alice from 198.51.100.4 port 2222 ssh2", "sshd", "811", "Accepted publickey for alice from 198.51.100.4 port 2222 ssh2", 38},
		{"no pri", "Mar 15 11:59:00 bastion CRON[22]: (root) CMD (true)", "CRON", "22", "(root) CMD (true)", -1},
		{"no pid", "<13>Mar 15 11:00:00 host app: hello", "app", "", "hello", 13},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := ParseSyslog(tc.raw, refNow)
			if err != nil {
				t.Fatal(err)
			}
			if msg.RFC != 3164 || msg.AppName != tc.app || msg.ProcID != tc.pid || msg.Message != tc.msg || msg.Priority != tc.pri {
				t.Fatalf("got %+v", msg)
			}
			if msg.Timestamp.Year() != 2026 {
				t.Fatalf("year not anchored: %v", msg.Timestamp)
			}
		})
	}
}

func TestParseSyslog3164YearRollover(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 5, 0, 0, time.UTC)
	msg, err := ParseSyslog("Dec 31 23:59:59 h app: x", now)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Timestamp.Year() != 2025 {
		t.Fatalf("want 2025, got %v", msg.Timestamp)
	}
}

func TestParseSyslogErrors(t *testing.T) {
	for _, raw := range []string{"", "<999>1 x", "<12", "<13>1 2026-03-15T10:14:15Z host", "<13>1 notatime h a p m -", "<13>1 2026-03-15T10:14:15Z h a p m [x a=\"b", "short"} {
		if _, err := ParseSyslog(raw, refNow); err == nil {
			t.Errorf("expected error for %q", raw)
		}
	}
}

func TestParseSSHD(t *testing.T) {
	cases := []struct {
		line, user, ip, outcome, action, method string
		port                                    int
	}{
		{"Failed password for root from 203.0.113.9 port 50122 ssh2", "root", "203.0.113.9", event.OutcomeFailure, "ssh_login", "password", 50122},
		{"Failed password for invalid user admin from 203.0.113.9 port 1 ssh2", "admin", "203.0.113.9", event.OutcomeFailure, "ssh_login", "password", 1},
		{"Accepted publickey for alice from 2001:db8::1 port 2222 ssh2: ED25519 SHA256:abc", "alice", "2001:db8::1", event.OutcomeSuccess, "ssh_login", "publickey", 2222},
		{"Invalid user oracle from 192.0.2.10 port 4444", "oracle", "192.0.2.10", event.OutcomeFailure, "ssh_invalid_user", "", 4444},
		{"error: maximum authentication attempts exceeded for root from 192.0.2.10 port 4444 ssh2 [preauth]", "root", "192.0.2.10", event.OutcomeFailure, "ssh_max_attempts", "", 4444},
	}
	for _, tc := range cases {
		ev, ok := ParseSSHD(tc.line, refNow, "h")
		if !ok {
			t.Fatalf("no match: %s", tc.line)
		}
		if ev.User != tc.user || ev.SrcIP != tc.ip || ev.Outcome != tc.outcome || ev.Action != tc.action || ev.SrcPort != tc.port {
			t.Errorf("%s: got %+v", tc.line, ev)
		}
		if got := ev.Fields["method"]; got != tc.method {
			t.Errorf("%s: method %q", tc.line, got)
		}
		if ev.Category != event.CategoryAuth || ev.Source != "sshd" {
			t.Errorf("category/source: %+v", ev)
		}
	}
	if _, ok := ParseSSHD("pam_unix(sshd:session): session opened for user alice", refNow, "h"); ok {
		t.Fatal("session line should not match")
	}
}

func TestParseNginx(t *testing.T) {
	line := `198.51.100.7 - bob [15/Mar/2026:10:00:01 +0000] "GET /wp-login.php?x=1 HTTP/1.1" 404 153 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"`
	ev, err := ParseNginx(line)
	if err != nil {
		t.Fatal(err)
	}
	if ev.SrcIP != "198.51.100.7" || ev.User != "bob" || ev.HTTPMethod != "GET" || ev.HTTPPath != "/wp-login.php?x=1" {
		t.Fatalf("got %+v", ev)
	}
	if ev.HTTPStatus != 404 || ev.Bytes != 153 || ev.Outcome != event.OutcomeFailure {
		t.Fatalf("status/bytes: %+v", ev)
	}
	if ev.Device != "linux/chrome" {
		t.Fatalf("device: %q", ev.Device)
	}
	if !ev.Timestamp.Equal(time.Date(2026, 3, 15, 10, 0, 1, 0, time.UTC)) {
		t.Fatalf("ts: %v", ev.Timestamp)
	}

	ev, err = ParseNginx(`10.0.0.1 - - [15/Mar/2026:10:00:01 -0500] "\x16\x03\x01" 400 0`)
	if err != nil {
		t.Fatal(err)
	}
	if ev.HTTPMethod != "" || ev.HTTPStatus != 400 || ev.User != "" {
		t.Fatalf("garbage request: %+v", ev)
	}
	if _, err := ParseNginx("not a log line"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseJSON(t *testing.T) {
	data := `{"@timestamp":"2026-03-15T09:00:00Z","event":{"action":"user_login","outcome":"failed"},"user":{"name":"carol"},"source":{"ip":"192.0.2.33","port":443},"user_agent":{"original":"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1"},"tenant":"acme","risk":0.7}`
	ev, err := ParseJSON([]byte(data), refNow)
	if err != nil {
		t.Fatal(err)
	}
	if ev.User != "carol" || ev.SrcIP != "192.0.2.33" || ev.SrcPort != 443 || ev.Action != "user_login" {
		t.Fatalf("got %+v", ev)
	}
	if ev.Outcome != event.OutcomeFailure || ev.Category != event.CategoryAuth || ev.Device != "ios/safari" {
		t.Fatalf("derived: %+v", ev)
	}
	if ev.Fields["tenant"] != "acme" || ev.Fields["risk"] != "0.7" {
		t.Fatalf("fields: %+v", ev.Fields)
	}
	if _, ok := ev.Fields["user.name"]; ok {
		t.Fatal("mapped field leaked into Fields")
	}
}

func TestParseJSONTimestamps(t *testing.T) {
	cases := map[string]time.Time{
		`{"ts":1773568800}`:              time.Unix(1773568800, 0).UTC(),
		`{"ts":1773568800123}`:           time.UnixMilli(1773568800123).UTC(),
		`{"time":"2026-03-15 10:00:00"}`: time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC),
		`{"msg":"no time"}`:              refNow,
	}
	for in, want := range cases {
		ev, err := ParseJSON([]byte(in), refNow)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if !ev.Timestamp.Equal(want) {
			t.Errorf("%s: got %v want %v", in, ev.Timestamp, want)
		}
	}
	if _, err := ParseJSON([]byte(`{"ts":"yesterday"}`), refNow); err == nil {
		t.Fatal("expected bad timestamp error")
	}
	if _, err := ParseJSON([]byte(`[1,2]`), refNow); err == nil {
		t.Fatal("expected error for non-object")
	}
}

func TestSyslogRouting(t *testing.T) {
	ev, err := Syslog("<38>Mar 15 09:01:02 bastion sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2", refNow)
	if err != nil || ev.Source != "sshd" || ev.Outcome != event.OutcomeFailure || ev.Host != "bastion" {
		t.Fatalf("sshd route: %+v %v", ev, err)
	}
	ev, err = Syslog(`<190>Mar 15 09:01:02 edge nginx: 203.0.113.5 - - [15/Mar/2026:09:01:02 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8.0"`, refNow)
	if err != nil || ev.Source != "nginx" || ev.Host != "edge" || ev.Device != "other/curl" {
		t.Fatalf("nginx route: %+v %v", ev, err)
	}
	ev, err = Syslog(`<14>1 2026-03-15T09:00:00Z app1 authsvc - - - {"action":"login","outcome":"success","user":"dave","ip":"192.0.2.1"}`, refNow)
	if err != nil || ev.Source != "authsvc" || ev.User != "dave" || ev.Host != "app1" {
		t.Fatalf("json route: %+v %v", ev, err)
	}
	ev, err = Syslog(`<14>1 2026-03-15T09:00:00Z app1 kernel - - [x y="z"] eth0 up`, refNow)
	if err != nil || ev.Category != event.CategoryGeneric || ev.Fields["x.y"] != "z" {
		t.Fatalf("generic route: %+v %v", ev, err)
	}
}

func TestLineAndFormat(t *testing.T) {
	if _, err := ParseFormat("xml"); err == nil {
		t.Fatal("expected error")
	}
	f, err := ParseFormat("NGINX")
	if err != nil || f != FormatNginx {
		t.Fatal(f, err)
	}
	if _, err := Line(FormatJSON, `{"user":"x"}`, refNow); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceFromUserAgent(t *testing.T) {
	cases := map[string]string{
		"":  "",
		"-": "",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36 Edg/124.0": "windows/edge",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0; rv:125.0) Gecko/20100101 Firefox/125.0":               "macos/firefox",
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36":              "android/chrome",
		"python-requests/2.32": "other/python",
		"Googlebot/2.1":        "other/bot",
	}
	for ua, want := range cases {
		if got := DeviceFromUserAgent(ua); got != want {
			t.Errorf("%q: got %q want %q", ua, got, want)
		}
	}
}
