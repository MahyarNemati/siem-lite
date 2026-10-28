// Package sim generates realistic background traffic and attack scenarios
// for demos and end-to-end tests.
package sim

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"
)

// Kind is the transport a line should be sent over.
type Kind int

// Line kinds.
const (
	Syslog Kind = iota
	JSON
)

// Line is one generated record.
type Line struct {
	Kind Kind
	Data string
	At   time.Time
}

// User is a simulated account with a stable home network and device.
type User struct {
	Name   string
	HomeIP string
	UA     string
}

// Users is the baseline population. Home IPs fall inside deploy/geo/demo-geo.csv.
var Users = []User{
	{"alice", "198.51.100.10", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15"},
	{"bob", "198.51.100.11", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"},
	{"carol", "192.0.2.20", "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"},
	{"dave", "192.0.2.21", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Version/17.4 Mobile Safari/604.1"},
	{"erin", "100.64.3.4", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36 Edg/124.0"},
}

// Generator builds lines. It is not safe for concurrent use.
type Generator struct {
	rng  *rand.Rand
	host string
	pid  int
}

// New returns a generator seeded for reproducible output.
func New(seed uint64) *Generator {
	return &Generator{rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), host: "bastion-1", pid: 1000}
}

func (g *Generator) sshd(at time.Time, msg string) Line {
	g.pid++
	return Line{Kind: Syslog, At: at, Data: fmt.Sprintf("<38>1 %s %s sshd %d - - %s", at.UTC().Format(time.RFC3339Nano), g.host, g.pid, msg)}
}

func (g *Generator) nginx(at time.Time, ip, method, path string, status int, ua string) Line {
	body := fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"`,
		ip, at.UTC().Format("02/Jan/2006:15:04:05 -0700"), method, path, status, 200+g.rng.IntN(5000), ua)
	return Line{Kind: Syslog, At: at, Data: fmt.Sprintf("<190>1 %s edge-1 nginx - - - %s", at.UTC().Format(time.RFC3339Nano), body)}
}

func appLogin(at time.Time, user, ip, ua, outcome string) Line {
	b, _ := json.Marshal(map[string]any{
		"@timestamp": at.UTC().Format(time.RFC3339Nano),
		"service":    "auth-api",
		"event":      map[string]string{"action": "user_login", "outcome": outcome},
		"user":       map[string]string{"name": user},
		"source":     map[string]string{"ip": ip},
		"user_agent": map[string]string{"original": ua},
	})
	return Line{Kind: JSON, At: at, Data: string(b)}
}

// Baseline produces n benign events spread over span ending at end: user
// logins from home, a little web traffic and the odd typo'd password.
func (g *Generator) Baseline(end time.Time, span time.Duration, n int) []Line {
	out := make([]Line, 0, n)
	for i := range n {
		at := end.Add(-span + time.Duration(i)*span/time.Duration(max(n, 1)))
		u := Users[g.rng.IntN(len(Users))]
		switch g.rng.IntN(10) {
		case 0, 1, 2:
			out = append(out, appLogin(at, u.Name, u.HomeIP, u.UA, "success"))
		case 3:
			out = append(out, g.sshd(at, fmt.Sprintf("Accepted publickey for %s from %s port %d ssh2: ED25519 SHA256:x", u.Name, u.HomeIP, 40000+g.rng.IntN(20000))))
		case 4:
			out = append(out, g.sshd(at, fmt.Sprintf("Failed password for %s from %s port %d ssh2", u.Name, u.HomeIP, 40000+g.rng.IntN(20000))))
		default:
			paths := []string{"/", "/pricing", "/docs", "/api/v1/items", "/static/app.js", "/favicon.ico"}
			status := 200
			if g.rng.IntN(20) == 0 {
				status = 404
			}
			out = append(out, g.nginx(at, u.HomeIP, "GET", paths[g.rng.IntN(len(paths))], status, u.UA))
		}
	}
	return out
}

// Scenario is a named attack.
type Scenario struct {
	Name string
	// Rule is the detection the scenario is designed to trigger.
	Rule string
	Gen  func(g *Generator, start time.Time) []Line
}

// Scenarios lists every attack the generator knows.
var Scenarios = []Scenario{
	{"ssh-bruteforce", "auth-bruteforce-ip", func(g *Generator, start time.Time) []Line {
		ip := "203.0.113.200"
		var out []Line
		for i := range 25 {
			out = append(out, g.sshd(start.Add(time.Duration(i)*3*time.Second),
				fmt.Sprintf("Failed password for root from %s port %d ssh2", ip, 50000+i)))
		}
		return out
	}},
	{"password-spray", "auth-password-spray", func(g *Generator, start time.Time) []Line {
		ip := "100.66.7.7"
		var out []Line
		for i, u := range []string{"admin", "alice", "bob", "carol", "dave", "erin", "oracle", "test"} {
			out = append(out, appLogin(start.Add(time.Duration(i)*20*time.Second), u, ip, "python-requests/2.32", "failure"))
		}
		return out
	}},
	{"account-bruteforce", "auth-bruteforce-user", func(g *Generator, start time.Time) []Line {
		var out []Line
		for i := range 24 {
			ip := fmt.Sprintf("100.65.%d.%d", i/200, 1+i%200)
			out = append(out, g.sshd(start.Add(time.Duration(i)*10*time.Second),
				fmt.Sprintf("Failed password for invalid user admin from %s port %d ssh2", ip, 30000+i)))
		}
		return out
	}},
	{"impossible-travel", "auth-impossible-travel", func(g *Generator, start time.Time) []Line {
		u := Users[0]
		return []Line{
			appLogin(start, u.Name, u.HomeIP, u.UA, "success"),
			appLogin(start.Add(40*time.Minute), u.Name, "203.0.113.150", u.UA, "success"),
		}
	}},
	{"new-country-device", "auth-new-country", func(g *Generator, start time.Time) []Line {
		u := Users[2]
		var out []Line
		for i := range 4 {
			out = append(out, appLogin(start.Add(time.Duration(i)*time.Hour), u.Name, u.HomeIP, u.UA, "success"))
		}
		// 30 hours later from Sao Paulo with a scripted client: plausible
		// travel speed, but a country and device the account never used.
		return append(out, appLogin(start.Add(34*time.Hour), u.Name, "100.65.9.9", "curl/8.6.0", "success"))
	}},
	{"web-scan", "web-scan-4xx-burst", func(g *Generator, start time.Time) []Line {
		ip := "203.0.113.201"
		words := []string{"admin", "backup", "old", "test", "dev", "api", "v1", "config", "db", "uploads", "tmp", "cgi-bin",
			"shell", "console", "login", "private", "secret", "staging", "debug", "install", "setup", "portal"}
		var out []Line
		for i, w := range words {
			out = append(out, g.nginx(start.Add(time.Duration(i)*500*time.Millisecond), ip, "GET", "/"+w+"/", 404, "Mozilla/5.0 (compatible; Nmap Scripting Engine)"))
		}
		return out
	}},
	{"sensitive-files", "web-sensitive-path-probe", func(g *Generator, start time.Time) []Line {
		ip := "100.66.1.2"
		var out []Line
		for i, p := range []string{"/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/.aws/credentials"} {
			out = append(out, g.nginx(start.Add(time.Duration(i)*2*time.Second), ip, "GET", p, 404, "Go-http-client/1.1"))
		}
		return out
	}},
}

// Find returns the named scenario.
func Find(name string) (Scenario, bool) {
	for _, s := range Scenarios {
		if s.Name == name {
			return s, true
		}
	}
	return Scenario{}, false
}
