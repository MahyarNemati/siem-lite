// Command loggen streams benign traffic plus periodic attack scenarios at a
// siem-lite instance over syslog and HTTP.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/sim"
)

type options struct {
	syslogAddr  string
	proto       string
	ingestURL   string
	token       string
	rate        int
	interval    time.Duration
	scenario    string
	once        bool
	seed        uint64
	waitTimeout time.Duration
}

func main() {
	var o options
	flag.StringVar(&o.syslogAddr, "syslog-addr", envOr("LOGGEN_SYSLOG_ADDR", "127.0.0.1:5514"), "siem-lite syslog address")
	flag.StringVar(&o.proto, "proto", envOr("LOGGEN_PROTO", "udp"), "syslog transport: udp or tcp")
	flag.StringVar(&o.ingestURL, "ingest-url", envOr("LOGGEN_INGEST_URL", "http://127.0.0.1:8080/v1/ingest"), "HTTP ingest endpoint for JSON events")
	flag.StringVar(&o.token, "token", os.Getenv("LOGGEN_TOKEN"), "bearer token for HTTP ingest")
	flag.IntVar(&o.rate, "rate", 20, "benign events per second")
	flag.DurationVar(&o.interval, "attack-interval", 30*time.Second, "time between attack scenarios")
	flag.StringVar(&o.scenario, "scenario", "random", "scenario name, 'random' or 'all'")
	flag.BoolVar(&o.once, "once", false, "run the selected scenario(s) once and exit")
	flag.Uint64Var(&o.seed, "seed", uint64(time.Now().UnixNano()), "random seed")
	flag.DurationVar(&o.waitTimeout, "wait", 60*time.Second, "how long to wait for siem-lite to come up")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, o, log); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("loggen failed", "err", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func run(ctx context.Context, o options, log *slog.Logger) error {
	if o.proto != "udp" && o.proto != "tcp" {
		return fmt.Errorf("unknown proto %q", o.proto)
	}
	if o.scenario != "random" && o.scenario != "all" {
		if _, ok := sim.Find(o.scenario); !ok {
			return fmt.Errorf("unknown scenario %q", o.scenario)
		}
	}
	s, err := newSender(ctx, o)
	if err != nil {
		return err
	}
	defer s.close()
	gen := sim.New(o.seed)
	rng := rand.New(rand.NewPCG(o.seed, 1))

	if o.once {
		for _, sc := range pick(o.scenario, rng) {
			if err := s.send(ctx, rebase(sc.Gen(gen, time.Now()), time.Now())); err != nil {
				return err
			}
			log.Info("scenario sent", "scenario", sc.Name, "expects", sc.Rule)
		}
		return nil
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	nextAttack := time.Now().Add(o.interval)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-tick.C:
			if err := s.send(ctx, gen.Baseline(now, time.Second, o.rate)); err != nil {
				log.Warn("send baseline", "err", err)
			}
			if now.After(nextAttack) {
				for _, sc := range pick(o.scenario, rng) {
					if err := s.send(ctx, rebase(sc.Gen(gen, now), now)); err != nil {
						log.Warn("send scenario", "scenario", sc.Name, "err", err)
						continue
					}
					log.Info("scenario sent", "scenario", sc.Name, "expects", sc.Rule)
				}
				nextAttack = now.Add(o.interval)
			}
		}
	}
}

func pick(name string, rng *rand.Rand) []sim.Scenario {
	switch name {
	case "all":
		return sim.Scenarios
	case "random":
		return []sim.Scenario{sim.Scenarios[rng.IntN(len(sim.Scenarios))]}
	}
	sc, _ := sim.Find(name)
	return []sim.Scenario{sc}
}

// rebase shifts a scenario so its last line lands at end. Scenarios span
// anything from seconds to days; replaying them compressed keeps the demo
// lively while event timestamps stay internally consistent.
func rebase(lines []sim.Line, end time.Time) []sim.Line {
	if len(lines) == 0 {
		return lines
	}
	last := lines[0].At
	for _, l := range lines {
		if l.At.After(last) {
			last = l.At
		}
	}
	shift := end.Sub(last)
	out := make([]sim.Line, len(lines))
	for i, l := range lines {
		out[i] = l
		out[i].At = l.At.Add(shift)
		out[i].Data = shiftTimestamps(l.Data, l.At, out[i].At)
	}
	return out
}

func shiftTimestamps(data string, from, to time.Time) string {
	for _, layout := range []string{time.RFC3339Nano, "02/Jan/2006:15:04:05 -0700"} {
		data = strings.ReplaceAll(data, from.UTC().Format(layout), to.UTC().Format(layout))
	}
	return data
}

type sender struct {
	conn   net.Conn
	proto  string
	url    string
	token  string
	client *http.Client
}

func newSender(ctx context.Context, o options) (*sender, error) {
	deadline := time.Now().Add(o.waitTimeout)
	var conn net.Conn
	var err error
	for {
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err = d.DialContext(ctx, o.proto, o.syslogAddr)
		if err == nil || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		return nil, fmt.Errorf("dial syslog: %w", err)
	}
	return &sender{conn: conn, proto: o.proto, url: o.ingestURL, token: o.token, client: &http.Client{Timeout: 10 * time.Second}}, nil
}

func (s *sender) send(ctx context.Context, lines []sim.Line) error {
	var jsonBody bytes.Buffer
	for _, l := range lines {
		if l.Kind == sim.JSON {
			jsonBody.WriteString(l.Data)
			jsonBody.WriteByte('\n')
			continue
		}
		var err error
		if s.proto == "tcp" {
			_, err = fmt.Fprintf(s.conn, "%d %s", len(l.Data), l.Data)
		} else {
			_, err = s.conn.Write([]byte(l.Data))
		}
		if err != nil {
			return fmt.Errorf("syslog write: %w", err)
		}
	}
	if jsonBody.Len() == 0 {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, &jsonBody)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("http ingest: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("http ingest: status %d", resp.StatusCode)
	}
	return nil
}

func (s *sender) close() { _ = s.conn.Close() }
