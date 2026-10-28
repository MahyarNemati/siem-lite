package ingest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/parser"
)

type collector struct {
	mu   sync.Mutex
	recs []Record
	full bool
}

func (c *collector) Handle(_ context.Context, r Record) error {
	c.mu.Lock()
	c.recs = append(c.recs, r)
	c.mu.Unlock()
	return nil
}

func (c *collector) TryHandle(r Record) bool {
	if c.full {
		return false
	}
	_ = c.Handle(context.Background(), r)
	return true
}

func (c *collector) snapshot() []Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Record(nil), c.recs...)
}

func waitFor(t *testing.T, c *collector, n int) []Record {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.snapshot(); len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d records, have %d", n, len(c.snapshot()))
	return nil
}

func TestUDPServer(t *testing.T) {
	c := &collector{}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &UDPServer{Handler: c}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, pc) }()

	conn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("<13>Mar 15 10:00:00 h app: one\n"))
	_, _ = conn.Write([]byte("<13>Mar 15 10:00:01 h app: two\n<13>Mar 15 10:00:02 h app: three\n"))
	got := waitFor(t, c, 3)
	if got[0].Transport != "udp" || got[0].Remote != "127.0.0.1" || got[0].Format != parser.FormatSyslog {
		t.Fatalf("record %+v", got[0])
	}
	if !strings.HasSuffix(got[2].Data, "three") {
		t.Fatalf("multi-line datagram split wrong: %+v", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestUDPServerDropsWhenFull(t *testing.T) {
	c := &collector{full: true}
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	drops := 0
	srv := &UDPServer{Handler: c, OnDrop: func() { mu.Lock(); drops++; mu.Unlock() }}
	go func() { _ = srv.Serve(ctx, pc) }()
	conn, _ := net.Dial("udp", pc.LocalAddr().String())
	defer conn.Close()
	_, _ = conn.Write([]byte("x"))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		d := drops
		mu.Unlock()
		if d == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("drop not reported")
}

func TestTCPServerFraming(t *testing.T) {
	c := &collector{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &TCPServer{Handler: c}
	go func() { _ = srv.Serve(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	msg := "<13>1 2026-03-15T10:00:00Z h app - - - line with\nembedded newline"
	fmt.Fprintf(conn, "%d %s", len(msg), msg)
	fmt.Fprint(conn, "<13>Mar 15 10:00:00 h app: newline framed\r\n")
	fmt.Fprint(conn, "<13>Mar 15 10:00:00 h app: last without newline")
	conn.Close()

	got := waitFor(t, c, 3)
	if got[0].Data != msg {
		t.Fatalf("octet-counted frame: %q", got[0].Data)
	}
	if got[1].Data != "<13>Mar 15 10:00:00 h app: newline framed" || !strings.HasSuffix(got[2].Data, "without newline") {
		t.Fatalf("newline frames: %+v", got)
	}
}

func TestReadFrameLimits(t *testing.T) {
	br := bufio.NewReader(strings.NewReader(fmt.Sprintf("%d x", MaxMessageSize+1)))
	if _, err := readFrame(br); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("got %v", err)
	}
	long := strings.Repeat("a", MaxMessageSize+10) + "\n"
	br = bufio.NewReaderSize(strings.NewReader(long), 16)
	if _, err := readFrame(br); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("got %v", err)
	}
	br = bufio.NewReader(strings.NewReader("12x <13>"))
	if _, err := readFrame(br); err == nil {
		t.Fatal("expected bad octet count")
	}
}

func TestHTTPHandler(t *testing.T) {
	c := &collector{}
	h := &HTTPHandler{Handler: c, Token: "tkn", MaxBody: 1024, MaxLines: 3}
	srv := httptest.NewServer(h)
	defer srv.Close()

	do := func(method, query, auth, body string) int {
		req, _ := http.NewRequest(method, srv.URL+"/v1/ingest"+query, strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	cases := []struct {
		name, method, query, auth, body string
		status, records                 int
	}{
		{"no auth", "POST", "", "", `{"a":1}`, 401, 0},
		{"wrong token", "POST", "", "Bearer nope", `{"a":1}`, 401, 0},
		{"get", "GET", "", "Bearer tkn", "", 405, 0},
		{"object", "POST", "", "Bearer tkn", `{"user":"a"}`, 202, 1},
		{"array", "POST", "", "Bearer tkn", `[{"user":"b"},{"user":"c"}]`, 202, 3},
		{"ndjson", "POST", "", "Bearer tkn", "{\"user\":\"d\"}\n\n{\"user\":\"e\"}\n", 202, 5},
		{"nginx", "POST", "?format=nginx", "Bearer tkn", `1.2.3.4 - - [15/Mar/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 1 "-" "x"`, 202, 6},
		{"bad format", "POST", "?format=xml", "Bearer tkn", "x", 400, 6},
		{"bad array", "POST", "", "Bearer tkn", `[{"a":1}`, 400, 6},
		{"empty", "POST", "", "Bearer tkn", "  ", 400, 6},
		{"too many lines", "POST", "", "Bearer tkn", "{}\n{}\n{}\n{}", 413, 6},
		{"too large", "POST", "", "Bearer tkn", strings.Repeat("x", 2048), 413, 6},
	}
	for _, tc := range cases {
		if got := do(tc.method, tc.query, tc.auth, tc.body); got != tc.status {
			t.Errorf("%s: status %d want %d", tc.name, got, tc.status)
		}
		if n := len(c.snapshot()); n != tc.records {
			t.Errorf("%s: %d records want %d", tc.name, n, tc.records)
		}
	}
	if got := c.snapshot()[5]; got.Format != parser.FormatNginx || got.Transport != "http" {
		t.Fatalf("nginx record %+v", got)
	}
}

func TestTailerFollowsRotationAndTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("old line before start\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &collector{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tl := &Tailer{Path: path, Format: parser.FormatSyslog, Handler: c, Interval: 10 * time.Millisecond}
	done := make(chan struct{})
	go func() { _ = tl.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)

	appendTo := func(s string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString(s)
		_ = f.Close()
	}
	appendTo("first\nsec")
	time.Sleep(40 * time.Millisecond)
	appendTo("ond\n")
	got := waitFor(t, c, 2)
	if got[0].Data != "first" || got[1].Data != "second" {
		t.Fatalf("partial line handling: %+v", got)
	}

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo("after rotate\n")
	got = waitFor(t, c, 3)
	if got[2].Data != "after rotate" {
		t.Fatalf("rotation: %+v", got)
	}

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	appendTo("x\n")
	got = waitFor(t, c, 4)
	if got[3].Data != "x" {
		t.Fatalf("truncation: %+v", got)
	}
	for _, r := range got {
		if strings.Contains(r.Data, "before start") {
			t.Fatal("tail should start at end of file")
		}
	}
	cancel()
	<-done
}
