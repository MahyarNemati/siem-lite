package ingest

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/parser"
)

// HTTPHandler accepts POSTed log records.
//
//	POST /v1/ingest                      JSON object, JSON array, or NDJSON
//	POST /v1/ingest?format=nginx|syslog  one raw line per body line
type HTTPHandler struct {
	Handler  Handler
	Token    string
	MaxBody  int64
	MaxLines int
}

type ingestResponse struct {
	Accepted int    `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, ingestResponse{Error: "method not allowed"})
		return
	}
	if h.Token != "" && !validBearer(r.Header.Get("Authorization"), h.Token) {
		writeJSON(w, http.StatusUnauthorized, ingestResponse{Error: "unauthorized"})
		return
	}
	format := parser.FormatJSON
	if q := r.URL.Query().Get("format"); q != "" {
		f, err := parser.ParseFormat(q)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ingestResponse{Error: err.Error()})
			return
		}
		format = f
	}
	maxBody := h.MaxBody
	if maxBody <= 0 {
		maxBody = 8 << 20
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeJSON(w, http.StatusRequestEntityTooLarge, ingestResponse{Error: "body too large"})
			return
		}
		writeJSON(w, http.StatusBadRequest, ingestResponse{Error: "read body"})
		return
	}
	lines, err := splitBody(format, body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ingestResponse{Error: err.Error()})
		return
	}
	maxLines := h.MaxLines
	if maxLines <= 0 {
		maxLines = 10_000
	}
	if len(lines) > maxLines {
		writeJSON(w, http.StatusRequestEntityTooLarge, ingestResponse{Error: "too many records"})
		return
	}
	now := time.Now()
	remote := remoteHost(r.RemoteAddr)
	for i, line := range lines {
		rec := Record{Format: format, Data: line, Received: now, Transport: "http", Remote: remote}
		if err := h.Handler.Handle(r.Context(), rec); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, ingestResponse{Accepted: i, Error: "pipeline unavailable"})
			return
		}
	}
	writeJSON(w, http.StatusAccepted, ingestResponse{Accepted: len(lines)})
}

func splitBody(format parser.Format, body []byte) ([]string, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("empty body")
	}
	if format == parser.FormatJSON && trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, errors.New("invalid JSON array")
		}
		out := make([]string, 0, len(arr))
		for _, m := range arr {
			out = append(out, string(m))
		}
		return out, nil
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(trimmed))
	sc.Buffer(make([]byte, 0, 64<<10), MaxMessageSize)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, errors.New("record exceeds maximum size")
	}
	return out, nil
}

func validBearer(header, token string) bool {
	got, ok := strings.CutPrefix(header, "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func remoteHost(addr string) string {
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		return strings.Trim(addr[:i], "[]")
	}
	return addr
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
