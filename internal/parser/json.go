package parser

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/event"
)

// Aliases map common field names (including ECS-style dotted keys) onto the
// normalized schema. The first match wins.
var jsonAliases = map[string][]string{
	"timestamp":   {"@timestamp", "timestamp", "time", "ts", "event.created"},
	"source":      {"source_type", "log.source", "service", "app", "event.module"},
	"host":        {"host", "hostname", "host.name"},
	"category":    {"category", "event.category"},
	"action":      {"action", "event.action", "event"},
	"outcome":     {"outcome", "event.outcome", "result"},
	"user":        {"user", "username", "user.name", "usr"},
	"src_ip":      {"src_ip", "source.ip", "client_ip", "client.ip", "ip", "remote_addr"},
	"src_port":    {"src_port", "source.port", "client.port"},
	"country":     {"country", "source.geo.country_iso_code"},
	"device":      {"device", "device_id", "device.id"},
	"user_agent":  {"user_agent", "user_agent.original", "ua", "http_user_agent"},
	"http_method": {"method", "http.request.method", "http_method"},
	"http_path":   {"path", "url.path", "http_path", "uri"},
	"http_status": {"status", "http.response.status_code", "http_status", "status_code"},
	"message":     {"message", "msg"},
}

// ParseJSON parses a generic JSON log object. Nested objects are flattened
// with dotted keys; anything not mapped to a schema field lands in Fields.
func ParseJSON(data []byte, now time.Time) (event.Event, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return event.Event{}, fmt.Errorf("%w: json: %w", errMalformed, err)
	}
	return FromMap(raw, now)
}

// FromMap normalizes an already-decoded JSON object.
func FromMap(raw map[string]any, now time.Time) (event.Event, error) {
	flat := make(map[string]string, len(raw))
	flatten("", raw, flat)

	used := map[string]bool{}
	pick := func(field string) string {
		for _, k := range jsonAliases[field] {
			if v, ok := flat[k]; ok && v != "" {
				used[k] = true
				return v
			}
		}
		return ""
	}

	ev := event.Event{
		Source:     orDefault(pick("source"), "json"),
		Host:       pick("host"),
		Category:   pick("category"),
		Action:     pick("action"),
		Outcome:    normalizeOutcome(pick("outcome")),
		User:       pick("user"),
		SrcIP:      pick("src_ip"),
		Country:    strings.ToUpper(pick("country")),
		Device:     pick("device"),
		UserAgent:  pick("user_agent"),
		HTTPMethod: pick("http_method"),
		HTTPPath:   pick("http_path"),
		Message:    pick("message"),
	}
	ev.SrcPort, _ = strconv.Atoi(pick("src_port"))
	ev.HTTPStatus, _ = strconv.Atoi(pick("http_status"))
	if ev.Device == "" {
		ev.Device = DeviceFromUserAgent(ev.UserAgent)
	}
	if ev.Category == "" {
		switch {
		case ev.HTTPStatus != 0:
			ev.Category = event.CategoryWeb
		case strings.Contains(ev.Action, "login") || strings.Contains(ev.Action, "auth"):
			ev.Category = event.CategoryAuth
		default:
			ev.Category = event.CategoryGeneric
		}
	}
	if ev.Outcome == event.OutcomeUnknown && ev.HTTPStatus != 0 {
		ev.Outcome = httpOutcome(ev.HTTPStatus)
	}

	ts, err := parseTime(pick("timestamp"))
	if err != nil {
		return event.Event{}, err
	}
	if ts.IsZero() {
		ts = now
	}
	ev.Timestamp = ts

	for k, v := range flat {
		if used[k] {
			continue
		}
		if ev.Fields == nil {
			ev.Fields = map[string]string{}
		}
		ev.Fields[k] = v
	}
	return ev, nil
}

func flatten(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flatten(key, child, out)
		}
	case string:
		out[prefix] = t
	case float64:
		out[prefix] = strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		out[prefix] = strconv.FormatBool(t)
	case nil:
	default:
		b, _ := json.Marshal(t)
		out[prefix] = string(b)
	}
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		switch {
		case n > 1e17:
			return time.Unix(0, int64(n)).UTC(), nil
		case n > 1e11:
			return time.UnixMilli(int64(n)).UTC(), nil
		default:
			sec := int64(n)
			return time.Unix(sec, int64((n-float64(sec))*1e9)).UTC(), nil
		}
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: unrecognized timestamp %q", errMalformed, s)
}

func normalizeOutcome(s string) string {
	switch strings.ToLower(s) {
	case "success", "succeeded", "ok", "allow", "allowed", "accepted", "true":
		return event.OutcomeSuccess
	case "failure", "failed", "fail", "deny", "denied", "rejected", "error", "false":
		return event.OutcomeFailure
	default:
		return event.OutcomeUnknown
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
