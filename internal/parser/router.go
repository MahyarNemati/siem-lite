// Package parser turns raw log lines into normalized events.
package parser

import (
	"fmt"
	"strings"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/event"
)

// Format identifies how a raw line should be decoded.
type Format string

// Supported line formats.
const (
	FormatSyslog Format = "syslog"
	FormatNginx  Format = "nginx"
	FormatJSON   Format = "json"
)

// ParseFormat validates a format name.
func ParseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(s)); f {
	case FormatSyslog, FormatNginx, FormatJSON:
		return f, nil
	}
	return "", fmt.Errorf("unknown log format %q", s)
}

// Line decodes a single line in the given format.
func Line(f Format, line string, now time.Time) (event.Event, error) {
	switch f {
	case FormatNginx:
		return ParseNginx(line)
	case FormatJSON:
		return ParseJSON([]byte(line), now)
	default:
		return Syslog(line, now)
	}
}

// Syslog parses a syslog record and routes the payload to the matching
// application parser. Unrecognized applications become generic events so
// nothing is silently dropped.
func Syslog(raw string, now time.Time) (event.Event, error) {
	msg, err := ParseSyslog(raw, now)
	if err != nil {
		return event.Event{}, err
	}
	ts := msg.Timestamp
	if ts.IsZero() {
		ts = now
	}
	body := strings.TrimSpace(msg.Message)

	switch {
	case msg.AppName == "sshd":
		if ev, ok := ParseSSHD(body, ts, msg.Hostname); ok {
			return ev, nil
		}
	case msg.AppName == "nginx" || strings.HasPrefix(msg.AppName, "nginx"):
		if ev, err := ParseNginx(body); err == nil {
			ev.Host = msg.Hostname
			return ev, nil
		}
	case strings.HasPrefix(body, "{"):
		if ev, err := ParseJSON([]byte(body), ts); err == nil {
			if ev.Host == "" {
				ev.Host = msg.Hostname
			}
			if ev.Source == "json" && msg.AppName != "" {
				ev.Source = msg.AppName
			}
			return ev, nil
		}
	}

	ev := event.Event{
		Timestamp: ts,
		Source:    orDefault(msg.AppName, "syslog"),
		Host:      msg.Hostname,
		Category:  event.CategoryGeneric,
		Outcome:   event.OutcomeUnknown,
		Message:   body,
	}
	for id, params := range msg.Structured {
		for k, v := range params {
			if ev.Fields == nil {
				ev.Fields = map[string]string{}
			}
			ev.Fields[id+"."+k] = v
		}
	}
	return ev, nil
}
