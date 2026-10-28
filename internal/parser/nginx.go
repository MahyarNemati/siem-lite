package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/event"
)

// nginx "combined" log format.
var nginxCombined = regexp.MustCompile(
	`^(\S+) \S+ (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?`)

const nginxTimeLayout = "02/Jan/2006:15:04:05 -0700"

// ParseNginx parses one nginx access log line in the combined format.
func ParseNginx(line string) (event.Event, error) {
	m := nginxCombined.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return event.Event{}, fmt.Errorf("%w: not an nginx combined line", errMalformed)
	}
	ts, err := time.Parse(nginxTimeLayout, m[3])
	if err != nil {
		return event.Event{}, fmt.Errorf("%w: nginx time: %w", errMalformed, err)
	}
	status, _ := strconv.Atoi(m[5])
	var size int64
	if m[6] != "-" {
		size, _ = strconv.ParseInt(m[6], 10, 64)
	}
	method, path := "", m[4]
	if parts := strings.SplitN(m[4], " ", 3); len(parts) >= 2 {
		method, path = parts[0], parts[1]
	}
	ev := event.Event{
		Timestamp:  ts,
		Source:     "nginx",
		Category:   event.CategoryWeb,
		Action:     "http_request",
		Outcome:    httpOutcome(status),
		SrcIP:      m[1],
		HTTPMethod: method,
		HTTPPath:   path,
		HTTPStatus: status,
		Bytes:      size,
		UserAgent:  m[8],
		Device:     DeviceFromUserAgent(m[8]),
		Message:    line,
	}
	if m[2] != "-" {
		ev.User = m[2]
	}
	if m[7] != "" && m[7] != "-" {
		ev.Fields = map[string]string{"referer": m[7]}
	}
	return ev, nil
}

func httpOutcome(status int) string {
	switch {
	case status >= 400:
		return event.OutcomeFailure
	case status > 0:
		return event.OutcomeSuccess
	default:
		return event.OutcomeUnknown
	}
}
