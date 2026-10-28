package parser

import (
	"regexp"
	"strconv"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/event"
)

var sshdPatterns = []struct {
	re      *regexp.Regexp
	outcome string
	action  string
}{
	{regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`), event.OutcomeSuccess, "ssh_login"},
	{regexp.MustCompile(`^Failed (\S+) for invalid user (\S*) from (\S+) port (\d+)`), event.OutcomeFailure, "ssh_login"},
	{regexp.MustCompile(`^Failed (\S+) for (\S+) from (\S+) port (\d+)`), event.OutcomeFailure, "ssh_login"},
	{regexp.MustCompile(`^error: maximum authentication attempts exceeded for (?:invalid user )?()(\S+) from (\S+) port (\d+)`), event.OutcomeFailure, "ssh_max_attempts"},
	{regexp.MustCompile(`^Invalid user ()(\S*) from (\S+) port (\d+)`), event.OutcomeFailure, "ssh_invalid_user"},
}

// ParseSSHD turns an sshd message body (without the syslog header) into an
// authentication event. ok is false when the line is not an auth decision,
// for example session open/close chatter.
func ParseSSHD(msg string, ts time.Time, host string) (ev event.Event, ok bool) {
	for _, p := range sshdPatterns {
		m := p.re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		port, _ := strconv.Atoi(m[4])
		ev = event.Event{
			Timestamp: ts,
			Source:    "sshd",
			Host:      host,
			Category:  event.CategoryAuth,
			Action:    p.action,
			Outcome:   p.outcome,
			User:      m[2],
			SrcIP:     m[3],
			SrcPort:   port,
			Message:   msg,
		}
		if m[1] != "" {
			ev.Fields = map[string]string{"method": m[1]}
		}
		return ev, true
	}
	return event.Event{}, false
}
