package parser

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SyslogMessage is the transport-level view of a syslog record before the
// payload is handed to an application parser.
type SyslogMessage struct {
	Priority   int
	Facility   int
	Severity   int
	Timestamp  time.Time
	Hostname   string
	AppName    string
	ProcID     string
	MsgID      string
	Structured map[string]map[string]string
	Message    string
	RFC        int
}

var (
	errEmpty     = errors.New("empty message")
	errMalformed = errors.New("malformed syslog message")
)

// ParseSyslog parses an RFC 5424 or RFC 3164 message. The PRI header is
// optional for 3164 so raw lines from /var/log/auth.log are accepted too.
// now anchors the year for 3164 timestamps, which do not carry one.
func ParseSyslog(raw string, now time.Time) (SyslogMessage, error) {
	s := strings.TrimRight(raw, "\r\n\x00")
	if s == "" {
		return SyslogMessage{}, errEmpty
	}
	msg := SyslogMessage{Priority: -1}
	if s[0] == '<' {
		end := strings.IndexByte(s, '>')
		if end < 2 || end > 4 {
			return msg, fmt.Errorf("%w: bad PRI", errMalformed)
		}
		pri, err := strconv.Atoi(s[1:end])
		if err != nil || pri > 191 {
			return msg, fmt.Errorf("%w: bad PRI", errMalformed)
		}
		msg.Priority, msg.Facility, msg.Severity = pri, pri/8, pri%8
		s = s[end+1:]
		if strings.HasPrefix(s, "1 ") {
			return parse5424(msg, s[2:])
		}
	}
	return parse3164(msg, s, now)
}

func parse5424(msg SyslogMessage, s string) (SyslogMessage, error) {
	msg.RFC = 5424
	fields := make([]string, 0, 5)
	for range 5 {
		i := strings.IndexByte(s, ' ')
		if i < 0 {
			return msg, fmt.Errorf("%w: truncated header", errMalformed)
		}
		fields = append(fields, s[:i])
		s = s[i+1:]
	}
	if fields[0] != "-" {
		ts, err := time.Parse(time.RFC3339Nano, fields[0])
		if err != nil {
			return msg, fmt.Errorf("%w: timestamp: %v", errMalformed, err)
		}
		msg.Timestamp = ts
	}
	msg.Hostname = nilValue(fields[1])
	msg.AppName = nilValue(fields[2])
	msg.ProcID = nilValue(fields[3])
	msg.MsgID = nilValue(fields[4])

	sd, rest, err := parseStructuredData(s)
	if err != nil {
		return msg, err
	}
	msg.Structured = sd
	rest = strings.TrimPrefix(rest, " ")
	rest = strings.TrimPrefix(rest, "\ufeff")
	msg.Message = rest
	return msg, nil
}

func nilValue(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func parseStructuredData(s string) (map[string]map[string]string, string, error) {
	if strings.HasPrefix(s, "-") {
		return nil, s[1:], nil
	}
	if !strings.HasPrefix(s, "[") {
		return nil, s, fmt.Errorf("%w: structured data", errMalformed)
	}
	out := map[string]map[string]string{}
	for strings.HasPrefix(s, "[") {
		s = s[1:]
		sp := strings.IndexAny(s, " ]")
		if sp < 0 {
			return nil, s, fmt.Errorf("%w: unterminated SD element", errMalformed)
		}
		id := s[:sp]
		params := map[string]string{}
		s = s[sp:]
		for {
			s = strings.TrimLeft(s, " ")
			if s == "" {
				return nil, s, fmt.Errorf("%w: unterminated SD element", errMalformed)
			}
			if s[0] == ']' {
				s = s[1:]
				break
			}
			eq := strings.Index(s, "=\"")
			if eq < 0 {
				return nil, s, fmt.Errorf("%w: SD param", errMalformed)
			}
			name := s[:eq]
			s = s[eq+2:]
			var b strings.Builder
			closed := false
			for i := 0; i < len(s); i++ {
				c := s[i]
				if c == '\\' && i+1 < len(s) && strings.IndexByte(`"\]`, s[i+1]) >= 0 {
					b.WriteByte(s[i+1])
					i++
					continue
				}
				if c == '"' {
					s = s[i+1:]
					closed = true
					break
				}
				b.WriteByte(c)
			}
			if !closed {
				return nil, s, fmt.Errorf("%w: unterminated SD value", errMalformed)
			}
			params[name] = b.String()
		}
		out[id] = params
	}
	return out, s, nil
}

func parse3164(msg SyslogMessage, s string, now time.Time) (SyslogMessage, error) {
	msg.RFC = 3164
	const stampLen = len("Jan _2 15:04:05")
	if len(s) < stampLen+1 {
		return msg, fmt.Errorf("%w: too short", errMalformed)
	}
	ts, err := time.ParseInLocation(time.Stamp, s[:stampLen], now.Location())
	if err != nil {
		return msg, fmt.Errorf("%w: timestamp: %v", errMalformed, err)
	}
	ts = ts.AddDate(now.Year(), 0, 0)
	// Messages logged in late December and read in early January belong to
	// the previous year.
	if ts.Sub(now) > 24*time.Hour {
		ts = ts.AddDate(-1, 0, 0)
	}
	msg.Timestamp = ts
	s = strings.TrimLeft(s[stampLen:], " ")

	host, rest, ok := strings.Cut(s, " ")
	if !ok {
		return msg, fmt.Errorf("%w: missing hostname", errMalformed)
	}
	msg.Hostname = host

	tagEnd := strings.IndexAny(rest, ":[ ")
	if tagEnd <= 0 {
		msg.Message = rest
		return msg, nil
	}
	msg.AppName = rest[:tagEnd]
	rest = rest[tagEnd:]
	if strings.HasPrefix(rest, "[") {
		if end := strings.IndexByte(rest, ']'); end > 0 {
			msg.ProcID = rest[1:end]
			rest = rest[end+1:]
		}
	}
	rest = strings.TrimPrefix(rest, ":")
	msg.Message = strings.TrimPrefix(rest, " ")
	return msg, nil
}
