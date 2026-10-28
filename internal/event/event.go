// Package event defines the normalized event schema shared by parsers,
// the detection engine, and storage.
package event

import (
	"strconv"
	"strings"
	"time"
)

// Outcome values.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeUnknown = "unknown"
)

// Category values.
const (
	CategoryAuth    = "authentication"
	CategoryWeb     = "web"
	CategoryGeneric = "generic"
)

// Event is the normalized representation of a single log record.
type Event struct {
	Timestamp  time.Time         `json:"timestamp"`
	Received   time.Time         `json:"received"`
	Source     string            `json:"source"`
	Host       string            `json:"host,omitempty"`
	Category   string            `json:"category"`
	Action     string            `json:"action,omitempty"`
	Outcome    string            `json:"outcome"`
	User       string            `json:"user,omitempty"`
	SrcIP      string            `json:"src_ip,omitempty"`
	SrcPort    int               `json:"src_port,omitempty"`
	Country    string            `json:"country,omitempty"`
	City       string            `json:"city,omitempty"`
	Lat        float64           `json:"lat,omitempty"`
	Lon        float64           `json:"lon,omitempty"`
	Device     string            `json:"device,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	HTTPMethod string            `json:"http_method,omitempty"`
	HTTPPath   string            `json:"http_path,omitempty"`
	HTTPStatus int               `json:"http_status,omitempty"`
	Bytes      int64             `json:"bytes,omitempty"`
	Message    string            `json:"message,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
}

// Get returns the string value of a field by its schema name. Unknown names
// fall through to the free-form Fields map. The second return value reports
// whether the field is set.
func (e *Event) Get(name string) (string, bool) {
	switch name {
	case "source":
		return e.Source, e.Source != ""
	case "host":
		return e.Host, e.Host != ""
	case "category":
		return e.Category, e.Category != ""
	case "action":
		return e.Action, e.Action != ""
	case "outcome":
		return e.Outcome, e.Outcome != ""
	case "user":
		return e.User, e.User != ""
	case "src_ip":
		return e.SrcIP, e.SrcIP != ""
	case "src_port":
		return itoa(e.SrcPort), e.SrcPort != 0
	case "country":
		return e.Country, e.Country != ""
	case "city":
		return e.City, e.City != ""
	case "device":
		return e.Device, e.Device != ""
	case "user_agent":
		return e.UserAgent, e.UserAgent != ""
	case "http_method":
		return e.HTTPMethod, e.HTTPMethod != ""
	case "http_path":
		return e.HTTPPath, e.HTTPPath != ""
	case "http_status":
		return itoa(e.HTTPStatus), e.HTTPStatus != 0
	case "bytes":
		return strconv.FormatInt(e.Bytes, 10), e.Bytes != 0
	case "message":
		return e.Message, e.Message != ""
	}
	if e.Fields == nil {
		return "", false
	}
	v, ok := e.Fields[strings.TrimPrefix(name, "fields.")]
	return v, ok
}

// HasGeo reports whether the event carries coordinates.
func (e *Event) HasGeo() bool { return e.Lat != 0 || e.Lon != 0 }

func itoa(n int) string { return strconv.Itoa(n) }
