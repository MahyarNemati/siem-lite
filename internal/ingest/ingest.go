// Package ingest receives raw log records over syslog (UDP/TCP), HTTP and
// tailed files and hands them to the pipeline.
package ingest

import (
	"context"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/parser"
)

// Record is one raw log line plus transport metadata.
type Record struct {
	Format    parser.Format
	Data      string
	Received  time.Time
	Transport string
	Remote    string
}

// Handler accepts records. Blocking transports (TCP, HTTP, files) wait on
// it, which propagates backpressure; UDP uses TryHandle and drops on overload.
type Handler interface {
	Handle(ctx context.Context, r Record) error
	TryHandle(r Record) bool
}

// MaxMessageSize bounds a single record on every transport.
const MaxMessageSize = 64 << 10
