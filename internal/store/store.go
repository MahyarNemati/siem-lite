// Package store persists normalized events and detections.
package store

import (
	"context"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/detect"
	"github.com/mahyarnemati/siem-lite/internal/event"
)

// Store is the persistence boundary used by the pipeline.
type Store interface {
	InsertEvents(ctx context.Context, evs []event.Event) error
	InsertDetections(ctx context.Context, ds []detect.Detection) error
	// RecentDetections returns detections newer than since, newest first.
	RecentDetections(ctx context.Context, since time.Time, limit int) ([]detect.Detection, error)
	Ping(ctx context.Context) error
	Close() error
}
