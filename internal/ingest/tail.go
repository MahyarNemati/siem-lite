package ingest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/parser"
)

// Tailer follows a file like `tail -F`: it survives rotation (rename and
// recreate) and truncation, polling at Interval.
type Tailer struct {
	Path      string
	Format    parser.Format
	Handler   Handler
	Logger    *slog.Logger
	Interval  time.Duration
	FromStart bool
}

// Run blocks until ctx is cancelled.
func (t *Tailer) Run(ctx context.Context) error {
	interval := t.Interval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	log := t.Logger
	if log == nil {
		log = slog.Default()
	}
	var (
		f      *os.File
		br     *bufio.Reader
		offset int64
		first  = true
	)
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
	var partial strings.Builder
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if f == nil {
			nf, err := os.Open(t.Path)
			switch {
			case err == nil:
				f, offset = nf, 0
				if first && !t.FromStart {
					if offset, err = f.Seek(0, io.SeekEnd); err != nil {
						return fmt.Errorf("tail %s: %w", t.Path, err)
					}
				}
				br = bufio.NewReaderSize(f, 64<<10)
				partial.Reset()
				log.Info("tailing file", "path", t.Path, "offset", offset)
			case errors.Is(err, os.ErrNotExist):
			default:
				log.Warn("tail open", "path", t.Path, "err", err)
			}
			first = false
		}
		if f != nil {
			for {
				line, err := br.ReadString('\n')
				offset += int64(len(line))
				if err != nil {
					partial.WriteString(line)
					if partial.Len() > MaxMessageSize {
						partial.Reset()
					}
					break
				}
				partial.WriteString(line)
				text := strings.TrimRight(partial.String(), "\r\n")
				partial.Reset()
				if text == "" {
					continue
				}
				if err := t.Handler.Handle(ctx, Record{Format: t.Format, Data: text, Received: time.Now(), Transport: "file", Remote: t.Path}); err != nil {
					return nil
				}
			}
			if rotated, truncated := t.checkRotation(f, offset); rotated || truncated {
				if truncated {
					log.Info("file truncated", "path", t.Path)
					if _, err := f.Seek(0, io.SeekStart); err == nil {
						offset = 0
						br.Reset(f)
						partial.Reset()
					}
				} else {
					log.Info("file rotated", "path", t.Path)
					_ = f.Close()
					f = nil
					continue
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (t *Tailer) checkRotation(f *os.File, offset int64) (rotated, truncated bool) {
	cur, err := f.Stat()
	if err != nil {
		return true, false
	}
	onDisk, err := os.Stat(t.Path)
	if err != nil {
		// Renamed away and not yet recreated: keep draining the old handle.
		return false, false
	}
	if !os.SameFile(cur, onDisk) {
		return true, false
	}
	return false, cur.Size() < offset
}
