// Package geo resolves IP addresses to locations. A MaxMind GeoLite2 City
// database is used when configured; a small CSV of CIDR ranges covers demos
// and tests without the licensed database.
package geo

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// Location is the resolved position of an IP.
type Location struct {
	Country string
	City    string
	Lat     float64
	Lon     float64
}

// Locator resolves an IP to a location.
type Locator interface {
	Lookup(ip string) (Location, bool)
}

// Nop resolves nothing.
type Nop struct{}

// Lookup always reports false.
func (Nop) Lookup(string) (Location, bool) { return Location{}, false }

// Static is an in-memory prefix table. It is safe for concurrent use.
type Static struct {
	mu      sync.RWMutex
	entries []staticEntry
}

type staticEntry struct {
	prefix netip.Prefix
	loc    Location
}

// NewStatic returns an empty static locator.
func NewStatic() *Static { return &Static{} }

// Add registers a CIDR. Longer prefixes win on lookup.
func (s *Static) Add(cidr string, loc Location) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("geo: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, staticEntry{prefix: p.Masked(), loc: loc})
	return nil
}

// Lookup returns the most specific match.
func (s *Static) Lookup(ip string) (Location, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Location{}, false
	}
	addr = addr.Unmap()
	s.mu.RLock()
	defer s.mu.RUnlock()
	best, bits := Location{}, -1
	for _, e := range s.entries {
		if e.prefix.Contains(addr) && e.prefix.Bits() > bits {
			best, bits = e.loc, e.prefix.Bits()
		}
	}
	return best, bits >= 0
}

// LoadCSV reads rows of cidr,country,city,lat,lon. Lines starting with '#'
// are comments.
func LoadCSV(r io.Reader) (*Static, error) {
	cr := csv.NewReader(r)
	cr.Comment = '#'
	cr.FieldsPerRecord = 5
	cr.TrimLeadingSpace = true
	s := NewStatic()
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return s, nil
		}
		if err != nil {
			return nil, fmt.Errorf("geo csv: %w", err)
		}
		lat, err1 := strconv.ParseFloat(rec[3], 64)
		lon, err2 := strconv.ParseFloat(rec[4], 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("geo csv: bad coordinates for %s", rec[0])
		}
		if err := s.Add(rec[0], Location{Country: strings.ToUpper(rec[1]), City: rec[2], Lat: lat, Lon: lon}); err != nil {
			return nil, err
		}
	}
}

// LoadCSVFile is LoadCSV on a path.
func LoadCSVFile(path string) (*Static, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geo csv: %w", err)
	}
	defer f.Close()
	return LoadCSV(f)
}

// MaxMind wraps a GeoLite2/GeoIP2 City database.
type MaxMind struct {
	db *geoip2.Reader
}

// OpenMaxMind opens an .mmdb file.
func OpenMaxMind(path string) (*MaxMind, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: %w", err)
	}
	return &MaxMind{db: db}, nil
}

// Lookup resolves ip using the City database.
func (m *MaxMind) Lookup(ip string) (Location, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Location{}, false
	}
	rec, err := m.db.City(addr.AsSlice())
	if err != nil || rec.Country.IsoCode == "" {
		return Location{}, false
	}
	return Location{
		Country: rec.Country.IsoCode,
		City:    rec.City.Names["en"],
		Lat:     rec.Location.Latitude,
		Lon:     rec.Location.Longitude,
	}, true
}

// Close releases the database.
func (m *MaxMind) Close() error { return m.db.Close() }

// Chain tries locators in order.
type Chain []Locator

// Lookup returns the first hit.
func (c Chain) Lookup(ip string) (Location, bool) {
	for _, l := range c {
		if loc, ok := l.Lookup(ip); ok {
			return loc, true
		}
	}
	return Location{}, false
}

const earthRadiusKm = 6371.0

// DistanceKm is the great-circle distance between two points.
func DistanceKm(lat1, lon1, lat2, lon2 float64) float64 {
	rad := math.Pi / 180
	dLat := (lat2 - lat1) * rad
	dLon := (lon2 - lon1) * rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthRadiusKm * math.Asin(math.Min(1, math.Sqrt(a)))
}
