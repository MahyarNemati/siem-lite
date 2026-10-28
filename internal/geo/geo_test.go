package geo

import (
	"math"
	"strings"
	"testing"
)

func TestStaticLongestPrefix(t *testing.T) {
	s := NewStatic()
	if err := s.Add("203.0.113.0/24", Location{Country: "CA"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("203.0.113.128/25", Location{Country: "AU"}); err != nil {
		t.Fatal(err)
	}
	if loc, ok := s.Lookup("203.0.113.5"); !ok || loc.Country != "CA" {
		t.Fatalf("got %v %v", loc, ok)
	}
	if loc, ok := s.Lookup("203.0.113.200"); !ok || loc.Country != "AU" {
		t.Fatalf("got %v %v", loc, ok)
	}
	if loc, ok := s.Lookup("::ffff:203.0.113.200"); !ok || loc.Country != "AU" {
		t.Fatalf("mapped v6: %v %v", loc, ok)
	}
	if _, ok := s.Lookup("192.0.2.1"); ok {
		t.Fatal("unexpected hit")
	}
	if _, ok := s.Lookup("garbage"); ok {
		t.Fatal("unexpected hit")
	}
	if err := s.Add("nope", Location{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadCSV(t *testing.T) {
	in := "# cidr,country,city,lat,lon\n198.51.100.0/24, ca, Toronto, 43.65, -79.38\n"
	s, err := LoadCSV(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	loc, ok := s.Lookup("198.51.100.9")
	if !ok || loc.Country != "CA" || loc.City != "Toronto" {
		t.Fatalf("got %+v", loc)
	}
	if _, err := LoadCSV(strings.NewReader("1.0.0.0/8,X,Y,abc,1\n")); err == nil {
		t.Fatal("expected coordinate error")
	}
	if _, err := LoadCSV(strings.NewReader("1.0.0.0/8,X\n")); err == nil {
		t.Fatal("expected field count error")
	}
}

func TestChainAndNop(t *testing.T) {
	s := NewStatic()
	_ = s.Add("10.0.0.0/8", Location{Country: "US"})
	c := Chain{Nop{}, s}
	if loc, ok := c.Lookup("10.1.1.1"); !ok || loc.Country != "US" {
		t.Fatal("chain miss")
	}
	if _, ok := c.Lookup("11.1.1.1"); ok {
		t.Fatal("chain false hit")
	}
}

func TestDistanceKm(t *testing.T) {
	// Toronto to Sydney is roughly 15,560 km.
	d := DistanceKm(43.65, -79.38, -33.87, 151.21)
	if math.Abs(d-15560) > 100 {
		t.Fatalf("distance %f", d)
	}
	if DistanceKm(1, 1, 1, 1) != 0 {
		t.Fatal("zero distance")
	}
}
