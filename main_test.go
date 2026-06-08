package main

import (
	"strings"
	"testing"
)

func TestReadFQDNs(t *testing.T) {
	input := `
# comment
www.example.com
api.example.com, staging.example.com

legacy.example.com
`
	got, err := readFQDNs(strings.NewReader(input))
	if err != nil {
		t.Fatalf("readFQDNs() error: %v", err)
	}

	want := []string{
		"www.example.com",
		"api.example.com",
		"staging.example.com",
		"legacy.example.com",
	}
	if len(got) != len(want) {
		t.Fatalf("readFQDNs() = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("readFQDNs()[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}

func TestDedupeStrings(t *testing.T) {
	got := dedupeStrings([]string{"a.com", "b.com", "a.com", "c.com"})
	want := []string{"a.com", "b.com", "c.com"}
	if len(got) != len(want) {
		t.Fatalf("dedupeStrings() = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dedupeStrings()[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}
