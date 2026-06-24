package main

import (
	"strings"
	"testing"

	"github.com/brenu/bounty-cli/internal/api"
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

func TestScopesFromFQDNs(t *testing.T) {
	fqdns := []string{"example.com", "sub.example.com", "*.wildcard.com"}
	scopes := scopesFromFQDNs(fqdns)

	if len(scopes) != 3 {
		t.Fatalf("scopesFromFQDNs() returned %d scopes; want 3", len(scopes))
	}
	for i, s := range scopes {
		if s.Endpoint != fqdns[i] {
			t.Errorf("scopesFromFQDNs()[%d].Endpoint = %q; want %q", i, s.Endpoint, fqdns[i])
		}
		if s.Type.Value != "Domain" {
			t.Errorf("scopesFromFQDNs()[%d].Type = %q; want %q", i, s.Type.Value, "Domain")
		}
		if s.Tier.Value != "In Scope" {
			t.Errorf("scopesFromFQDNs()[%d].Tier = %q; want %q", i, s.Tier.Value, "In Scope")
		}
	}
}

func TestWildcardScope(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantEP   string
		wantType string
	}{
		{"bare domain", "example.com", "*.example.com", "Wildcard"},
		{"already wildcard", "*.example.com", "*.example.com", "Wildcard"},
		{"subdomain", "sub.example.com", "*.sub.example.com", "Wildcard"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := api.Scope{
				Endpoint: tt.input,
				Type:     api.AssetType{Value: "Domain"},
				Tier:     api.Tier{Value: "In Scope"},
			}
			got := wildcardScope(s)
			if got.Endpoint != tt.wantEP {
				t.Errorf("wildcardScope().Endpoint = %q; want %q", got.Endpoint, tt.wantEP)
			}
			if got.Type.Value != tt.wantType {
				t.Errorf("wildcardScope().Type = %q; want %q", got.Type.Value, tt.wantType)
			}
		})
	}
}
