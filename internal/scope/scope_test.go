package scope

import (
	"testing"

	"github.com/brenu/bounty-cli/internal/api"
)

func TestScopeManager_IsAllowed(t *testing.T) {
	scopes := []api.Scope{
		{
			Endpoint: "example.com",
			Tier:     api.Tier{Value: "Tier 1"},
			Type:     api.AssetType{Value: "Domain"},
		},
		{
			Endpoint: "*.target.local",
			Tier:     api.Tier{Value: "Tier 2"},
			Type:     api.AssetType{Value: "Wildcard"},
		},
		{
			Endpoint: "oos.com",
			Tier:     api.Tier{Value: "Out of Scope"},
			Type:     api.AssetType{Value: "Domain"},
		},
	}

	sm := NewScopeManager(scopes)

	tests := []struct {
		name     string
		target   string
		expected bool
	}{
		{"exact match", "example.com", true},
		{"subdomain wildcard", "sub.target.local", true},
		{"base domain wildcard", "target.local", true},
		{"not allowed", "other.com", false},
		{"excluded via Tier", "oos.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sm.IsAllowed(tt.target)
			if got != tt.expected {
				t.Errorf("IsAllowed(%q) = %v; want %v", tt.target, got, tt.expected)
			}
		})
	}
}

func TestScopeManager_Matches(t *testing.T) {
	sm := &ScopeManager{}

	tests := []struct {
		pattern  string
		target   string
		expected bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "example.com ", true},
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "sub.sub.example.com", true},
		{"*.example.com", "other.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"->"+tt.target, func(t *testing.T) {
			got := sm.matches(tt.pattern, tt.target)
			if got != tt.expected {
				t.Errorf("matches(%q, %q) = %v; want %v", tt.pattern, tt.target, got, tt.expected)
			}
		})
	}
}

func TestScopeManager_GetInitialTargets(t *testing.T) {
	scopes := []api.Scope{
		{
			Endpoint: "example.com",
			Tier:     api.Tier{Value: "Tier 1"},
			Type:     api.AssetType{Value: "Domain"},
		},
		{
			Endpoint: "*.target.local",
			Tier:     api.Tier{Value: "Tier 1"},
			Type:     api.AssetType{Value: "Wildcard"},
		},
		{
			Endpoint: "https://target.com/api",
			Tier:     api.Tier{Value: "Tier 1"},
			Type:     api.AssetType{Value: "Url"},
		},
		{
			Endpoint: "some-ip",
			Tier:     api.Tier{Value: "Tier 1"},
			Type:     api.AssetType{Value: "CIDR"},
		},
	}

	sm := NewScopeManager(scopes)
	targets := sm.GetInitialTargets()

	if len(targets) != 3 {
		t.Errorf("expected 3 targets, got %d", len(targets))
	}

	if targets[0] != "example.com" || targets[1] != "*.target.local" || targets[2] != "https://target.com/api" {
		t.Errorf("unexpected targets: %v", targets)
	}
}

func TestGetReconTargets(t *testing.T) {
	scopes := []api.Scope{
		{
			Endpoint: "example.com",
			Tier:     api.Tier{Value: "Tier 1"},
			Type:     api.AssetType{Value: "Domain"},
		},
		{
			Endpoint: "*.target.local",
			Tier:     api.Tier{Value: "Tier 1"},
			Type:     api.AssetType{Value: "Wildcard"},
		},
		{
			Endpoint: "https://target.com/api",
			Tier:     api.Tier{Value: "Tier 1"},
			Type:     api.AssetType{Value: "Url"},
		},
		{
			Endpoint: "some-ip",
			Tier:     api.Tier{Value: "Tier 1"},
			Type:     api.AssetType{Value: "CIDR"},
		},
	}

	sm := NewScopeManager(scopes)

	t.Run("wildcard mode", func(t *testing.T) {
		got := sm.GetReconTargets("wildcard")
		if len(got) != 1 {
			t.Fatalf("expected 1 target, got %d: %v", len(got), got)
		}
		if got[0] != "target.local" {
			t.Errorf("got[0] = %q; want %q", got[0], "target.local")
		}
	})

	t.Run("domain mode", func(t *testing.T) {
		got := sm.GetReconTargets("domain")
		if len(got) != 2 {
			t.Fatalf("expected 2 targets, got %d: %v", len(got), got)
		}
		if got[0] != "example.com" {
			t.Errorf("got[0] = %q; want %q", got[0], "example.com")
		}
		if got[1] != "target.local" {
			t.Errorf("got[1] = %q; want %q", got[1], "target.local")
		}
	})

	t.Run("url excluded in both modes", func(t *testing.T) {
		gotWildcard := sm.GetReconTargets("wildcard")
		gotDomain := sm.GetReconTargets("domain")
		for _, g := range gotWildcard {
			if g == "target.com/api" || g == "https://target.com/api" {
				t.Errorf("wildcard mode includes URL scope: %q", g)
			}
		}
		for _, g := range gotDomain {
			if g == "target.com/api" || g == "https://target.com/api" {
				t.Errorf("domain mode includes URL scope: %q", g)
			}
		}
	})

	t.Run("cidr excluded in both modes", func(t *testing.T) {
		gotWildcard := sm.GetReconTargets("wildcard")
		gotDomain := sm.GetReconTargets("domain")
		for _, g := range gotWildcard {
			if g == "some-ip" {
				t.Errorf("wildcard mode includes CIDR scope: %q", g)
			}
		}
		for _, g := range gotDomain {
			if g == "some-ip" {
				t.Errorf("domain mode includes CIDR scope: %q", g)
			}
		}
	})

	t.Run("no matching scopes returns empty", func(t *testing.T) {
		onlyCIDR := []api.Scope{
			{
				Endpoint: "10.0.0.0/8",
				Tier:     api.Tier{Value: "Tier 1"},
				Type:     api.AssetType{Value: "CIDR"},
			},
		}
		sm2 := NewScopeManager(onlyCIDR)
		if got := sm2.GetReconTargets("wildcard"); len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
		if got := sm2.GetReconTargets("domain"); len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})
}
