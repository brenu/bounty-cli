package group

import (
	"reflect"
	"testing"
)

func TestExtractRoot(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sub.example.com", "example.com"},
		{"sub.example.com:443", "example.com"},
		{"example.com", "example.com"},
		{"localhost", "localhost"},
		{"192.168.1.1", "1.1"},
		{"", ""},
		{"  spaced.example.com  ", "example.com"},
		{"a.b.c.example.co.uk", "co.uk"}, // simple "last 2 parts" heuristic — known limitation for ccTLDs
		{"https://api.example.com/path", "example.com"},
		{"*.wildcard.example.com", "example.com"},
		{"single", "single"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ExtractRoot(tt.input)
			if got != tt.expected {
				t.Errorf("ExtractRoot(%q) = %q; want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestByRootDomain_Basic(t *testing.T) {
	hosts := []string{
		"sub1.example.com",
		"api.test.com",
		"sub2.example.com",
		"admin.test.com",
	}
	groups := ByRootDomain(hosts)

	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	// example.com group
	if groups[0].Root != "example.com" {
		t.Errorf("groups[0].Root = %q; want %q", groups[0].Root, "example.com")
	}
	wantExample := []string{"sub1.example.com", "sub2.example.com"}
	if !reflect.DeepEqual(groups[0].Targets, wantExample) {
		t.Errorf("groups[0].Targets = %v; want %v", groups[0].Targets, wantExample)
	}

	// test.com group
	if groups[1].Root != "test.com" {
		t.Errorf("groups[1].Root = %q; want %q", groups[1].Root, "test.com")
	}
	wantTest := []string{"api.test.com", "admin.test.com"}
	if !reflect.DeepEqual(groups[1].Targets, wantTest) {
		t.Errorf("groups[1].Targets = %v; want %v", groups[1].Targets, wantTest)
	}
}

func TestByRootDomain_SingleDomain(t *testing.T) {
	hosts := []string{
		"a.example.com",
		"b.example.com",
		"c.example.com",
	}
	groups := ByRootDomain(hosts)

	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].Root != "example.com" {
		t.Errorf("Root = %q; want %q", groups[0].Root, "example.com")
	}
	if len(groups[0].Targets) != 3 {
		t.Errorf("expected 3 targets, got %d", len(groups[0].Targets))
	}
}

func TestByRootDomain_Empty(t *testing.T) {
	groups := ByRootDomain(nil)
	if len(groups) != 0 {
		t.Errorf("expected empty result, got %d groups", len(groups))
	}

	groups = ByRootDomain([]string{})
	if len(groups) != 0 {
		t.Errorf("expected empty result, got %d groups", len(groups))
	}
}

func TestByRootDomain_PreservesInsertionOrder(t *testing.T) {
	hosts := []string{
		"x.foo.com",
		"a.bar.com",
		"y.foo.com",
		"z.baz.com",
	}
	groups := ByRootDomain(hosts)

	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}

	// Order must be: foo.com, bar.com, baz.com (first occurrence order)
	expectedRoots := []string{"foo.com", "bar.com", "baz.com"}
	for i, g := range groups {
		if g.Root != expectedRoots[i] {
			t.Errorf("groups[%d].Root = %q; want %q", i, g.Root, expectedRoots[i])
		}
	}
}

func TestByRootDomain_PortHandling(t *testing.T) {
	hosts := []string{
		"sub1.example.com:443",
		"sub2.example.com:80",
		"other.test.com:8080",
	}
	groups := ByRootDomain(hosts)

	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	// Both port-suffixed hosts should land in example.com
	if groups[0].Root != "example.com" {
		t.Errorf("groups[0].Root = %q; want %q", groups[0].Root, "example.com")
	}
	if len(groups[0].Targets) != 2 {
		t.Errorf("expected 2 targets in example.com, got %d", len(groups[0].Targets))
	}
}
