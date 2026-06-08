package tools

import "testing"

func TestCleanDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://example.com/api", "example.com"},
		{"https://sub.domain.local:8080/path?query=1", "sub.domain.local"},
		{"example.com", "example.com"},
		{"  sub.example.com  ", "sub.example.com"},
		{"http://127.0.0.1:8000/", "127.0.0.1"},
		{"*.example.com", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := cleanDomain(tt.input)
			if got != tt.expected {
				t.Errorf("cleanDomain(%q) = %q; want %q", tt.input, got, tt.expected)
			}
		})
	}
}
