// Package group provides root-domain extraction and target grouping utilities
// for concurrent pipeline execution. Targets sharing the same root domain
// (e.g. sub1.example.com and sub2.example.com → example.com) are grouped
// together so they can be processed as a unit.
package group

import (
	"strconv"
	"strings"
)

// Group holds a named bucket of targets sharing the same root domain.
type Group struct {
	Root    string
	Targets []string
}

// ExtractRoot returns the registered domain portion of host, using a
// "last two dot-separated parts" heuristic. Strips port numbers and
// URL schemes first. Single-label and two-label names are returned as-is.
//
//	ExtractRoot("sub.example.com:443")   → "example.com"
//	ExtractRoot("example.com")           → "example.com"
//	ExtractRoot("localhost")             → "localhost"
//	ExtractRoot("192.168.1.1")           → "168.1"
//	ExtractRoot("")                      → ""
func ExtractRoot(host string) string {
	host = strings.TrimSpace(host)

	// Strip URL scheme (e.g. "https://")
	if idx := strings.Index(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}

	// Strip trailing path (after first /)
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}

	// Strip trailing port (host:port where port is numeric)
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		portPart := host[idx+1:]
		if _, err := strconv.Atoi(portPart); err == nil {
			host = host[:idx]
		}
	}

	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// ByRootDomain partitions hosts into Groups keyed by their root domain.
// The returned slice preserves the insertion order of each root domain's
// first occurrence. Each host appears in exactly one group.
func ByRootDomain(hosts []string) []Group {
	groupsMap := make(map[string]*Group)
	var order []string

	for _, h := range hosts {
		root := ExtractRoot(h)
		if g, ok := groupsMap[root]; ok {
			g.Targets = append(g.Targets, h)
		} else {
			order = append(order, root)
			groupsMap[root] = &Group{Root: root, Targets: []string{h}}
		}
	}

	result := make([]Group, len(order))
	for i, root := range order {
		result[i] = *groupsMap[root]
	}
	return result
}
