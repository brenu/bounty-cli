package scope

import (
	"regexp"
	"strings"

	"github.com/brenu/bounty-cli/internal/api"
)

type ScopeManager struct {
	inScope    []api.Scope
	outOfScope []api.Scope
}

func NewScopeManager(scopes []api.Scope) *ScopeManager {
	var inScope, outOfScope []api.Scope
	for _, s := range scopes {
		if s.Tier.Value == "Out of Scope" {
			outOfScope = append(outOfScope, s)
		} else {
			inScope = append(inScope, s)
		}
	}
	return &ScopeManager{inScope: inScope, outOfScope: outOfScope}
}

func (sm *ScopeManager) IsAllowed(endpoint string) bool {
	for _, oos := range sm.outOfScope {
		if sm.matches(oos.Endpoint, endpoint) {
			return false
		}
	}

	for _, is := range sm.inScope {
		if sm.matches(is.Endpoint, endpoint) {
			return true
		}
	}

	return false
}

func (sm *ScopeManager) matches(pattern, target string) bool {
	pattern = strings.TrimSpace(pattern)
	target = strings.TrimSpace(target)

	if pattern == target {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return target == base || strings.HasSuffix(target, "."+base)
	}

	// Simple regex conversion
	regexPattern := "^" + strings.ReplaceAll(strings.ReplaceAll(pattern, ".", "\\."), "*", ".*") + "$"
	if re, err := regexp.Compile(regexPattern); err == nil {
		return re.MatchString(target)
	}

	return false
}

func (sm *ScopeManager) GetInitialTargets() []string {
	var targets []string
	for _, s := range sm.inScope {
		if s.Type.Value == "Url" || s.Type.Value == "Domain" || s.Type.Value == "Wildcard" {
			targets = append(targets, s.Endpoint)
		}
	}
	return targets
}

// GetReconTargets returns scope endpoints suitable for subdomain recon,
// filtered by the given mode:
//   - "wildcard" — only Wildcard-type scopes (e.g. *.example.com → example.com)
//   - "domain"   — Wildcard + Domain-type scopes
//
// Url-type scopes are never included — subdomain enumeration tools expect
// a domain name, not a full URL.
func (sm *ScopeManager) GetReconTargets(mode string) []string {
	var targets []string
	for _, s := range sm.inScope {
		switch mode {
		case "domain":
			if s.Type.Value == "Domain" || s.Type.Value == "Wildcard" {
				targets = append(targets, strings.TrimPrefix(s.Endpoint, "*."))
			}
		default: // "wildcard"
			if s.Type.Value == "Wildcard" {
				targets = append(targets, strings.TrimPrefix(s.Endpoint, "*."))
			}
		}
	}
	return targets
}
