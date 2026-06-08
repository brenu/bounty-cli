package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/brenu/bounty-cli/internal/db"
)

type ReportGenerator struct {
	ProgramName string
	Subdomains  []string
	LiveHosts   []string
	Findings    []db.NucleiFinding
	IsNewOnly   bool
}

func NewReportGenerator(name string, subs, hosts []string, findings []db.NucleiFinding, newOnly bool) *ReportGenerator {
	return &ReportGenerator{name, subs, hosts, findings, newOnly}
}

func (rg *ReportGenerator) Generate(outputPath string) error {
	var sb strings.Builder
	reportType := "Full Scan"
	if rg.IsNewOnly {
		reportType = "New Findings Only"
	}

	sb.WriteString(fmt.Sprintf("# Bug Bounty Report: %s (%s)\n\n", rg.ProgramName, reportType))
	sb.WriteString("## Summary\n")
	sb.WriteString(fmt.Sprintf("- **Total Subdomains Discovered:** %d\n", len(rg.Subdomains)))
	sb.WriteString(fmt.Sprintf("- **Total Live Hosts Identified:** %d\n", len(rg.LiveHosts)))
	sb.WriteString(fmt.Sprintf("- **Relevant Findings in this Report:** %d\n\n", len(rg.Findings)))

	sb.WriteString("## Discovered Subdomains\n")
	for _, sub := range rg.Subdomains {
		sb.WriteString(fmt.Sprintf("- %s\n", sub))
	}
	sb.WriteString("\n## Live Hosts & Services\n")
	for _, host := range rg.LiveHosts {
		sb.WriteString(fmt.Sprintf("- %s\n", host))
	}

	sb.WriteString("\n## Vulnerabilities Found\n")
	if len(rg.Findings) == 0 {
		sb.WriteString("No new vulnerabilities found.\n")
	} else {
		sb.WriteString("| Severity | Name | Description | Target | Template ID |\n|----------|------|-------------|--------|-------------|\n")
		for _, f := range rg.Findings {
			desc := strings.ReplaceAll(strings.ReplaceAll(f.Info.Description, "\n", " "), "\r", "")
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				strings.ToUpper(f.Info.Severity), f.Info.Name, desc, f.MatchedAt, f.TemplateID))
		}
	}

	return os.WriteFile(outputPath, []byte(sb.String()), 0644)
}

func GetUniqueReportPath(baseDir, programName string) string {
	// Ensure directory exists
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		os.MkdirAll(baseDir, 0755)
	}

	// Sanitize program name for filename
	safeName := strings.ReplaceAll(programName, " ", "_")
	safeName = strings.ReplaceAll(safeName, "/", "-")

	filename := fmt.Sprintf("%s.md", safeName)
	path := filepath.Join(baseDir, filename)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}

	// Versioning
	counter := 1
	for {
		filename = fmt.Sprintf("%s_v%d.md", safeName, counter)
		path = filepath.Join(baseDir, filename)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return path
		}
		counter++
	}
}

func ParseNucleiOutput(path string) ([]db.NucleiFinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []db.NucleiFinding
	seen := make(map[string]bool)
	decoder := json.NewDecoder(file)
	for decoder.More() {
		var f db.NucleiFinding
		if err := decoder.Decode(&f); err != nil {
			// Skip malformed lines if any
			continue
		}
		
		key := fmt.Sprintf("%s-%s", f.TemplateID, f.MatchedAt)
		if !seen[key] {
			findings = append(findings, f)
			seen[key] = true
		}
	}
	return findings, nil
}
