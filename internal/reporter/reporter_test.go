package reporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brenu/bounty-cli/internal/db"
)

func TestParseNucleiOutput(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "reporter_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	jsonlPath := filepath.Join(tempDir, "results.jsonl")

	// Write mock JSONL findings
	mockData := `{"template-id":"template-1","matched-at":"https://target1.com","info":{"name":"Vuln 1","severity":"info","description":"Desc 1"}}
{"template-id":"template-2","matched-at":"https://target2.com","info":{"name":"Vuln 2","severity":"high","description":"Line 1\nLine 2"}}`

	err = os.WriteFile(jsonlPath, []byte(mockData), 0644)
	if err != nil {
		t.Fatalf("failed to write mock jsonl: %v", err)
	}

	findings, err := ParseNucleiOutput(jsonlPath)
	if err != nil {
		t.Fatalf("ParseNucleiOutput failed: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.TemplateID != "template-1" || f1.MatchedAt != "https://target1.com" {
		t.Errorf("unexpected finding 1 values: %+v", f1)
	}
	if f1.Info.Name != "Vuln 1" || f1.Info.Severity != "info" || f1.Info.Description != "Desc 1" {
		t.Errorf("unexpected finding 1 info: %+v", f1.Info)
	}

	// Test with a very long line that would exceed default bufio.Scanner buffer (64KB)
	longDesc := strings.Repeat("A", 70*1024)
	longLine := `{"template-id":"long-template","matched-at":"https://long.com","info":{"name":"Long Vuln","severity":"info","description":"` + longDesc + `"}}`
	
	err = os.WriteFile(jsonlPath, []byte(longLine), 0644)
	if err != nil {
		t.Fatalf("failed to write long jsonl: %v", err)
	}

	findings, err = ParseNucleiOutput(jsonlPath)
	if err != nil {
		t.Fatalf("ParseNucleiOutput failed on long line: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for long line, got %d", len(findings))
	}
	if findings[0].Info.Description != longDesc {
		t.Errorf("long description mismatch")
	}

	// Test de-duplication
	dupData := `{"template-id":"dup","matched-at":"target.com","info":{"name":"Dup"}}
{"template-id":"dup","matched-at":"target.com","info":{"name":"Dup"}}`
	err = os.WriteFile(jsonlPath, []byte(dupData), 0644)
	if err != nil {
		t.Fatalf("failed to write dup jsonl: %v", err)
	}

	findings, err = ParseNucleiOutput(jsonlPath)
	if err != nil {
		t.Fatalf("ParseNucleiOutput failed on dup: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding after de-duplication, got %d", len(findings))
	}
}

func TestReportGenerator_Generate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "reporter_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outputPath := filepath.Join(tempDir, "report.md")

	findings := []db.NucleiFinding{
		{
			TemplateID: "dns-detect",
			MatchedAt:  "target.com",
		},
	}
	findings[0].Info.Name = "DNS Detect"
	findings[0].Info.Severity = "info"
	findings[0].Info.Description = "DNS finding description."

	rg := NewReportGenerator(
		"Test Program",
		[]string{"sub.target.com"},
		[]string{"target.com"},
		findings,
		true,
	)

	err = rg.Generate(outputPath)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Read and verify file contents
	contentBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read generated report: %v", err)
	}
	content := string(contentBytes)

	expectedHeaders := []string{
		"# Bug Bounty Report: Test Program (New Findings Only)",
		"## Summary",
		"## Discovered Subdomains",
		"- sub.target.com",
		"## Live Hosts & Services",
		"- target.com",
		"## Vulnerabilities Found",
		"| Severity | Name | Description | Target | Template ID |",
		"|----------|------|-------------|--------|-------------|",
		"| INFO | DNS Detect | DNS finding description. | target.com | dns-detect |",
	}

	for _, header := range expectedHeaders {
		if !strings.Contains(content, header) {
			t.Errorf("expected report to contain %q, but it didn't", header)
		}
	}
}

func TestGetUniqueReportPath(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "reporter_version_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	programName := "Test Program"
	
	// Test first report
	path1 := GetUniqueReportPath(tempDir, programName)
	expected1 := filepath.Join(tempDir, "Test_Program.md")
	if path1 != expected1 {
		t.Errorf("expected %q, got %q", expected1, path1)
	}

	// Create the file
	if err := os.WriteFile(path1, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Test second report (v1)
	path2 := GetUniqueReportPath(tempDir, programName)
	expected2 := filepath.Join(tempDir, "Test_Program_v1.md")
	if path2 != expected2 {
		t.Errorf("expected %q, got %q", expected2, path2)
	}

	// Create the second file
	if err := os.WriteFile(path2, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Test third report (v2)
	path3 := GetUniqueReportPath(tempDir, programName)
	expected3 := filepath.Join(tempDir, "Test_Program_v2.md")
	if path3 != expected3 {
		t.Errorf("expected %q, got %q", expected3, path3)
	}
}
