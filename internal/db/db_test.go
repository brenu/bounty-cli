package db

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestDatabase_Workflow(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "db_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")

	// 1. Test creation
	database, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	defer database.conn.Close()

	// 2. Test saving domains
	domains := []string{"target.com", "sub.target.com"}
	err = database.SaveDomains(domains)
	if err != nil {
		t.Errorf("failed to save domains: %v", err)
	}

	// 3. Test saving findings and IsNewFinding deduplication
	finding := NucleiFinding{
		TemplateID: "cve-1234",
		MatchedAt:  "https://target.com",
	}
	finding.Info.Name = "Test CVE"
	finding.Info.Severity = "high"
	finding.Info.Description = "A mock high severity finding."

	// Should be new initially
	isNew, err := database.IsNewFinding(&finding)
	if err != nil {
		t.Errorf("failed checking IsNewFinding: %v", err)
	}
	if !isNew {
		t.Error("expected finding to be new, but got false")
	}

	// Save findings
	err = database.SaveFindings([]NucleiFinding{finding})
	if err != nil {
		t.Errorf("failed to save findings: %v", err)
	}

	// Should not be new anymore
	isNew, err = database.IsNewFinding(&finding)
	if err != nil {
		t.Errorf("failed checking IsNewFinding: %v", err)
	}
	if isNew {
		t.Error("expected finding to not be new, but got true")
	}

	// Verify database content
	var severity, name, description string
	err = database.conn.QueryRow("SELECT severity, name, description FROM findings WHERE template_id = ?", "cve-1234").Scan(&severity, &name, &description)
	if err != nil {
		t.Fatalf("failed to query saved finding: %v", err)
	}

	if severity != "high" {
		t.Errorf("expected severity 'high', got %q", severity)
	}
	if name != "Test CVE" {
		t.Errorf("expected name 'Test CVE', got %q", name)
	}
	if description != "A mock high severity finding." {
		t.Errorf("expected description 'A mock high severity finding.', got %q", description)
	}
}

func TestDatabase_AutoMigration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "db_migration_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "migration.db")

	// Create a database with the old schema (no description column)
	rawDb, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open raw sqlite db: %v", err)
	}
	_, err = rawDb.Exec(`
		CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY,
			template_id TEXT,
			target TEXT,
			severity TEXT,
			name TEXT,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(template_id, target)
		);
	`)
	if err != nil {
		rawDb.Close()
		t.Fatalf("failed to initialize old schema: %v", err)
	}
	rawDb.Close()

	// Initialize database using our code - should dynamically run the ALTER TABLE migration
	database, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("NewDatabase failed during migration: %v", err)
	}
	defer database.conn.Close()

	// Verify we can insert a description successfully
	finding := NucleiFinding{
		TemplateID: "cve-migrated",
		MatchedAt:  "https://target.com",
	}
	finding.Info.Name = "Test CVE Migrated"
	finding.Info.Severity = "medium"
	finding.Info.Description = "Auto-migrated description test"

	err = database.SaveFindings([]NucleiFinding{finding})
	if err != nil {
		t.Errorf("failed to save findings after auto-migration: %v", err)
	}
}
