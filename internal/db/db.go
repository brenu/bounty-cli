package db

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	conn *sql.DB
}

type NucleiFinding struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
}

func NewDatabase(path string) (*Database, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS domains (
			id INTEGER PRIMARY KEY,
			domain TEXT UNIQUE,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY,
			template_id TEXT,
			target TEXT,
			severity TEXT,
			name TEXT,
			description TEXT,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(template_id, target)
		);
	`)
	if err != nil {
		return nil, err
	}

	_, _ = db.Exec("ALTER TABLE findings ADD COLUMN description TEXT")

	return &Database{conn: db}, nil
}

func (d *Database) SaveDomains(domains []string) error {
	tx, err := d.conn.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO domains (domain) VALUES (?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, domain := range domains {
		_, err = stmt.Exec(domain)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *Database) IsNewFinding(finding *NucleiFinding) (bool, error) {
	var count int
	err := d.conn.QueryRow(
		"SELECT COUNT(*) FROM findings WHERE template_id = ? AND target = ?",
		finding.TemplateID, finding.MatchedAt,
	).Scan(&count)
	return count == 0, err
}

func (d *Database) SaveFindings(findings []NucleiFinding) error {
	tx, err := d.conn.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO findings (template_id, target, severity, name, description) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range findings {
		_, err = stmt.Exec(f.TemplateID, f.MatchedAt, f.Info.Severity, f.Info.Name, f.Info.Description)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
