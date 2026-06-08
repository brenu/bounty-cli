# AI Agent Context Guide (AGENTS.md)

This document provides immediate, structured context about the Bug Bounty CLI project for future AI coding assistants. Read this file to understand the architecture, database schemas, command orchestration, and guidelines.

---

## 1. Project Overview
A Go-based command-line interface designed to automate bug bounty recon and vulnerability discovery. It integrates with the Intigriti Researcher API to fetch program scope, runs automated subdomain discovery, probes live web servers, scans for vulnerabilities using Nuclei, saves findings to SQLite, deduplicates issues, and writes a Markdown report.

- **Stack:** Go (Modules-based), SQLite3 (`github.com/mattn/go-sqlite3`)
- **Key Specifications Location:** 
  - [project.md](file:///home/eu-mesmo/projetos/agents/scripts/bounty_cli/docs/project.md) (Capabilities & Status)
  - [spec.md](file:///home/eu-mesmo/projetos/agents/scripts/bounty_cli/docs/spec.md) (Tech specifications, API contracts, SQLite schema details)
  - [design.md](file:///home/eu-mesmo/projetos/agents/scripts/bounty_cli/docs/design.md) (Architecture overview & packages)

---

## 2. Directory Structure & Architecture

```text
├── bounty_cli          # Compiled production binary
├── docs/
│   ├── project.md      # General project info
│   ├── spec.md         # Database schema & technical specification
│   └── design.md       # Architecture & design document
├── go.mod / go.sum     # Go module files
├── main.go             # Pipeline orchestrator and CLI entry point
├── reports/            # Generated versioned markdown reports
└── internal/
    ├── api/            # Intigriti Researcher API Client
    ├── db/             # SQLite connection, persistence, and deduplication
    ├── reporter/       # Parsing JSONL and generating reports
    ├── scope/          # Validating and matching target wildcard scopes
    └── tools/          # Wrappers for external processes
```

---

## 3. Database Schema (SQLite)
The tool persists discoveries inside `bounty.db` (default) using two tables:

- **`domains`**:
  - `id` INTEGER PRIMARY KEY
  - `domain` TEXT UNIQUE
  - `first_seen` DATETIME (default: `CURRENT_TIMESTAMP`)

- **`findings`**:
  - `id` INTEGER PRIMARY KEY
  - `template_id` TEXT
  - `target` TEXT
  - `severity` TEXT
  - `name` TEXT
  - `description` TEXT
  - `first_seen` DATETIME (default: `CURRENT_TIMESTAMP`)
  - `UNIQUE(template_id, target)`

> [!NOTE]
> `internal/db` automatically runs migration logic (`ALTER TABLE findings ADD COLUMN description TEXT`) on database initialization, guaranteeing seamless schema upgrades without breaking existing databases.

---

## 4. Key Orchestration Rules & Hostname Safety
- **Recon/Discovery Tools:** `subfinder`, `amass`, and `naabu` do not tolerate full URLs (e.g. `https://example.com/api`).
- **Safety Mechanism:** The `internal/tools` package contains a private helper `cleanDomain` which extracts raw hostnames from URLs. Inputs for `RunSubfinder`, `RunAmass`, and `RunNaabu` are automatically sanitized before invoking command processes.
- **Reporting Format:** The reporter standardizes findings from Nuclei, replacing inner newlines (`\n` and `\r`) in descriptions with single spaces to keep the generated Markdown table aligned and properly formatted.

---

## 5. Development & Testing Commands

### Build & Compilation
Build the production binary:
```bash
go build -o bounty_cli main.go
```

### Running the Tool
Run the pipeline (requires `INTIGRITI_TOKEN` set):
```bash
export INTIGRITI_TOKEN="your_token_here"
./bounty_cli --program-id <program-id> [flags]
```
**Flags:**
- `--program-id`: Target Intigriti program ID.
- `--target`: Direct target domain or wildcard (skips Intigriti API).
- `--fqdn`: Explicit FQDN to scan (repeatable; comma-separated values also accepted). Pass `-` or pipe FQDNs via stdin (one per line). Skips Intigriti API and recon. Requires `--program-name`.
- `--program-name`: Program name used for report filenames when scanning with `--fqdn`.
- `--db`: Custom database filename (default: `bounty.db`).
- `--skip-recon`: Set true (default) to bypass active/passive subdomain discovery phases.
- `--skip-naabu`: Skip naabu port scan; httpx will probe 80/443 directly on the filtered host list.
- `--llm-url`: OpenAI-compatible LLM endpoint base URL (default: local Ollama).
- `--llm-model`: Model name for LLM triage analysis.
- `--llm-api-key`: Bearer token for authenticated LLM providers (overrides `LLM_API_KEY` env var).
- `--skip-analysis`: Skip LLM triage analysis and Telegram notification.

> [!NOTE]
> Reports are automatically generated in the `reports/` folder, named after the program, with automatic versioning (e.g., `ProgramName.md`, `ProgramName_v1.md`, etc.).

Scan a predefined list of FQDNs (skips Intigriti API and recon):
```bash
./bounty_cli --program-name "Acme Corp" \
  --fqdn www.example.com \
  --fqdn api.example.com \
  --fqdn staging.example.com
```

Pipe a large asset list from another command or file:
```bash
cat assets.txt | ./bounty_cli --program-name "Acme Corp"
subfinder -d example.com -silent | ./bounty_cli --program-name "Acme Corp"
./bounty_cli --program-name "Acme Corp" --fqdn - < assets.txt
```

Use Claude (or any OpenAI-compatible hosted model) for LLM triage:
```bash
export LLM_API_KEY="your_claude_api_key"
./bounty_cli --program-id <program-id> \
  --llm-url https://openrouter.ai/api/v1 \
  --llm-model anthropic/claude-sonnet-4
```

### Executing Tests
All packages include idiomatic Go table-driven unit tests. Run the full test suite with:
```bash
go test -v ./...
```
