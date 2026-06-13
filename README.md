# bounty-cli

A Go command-line tool that automates bug bounty recon and vulnerability discovery. It integrates with the [Intigriti Researcher API](https://www.intigriti.com/) to fetch program scope, runs subdomain discovery and live-host probing, scans targets with [Nuclei](https://github.com/projectdiscovery/nuclei), deduplicates findings in SQLite, and writes versioned Markdown reports.

## Features

- Fetch in-scope assets from an Intigriti program, or scan a direct target / explicit FQDN list
- Subdomain enumeration via `subfinder` and `amass` (optional)
- Port scanning with `naabu` and live-host detection with `httpx`
- Vulnerability scanning with Nuclei (medium, high, and critical severity)
- SQLite-backed deduplication so repeat scans only surface new findings
- Automatic Markdown reports in `reports/` with program-based naming and versioning
- Optional LLM triage of new findings and Telegram notifications via [notify](https://github.com/projectdiscovery/notify)

## Prerequisites

### Required

- **Go** 1.25+
- External tools on your `PATH` (from [ProjectDiscovery](https://projectdiscovery.io/) and [OWASP Amass](https://github.com/owasp-amass/amass)):
  - `subfinder`
  - `amass`
  - `naabu`
  - `httpx`
  - `nuclei`

### Optional (for LLM triage and notifications)

- An OpenAI-compatible LLM endpoint (defaults to local [Ollama](http://localhost:11434))
- [notify](https://github.com/projectdiscovery/notify) configured with a Telegram provider (default provider ID: `tel`)

## Installation

Clone the repository and build the binary:

```bash
git clone https://github.com/brenu/bounty-cli.git
cd bounty-cli
go build -o bounty_cli main.go
```

## Configuration

| Variable | Required when | Description |
|---|---|---|
| `INTIGRITI_TOKEN` | Using `--program-id` | Bearer token for the Intigriti Researcher API |
| `LLM_API_KEY` | Hosted LLM providers | API key for OpenAI-compatible endpoints (overridden by `--llm-api-key`) |

## Usage

The tool accepts exactly one input mode: `--program-id`, `--target`, or `--fqdn`.

### Scan an Intigriti program

```bash
export INTIGRITI_TOKEN="your_token_here"
./bounty_cli --program-id <program-id>
```

The pipeline fetches program scope, respects the program's max RPS from rules of engagement, and names the report after the program.

### Scan a direct target

Skip the Intigriti API and treat a domain or wildcard as in scope:

```bash
./bounty_cli --target "*.example.com"
```

### Scan explicit FQDNs

Provide a fixed list of hosts. This skips Intigriti. Recon is skipped by default but can be enabled with `--skip-recon=false`:

```bash
./bounty_cli --program-name "Acme Corp" \
  --fqdn www.example.com \
  --fqdn api.example.com \
  --fqdn staging.example.com
```

Pipe a large asset list from a file or another command:

```bash
cat assets.txt | ./bounty_cli --program-name "Acme Corp"
subfinder -d example.com -silent | ./bounty_cli --program-name "Acme Corp"
./bounty_cli --program-name "Acme Corp" --fqdn - < assets.txt
```

Lines starting with `#` and blank lines are ignored. Comma-separated values on a single line are also supported.

### Enable subdomain recon

Recon is skipped by default. Pass `--skip-recon=false` to run `subfinder` and `amass` on each initial target:

```bash
./bounty_cli --program-id <program-id> --skip-recon=false
```

Pipe root domains and run recon on them:

```bash
cat root-domains.txt | ./bounty_cli --program-name "Acme Corp" --skip-recon=false
```

### Skip port scanning

When naabu is not needed, httpx probes ports 80 and 443 directly:

```bash
./bounty_cli --program-id <program-id> --skip-naabu
```

### LLM triage with a hosted model

By default, the tool queries a local Ollama instance and sends triaged findings to Telegram. To use a hosted model:

```bash
export LLM_API_KEY="your_api_key"
./bounty_cli --program-id <program-id> \
  --llm-url https://openrouter.ai/api/v1 \
  --llm-model anthropic/claude-sonnet-4
```

Skip analysis and notifications entirely:

```bash
./bounty_cli --program-id <program-id> --skip-analysis
```

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `--program-id` | | Intigriti program ID |
| `--target` | | Direct target domain or wildcard (skips Intigriti) |
| `--fqdn` | | FQDN to scan (repeatable; use `-` for stdin) |
| `--program-name` | | Program name for report filenames (required with `--fqdn`) |
| `--db` | `bounty.db` | SQLite database filename |
| `--skip-recon` | `true` | Skip subdomain discovery (`subfinder`, `amass`) |
| `--concurrency` | `1` | Number of concurrent root-domain groups to process (1 = sequential). Groups targets by registered domain; each group runs at full RPS |
| `--skip-naabu` | `false` | Skip port scan; httpx probes 80/443 directly |
| `--skip-analysis` | `false` | Skip LLM triage and Telegram notification |
| `--llm-url` | `http://localhost:11434/v1` | OpenAI-compatible LLM endpoint |
| `--llm-model` | `hf.co/bartowski/gemma-4-e4b-it-GGUF:Q4_K_M` | LLM model name |
| `--llm-api-key` | | Bearer token for the LLM API |
| `--notify-id` | `tel` | notify provider ID (matches `id:` in `provider-config.yaml`) |

## Pipeline

```
Fetch scope → Recon (optional) → Scope filter → [naabu] → [httpx] → [nuclei] → Deduplicate → Report → LLM triage (optional)
```

With `--concurrency > 1`, the `[naabu]`, `[httpx]`, and `[nuclei]` phases each run concurrently across root-domain groups. All groups finish one phase before the next begins.

1. **Scope** — Assets come from Intigriti, a `--target` wildcard, or an explicit `--fqdn` list.
2. **Recon** — `subfinder` and `amass` discover subdomains (when enabled).
3. **Filter** — Only in-scope hosts are kept.
4. **Discovery** — `naabu` finds open ports; `httpx` confirms live web servers.
5. **Scan** — Nuclei runs against live hosts; results are written to `nuclei_results.jsonl`.
6. **Deduplicate** — New findings are compared against the SQLite database (`bounty.db` by default).
7. **Report** — A Markdown report is saved under `reports/` (e.g. `ProgramName.md`, `ProgramName_v1.md`).
8. **Triage** — An LLM reviews new findings and actionable results are sent via `notify`.

## Output

- **`bounty.db`** — SQLite database tracking discovered domains and findings across runs.
- **`reports/`** — Versioned Markdown reports named after the program or target.
- **`nuclei_results.jsonl`** — Raw Nuclei output from the latest scan.

## Development

Run the test suite:

```bash
go test -v ./...
```

Additional documentation:

- [docs/project.md](docs/project.md) — Capabilities and project status
- [docs/spec.md](docs/spec.md) — API contracts and database schema
- [docs/design.md](docs/design.md) — Architecture overview

## License

See the repository for license information.
