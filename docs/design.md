# Design Document

## Architecture Overview
The application follows a modular, package-based design in Go to ensure separation of concerns and maintainability.

### Package Structure
- `main`: Entry point, command-line argument parsing, and workflow orchestration.
- `internal/api`: Intigriti client for API communication.
- `internal/db`: SQLite database interaction wrapper.
- `internal/scope`: Domain filtering logic and scope matching.
- `internal/tools`: Wrapper for external process orchestration (`os/exec`).
- `internal/reporter`: Generation of Markdown reports and parsing of Nuclei output.

## Design Principles
- **Orchestration**: The `main` package orchestrates the lifecycle: Init -> Fetch -> Recon -> Discovery -> Scan -> Deduplicate -> Report.
- **Automated Reporting**: Reports are automatically saved to the `reports/` directory. Filenames are derived from the program name and include automatic versioning (v1, v2, etc.) to prevent overwriting previous results.
- **Error Handling**: Standard Go error propagation.
- **External Tooling**: Minimal wrapper approach, delegating logic to industry-standard tools for reliability.
- **State Management**: Deduplication relies on a local SQLite database to prevent redundant reporting of known findings.

## Concurrency Model

The Live Host Discovery (naabu → httpx) and Scanning (nuclei) phases support concurrent execution via a `--concurrency` flag (default 1 = sequential).

### Root-Domain Grouping
Targets are partitioned into groups by their registered domain (last two dot-separated parts). All subdomains of `example.com` (e.g., `sub1.example.com`, `sub2.example.com`) form one group — they are always processed together.

### Worker Pool
A channel-based semaphore pattern limits concurrent goroutines. A `sync.WaitGroup` ensures all groups complete one tool phase before the next begins (barrier).

### Per-Tool Barriers
All groups finish naabu before httpx starts, and all groups finish httpx before nuclei starts. Within each phase, groups run independently and concurrently up to the `--concurrency` limit.

### Temp File Strategy for Nuclei
When running concurrently, each group writes nuclei output to a separate temporary JSONL file. After all groups finish, the temporary files are parsed and findings are merged. The temp directory is cleaned up automatically.
