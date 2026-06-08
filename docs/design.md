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
