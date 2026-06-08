# Technical Specification

## API Integration
- **Official Documentation:** [Intigriti Researcher API](https://intigriti-researcher-api.readme.io/)
- **Base URL:** `https://api.intigriti.com/external/researcher/v1`
- **Auth:** Bearer Token via `INTIGRITI_TOKEN` environment variable.
- **Required Endpoints:**
    - `GET /programs/{programID}`: Fetch program details, including `versionId`.
    - `GET /programs/{programID}/domains/{versionID}`: Retrieve the current program scope.

## Dependencies
The following tools must be installed and accessible in the system `$PATH`:
- `subfinder`: Passive/Active subdomains.
- `amass`: Passive subdomains.
- `naabu`: Port scanning/Live host discovery.
- `httpx`: Probing and HTTP status checks.
- `nuclei`: Vulnerability scanning.

## Database Schema (SQLite)
- **domains**: Tracks discovered in-scope domains.
- **findings**: Stores unique vulnerability findings identified by `template_id` and `target`, including their metadata, severity, and description.

