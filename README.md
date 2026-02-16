# Ada - Audit Aggregator

ADA is a security vulnerability aggregation tool that detects, audits, and consolidates dependency security findings from multiple package managers and external scanners into unified branded reports.

<div align="center">
  <img width="650" src="https://github.com/user-attachments/assets/65e7d21d-5d19-46cc-8ddf-775ed9675355" alt="sample"> <br><br>
</div>

### Features

- **Multi-Project Detection**: Automatically identifies npm, Composer, and other project types
- **External Scanner Support**: Consumes JSON output from Snyk, npm audit, composer audit, and merges them into a single report
- **Dependency Collection**: Walks source trees to find and classify dependency manifests (scannable vs vendored)
- **OSV.dev Integration**: Queries OSV.dev for vulnerabilities in vendored/bundled dependencies
- **Report Merging**: Consolidates multiple scan results into one unified HTML/JSON report
- **Custom Branding**: Configurable company theming, logos, and colors via `~/.config/ada.config`
- **Zero Dependencies**: Self-contained Go binary with embedded default configuration

### Installation

```bash
git clone https://github.com/rvizx/ada.git
cd ada
go build -o ada ./cmd/ada
sudo mv ada /usr/local/bin/ada
```

**Prerequisites**: Go 1.24+

### Commands

#### `ada audit` — Run security audits directly

Navigate to a project directory and run audits. Ada auto-detects project types (npm, Composer, etc.) and runs the appropriate audit tools.

```bash
ada audit              # Generate both JSON and HTML reports
ada audit --json       # JSON only
ada audit --html       # HTML only
```

**Output**: `ada-audit-report.json`, `ada-report.html`

#### `ada report --from-json` — Generate reports from external scanner output

Consume JSON output from external scanners (e.g., Snyk) and generate consolidated branded reports. Auto-detects the input format.

```bash
ada report --from-json scan-results.json --html             # Single file → HTML
ada report --from-json scan1.json scan2.json --html --json  # Merge multiple → HTML + JSON
```

This is the primary integration point for CI/CD pipelines where scanning is handled by tools like Snyk, and Ada handles report generation.

**Output**: `ada-report.html`, `ada-audit-report.json`

#### `ada collect` — Collect dependency manifests from source

Walks a source directory, finds dependency manifest and lock files, copies them preserving structure, and classifies each target as scannable or vendored/bundled.

```bash
ada collect --source ./repo --out ./deps
```

**Output**: `ada-collect-manifest.json` in the output directory

#### `ada osv` — Scan vendored dependencies via OSV.dev

Reads a collect manifest and queries [OSV.dev](https://osv.dev) for known vulnerabilities in vendored libraries. Output is compatible with `ada report --from-json`.

```bash
ada osv --manifest ada-collect-manifest.json           # JSON report (default)
ada osv --manifest ada-collect-manifest.json --html    # HTML report
```

**Output**: `ada-osv-report.json`

### CI/CD Integration

Ada is designed to plug into CI/CD pipelines as the report consolidation layer. A typical flow:

```
Scanner (Snyk/npm audit/etc.)          Ada
─────────────────────────────    ──────────────────────
snyk test --json → result1.json ─┐
snyk test --json → result2.json ─┼→ ada report --from-json *.json --html --json
snyk test --json → result3.json ─┘         ↓
                                    ada-report.html (branded)
                                    ada-audit-report.json (machine-readable)
```

### Configuration

Create `~/.config/ada.config` to customize branding:

```json
{
  "theme": {
    "primaryColor": "#ff8f1a",
    "headerBackground": "#ff8f1a",
    "headerTextColor": "#fff"
  },
  "company": {
    "title": "Your Company",
    "report_heading": "Dependency Security Analysis Report",
    "logo_link": "https://yourcompany.com/logo.png",
    "favicon_link": "https://yourcompany.com/favicon.ico",
    "website": "https://yourcompany.com"
  },
  "report": {
    "title": "Dependency Security Report",
    "description": "Security vulnerability analysis for dependencies"
  }
}
```

Falls back to embedded defaults if no config file is present.

### Project Structure

```
ada/
├── cmd/ada/           # CLI entry point
│   └── main.go
├── internal/          # Core logic
│   ├── audit.go       # Audit execution
│   ├── collect.go     # Dependency file collection
│   ├── config.go      # Configuration management
│   ├── config.json    # Embedded default config
│   ├── osv.go         # OSV.dev integration
│   ├── project.go     # Project type detection
│   └── reports.go     # Report generation (JSON/HTML)
├── go.mod
└── README.md
```

### Credits

Inspired by [snyk-to-html](https://github.com/snyk/snyk-to-html) for report card structure and styling.
