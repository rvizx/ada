# Ada - Audit Aggregator

### Description

ADA (Audit Aggregator) is a comprehensive security vulnerability scanning tool that automatically detects and aggregates audit results from multiple package managers. It intelligently identifies project types based on configuration files and runs appropriate security audits using built-in parsers for JSON outputs.


<div align="center">
  <img width="650" src="https://github.com/user-attachments/assets/65e7d21d-5d19-46cc-8ddf-775ed9675355" alt="sample"> <br><br>
</div>

The tool seamlessly handles npm audit, composer audit, and other audit tools individually or in combination, creating unified security reports. ADA automatically installs missing audit tools in temporary locations when needed, ensuring developers and security analysts can focus on results rather than tool setup.

### Features

- **Multi-Project Detection**: Automatically identifies npm, Composer, and other project types
- **Intelligent Tool Management**: Installs missing audit tools temporarily for the audit report and cleans up automatically
- **Unified Reporting**: Combines multiple audit results into single comprehensive reports
- **Custom Branding**: Fully configurable company theming and logo placement with user-specific configuration
- **User Configuration**: Support for `~/.config/ada.config` with automatic fallback to embedded defaults
- **Professional Output**: Generates both JSON and HTML reports with enterprise-grade styling
- **Zero Dependencies**: Self-contained binary with embedded configuration

### Prerequisites

- **Go 1.24 or later** (tested with Go 1.24.6)
- **Git** for cloning the repository
- **npm** and **composer** (optional - ADA will attempt to install them if missing)



### Installation & Building

**1. Clone the Repository**
```bash
git clone https://github.com/rvizx/ada.git
cd ada
```

**2. Build the Binary**
```bash
go build -o ada ./cmd/ada
```

**3. Install System-Wide (Optional)**
```bash
sudo cp ada /usr/local/bin/ada
sudo chmod +x /usr/local/bin/ada
```


### Usage

**Executing ADA**
Navigate to any repository you want to audit:

```bash
ada audit          # Generate both JSON and HTML reports
ada audit --json   # JSON report only
ada audit --html   # HTML report only
ada audit --help   # Show help message
```


### Configuration

ADA supports two configuration methods:

#### 1. User Configuration (Recommended)

Create a user-specific configuration file at `~/.config/ada.config` to customize branding and theming:

```bash
# Create the config directory if it doesn't exist
mkdir -p ~/.config

# Create your custom configuration
cat > ~/.config/ada.config << 'EOF'
{
  "theme": {
    "primaryColor": "#ff8f1a",
    "headerBackground": "#ff8f1a",
    "headerTextColor": "#fff"
  },
  "company": {
    "title": "Your Company Name",
    "report_heading": "Software Dependency Security Analysis Report",
    "logo_link": "https://yourcompany.com/logo.png",
    "favicon_link": "https://yourcompany.com/favicon.ico",
    "website": "https://yourcompany.com"
  },
  "report": {
    "title": "Software Dependency Security Analysis Report",
    "description": "Security vulnerability analysis report for Your Company dependencies"
  }
}
EOF
```

**Configuration Priority:**
1. **User Config**: `~/.config/ada.config` (if exists)
2. **Embedded Config**: Built-in default configuration (fallback) - currently set to zyenra


### Project Structure

```
ada/
├── cmd/ada/          # Main application entry point
│   └── main.go       # Command-line interface and main logic
├── internal/          # Internal packages (not importable)
│   ├── config.go      # Configuration management and embedding
│   ├── audit.go       # Security audit execution logic
│   ├── project.go     # Project type detection and analysis
│   ├── reports.go     # Report generation (JSON/HTML)
│   └── config.json    # Embedded configuration file
├── internal/config.json # Embedded configuration file
├── go.mod             # Go module definition
├── .gitignore         # Git ignore patterns
└── README.md          # This file
```


### Contribution

Contributions are welcome! Please ensure code follows best practices and includes appropriate tests.


### Credits

Inspired by [snyk-to-html](https://github.com/snyk/snyk-to-html) for report card structure and styling.
