package internal

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"regexp"
	"strings"
	"time"
)

// formatDateWithOrdinal formats a time with proper ordinal suffix (1st, 2nd, 3rd, 4th, etc.)
func formatDateWithOrdinal(t time.Time) string {
	day := t.Day()
	suffix := "th"
	switch {
	case day == 1 || day == 21 || day == 31:
		suffix = "st"
	case day == 2 || day == 22:
		suffix = "nd"
	case day == 3 || day == 23:
		suffix = "rd"
	}
	return fmt.Sprintf("%s %d%s %d, %s",
		t.Format("January"), day, suffix, t.Year(),
		t.Format("3:04:05 pm (UTC-07:00)"))
}

// sanitizeHTML safely escapes HTML content to prevent XSS attacks
func sanitizeHTML(input string) string {
	if input == "" {
		return ""
	}

	// First, HTML escape the content
	escaped := html.EscapeString(input)

	// Remove any remaining potentially dangerous patterns
	// Remove script tags and content
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	escaped = scriptRegex.ReplaceAllString(escaped, "")

	// Remove other dangerous tags
	dangerousTags := regexp.MustCompile(`(?i)<(iframe|object|embed|form|input|textarea|select|button|link|meta|style|base)[^>]*>.*?</(iframe|object|embed|form|input|textarea|select|button|link|meta|style|base)>`)
	escaped = dangerousTags.ReplaceAllString(escaped, "")

	// Remove dangerous attributes
	dangerousAttrs := regexp.MustCompile(`(?i)\s+(on\w+|javascript:|vbscript:|data:|mocha:|livescript:)[^=]*=`)
	escaped = dangerousAttrs.ReplaceAllString(escaped, "")

	// Remove any remaining HTML tags (keep only text)
	htmlTags := regexp.MustCompile(`<[^>]*>`)
	escaped = htmlTags.ReplaceAllString(escaped, "")

	return escaped
}

// sanitizeVersion safely handles version strings while preserving comparison operators
func sanitizeVersion(input string) string {
	if input == "" {
		return ""
	}

	// For version strings, we only need to remove potentially dangerous HTML tags
	// but preserve <, >, =, | operators since they're safe in this context

	// Remove script tags and content
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	cleaned := scriptRegex.ReplaceAllString(input, "")

	// Remove other dangerous tags
	dangerousTags := regexp.MustCompile(`(?i)<(iframe|object|embed|form|input|textarea|select|button|link|meta|style|base)[^>]*>.*?</(iframe|object|embed|form|input|textarea|select|button|link|meta|style|base)>`)
	cleaned = dangerousTags.ReplaceAllString(cleaned, "")

	// Remove dangerous attributes
	dangerousAttrs := regexp.MustCompile(`(?i)\s+(on\w+|javascript:|vbscript:|data:|mocha:|livescript:)[^=]*=`)
	cleaned = dangerousAttrs.ReplaceAllString(cleaned, "")

	// Remove any remaining HTML tags (keep only text)
	htmlTags := regexp.MustCompile(`<[^>]*>`)
	cleaned = htmlTags.ReplaceAllString(cleaned, "")

	return cleaned
}

// sanitizeURL ensures URLs are safe and don't contain javascript: or data: schemes
func sanitizeURL(input string) string {
	if input == "" {
		return ""
	}

	// Remove any dangerous URL schemes
	dangerousSchemes := regexp.MustCompile(`(?i)^(javascript|data|vbscript|mocha|livescript):`)
	if dangerousSchemes.MatchString(input) {
		return "#"
	}

	// Only allow http, https, and relative URLs
	safeURL := regexp.MustCompile(`(?i)^(https?://|/|#)`)
	if !safeURL.MatchString(input) {
		return "#"
	}

	return html.EscapeString(input)
}

// sanitizeCSSClass ensures CSS class names are safe
func sanitizeCSSClass(input string) string {
	if input == "" {
		return ""
	}

	// Only allow alphanumeric characters, hyphens, and underscores
	safeClass := regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	return safeClass.ReplaceAllString(strings.ToLower(input), "")
}

// ReadAuditResultFromJSON reads an AuditResult from a JSON file
// Auto-detects format: Ada native JSON or Snyk JSON output
func ReadAuditResultFromJSON(filePath string) (*AuditResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read JSON file: %v", err)
	}

	// Detect format by peeking at the JSON structure
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	// Snyk JSON has "ok" field and "vulnerabilities" as array at top level
	// Ada JSON has "projectType" field
	_, hasOk := probe["ok"]
	_, hasPackageManager := probe["packageManager"]
	_, hasProjectType := probe["projectType"]

	if (hasOk || hasPackageManager) && !hasProjectType {
		fmt.Printf("[>] detected snyk json format: %s\n", filePath)
		return parseSnykJSON(data)
	}

	// Default: Ada native format
	var result AuditResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse ada json: %v", err)
	}

	if result.Timestamp.IsZero() {
		result.Timestamp = time.Now()
	}

	return &result, nil
}

// SnykJSON represents the top-level structure of snyk test --json output
type SnykJSON struct {
	OK                bool       `json:"ok"`
	Vulnerabilities   []SnykVuln `json:"vulnerabilities"`
	DependencyCount   int        `json:"dependencyCount"`
	PackageManager    string     `json:"packageManager"`
	ProjectName       string     `json:"projectName"`
	Summary           string     `json:"summary"`
	DisplayTargetFile string     `json:"displayTargetFile"`
}

// SnykVuln represents a single vulnerability in snyk json output
type SnykVuln struct {
	ID             string          `json:"id"`
	Title          string          `json:"title"`
	Severity       string          `json:"severity"`
	PackageName    string          `json:"packageName"`
	Version        string          `json:"version"`
	Language       string          `json:"language"`
	PackageManager string          `json:"packageManager"`
	Description    string          `json:"description"`
	URL            string          `json:"url"`
	Identifiers    SnykIdentifiers `json:"identifiers"`
	Semver         SnykSemver      `json:"semver"`
	CVSSv3         string          `json:"CVSSv3"`
	CvssScore      float64         `json:"cvssScore"`
	From           []string        `json:"from"`
	UpgradePath    []interface{}   `json:"upgradePath"`
	FixedIn        []string        `json:"fixedIn"`
	IsUpgradable   bool            `json:"isUpgradable"`
	IsPatchable    bool            `json:"isPatchable"`
}

// SnykIdentifiers holds CVE, CWE, and GHSA identifiers
type SnykIdentifiers struct {
	CVE  []string `json:"CVE"`
	CWE  []string `json:"CWE"`
	GHSA []string `json:"GHSA"`
}

// SnykSemver holds vulnerable version ranges
type SnykSemver struct {
	Vulnerable []string `json:"vulnerable"`
}

// parseSnykJSON converts Snyk JSON output to Ada's AuditResult format
func parseSnykJSON(data []byte) (*AuditResult, error) {
	var snyk SnykJSON
	if err := json.Unmarshal(data, &snyk); err != nil {
		return nil, fmt.Errorf("failed to parse snyk json: %v", err)
	}

	// Map snyk package manager to ada project type
	projectType := ProjectTypeUnknown
	switch strings.ToLower(snyk.PackageManager) {
	case "npm", "yarn":
		projectType = ProjectTypeNPM
	case "composer":
		projectType = ProjectTypeComposer
	default:
		// Use the raw value so it still shows in the report
		projectType = ProjectType(snyk.PackageManager)
	}

	result := &AuditResult{
		ProjectType: projectType,
		ProjectName: snyk.ProjectName,
		Timestamp:   time.Now(),
	}

	// Track unique vulnerabilities — map key to index for path accumulation
	seenVulns := make(map[string]int)

	for _, sv := range snyk.Vulnerabilities {
		// Deduplicate by snyk vuln ID + package name
		vulnKey := fmt.Sprintf("%s:%s", sv.ID, sv.PackageName)

		// Build dependency path from the "from" array
		dependencyPath := strings.Join(sv.From, " > ")

		// If we've seen this vuln, accumulate the new path into the existing record
		if existingIdx, seen := seenVulns[vulnKey]; seen {
			if dependencyPath != "" && !containsString(result.Vulnerabilities[existingIdx].Paths, dependencyPath) {
				result.Vulnerabilities[existingIdx].Paths = append(result.Vulnerabilities[existingIdx].Paths, dependencyPath)
			}
			continue
		}

		// New vulnerability — create record

		// Extract primary CVE
		cve := ""
		if len(sv.Identifiers.CVE) > 0 {
			cve = sv.Identifiers.CVE[0]
		}

		// Extract CWE codes
		cweCodes := sv.Identifiers.CWE

		// Build affected versions string from semver ranges
		affectedVersions := strings.Join(sv.Semver.Vulnerable, " || ")

		// Build fixed-in version string
		fixedIn := strings.Join(sv.FixedIn, ", ")

		// Build advisory URL (prefer snyk url, fallback to GHSA)
		advisoryURL := sv.URL
		if advisoryURL == "" && len(sv.Identifiers.GHSA) > 0 {
			advisoryURL = fmt.Sprintf("https://github.com/advisories/%s", sv.Identifiers.GHSA[0])
		}

		// Normalize severity
		severity := sv.Severity
		if strings.ToLower(severity) == "moderate" {
			severity = "medium"
		}

		// Initialize paths slice
		paths := []string{}
		if dependencyPath != "" {
			paths = append(paths, dependencyPath)
		}

		seenVulns[vulnKey] = len(result.Vulnerabilities)

		v := Vulnerability{
			ID:               sv.ID,
			Title:            sv.Title,
			Severity:         severity,
			PackageName:      sv.PackageName,
			Version:          sv.Version,
			FixedIn:          fixedIn,
			Description:      sv.Description,
			Path:             dependencyPath,
			Paths:            paths,
			ProjectType:      projectType,
			CVE:              cve,
			AdvisoryURL:      advisoryURL,
			CVSSScore:        sv.CvssScore,
			CVSSVector:       sv.CVSSv3,
			CWECodes:         cweCodes,
			AffectedVersions: affectedVersions,
			InstalledVersion: sv.Version,
			FixAvailable:     sv.IsUpgradable || sv.IsPatchable || len(sv.FixedIn) > 0,
			Sources:          []string{"snyk"},
		}
		result.Vulnerabilities = append(result.Vulnerabilities, v)

		// Update summary
		result.Summary.TotalVulnerabilities++
		switch strings.ToLower(severity) {
		case "critical":
			result.Summary.Critical++
		case "high":
			result.Summary.High++
		case "medium":
			result.Summary.Medium++
		case "low":
			result.Summary.Low++
		default:
			result.Summary.Info++
		}
	}

	// Sort by severity
	result.Vulnerabilities = sortVulnerabilitiesBySeverity(result.Vulnerabilities)

	return result, nil
}

// MergeAuditResults merges multiple AuditResult JSONs into a single consolidated result
// with proper cross-file deduplication — same vuln across files gets paths merged, not duplicated
func MergeAuditResults(filePaths []string) (*AuditResult, error) {
	if len(filePaths) == 0 {
		return nil, fmt.Errorf("no JSON files provided")
	}

	// If only one file, just read and return it
	if len(filePaths) == 1 {
		return ReadAuditResultFromJSON(filePaths[0])
	}

	consolidated := &AuditResult{
		ProjectType: ProjectTypeMulti,
		ProjectName: "",
		Timestamp:   time.Now(),
		MultiProjectInfo: &MultiProjectInfo{
			ProjectTypes: []ProjectType{},
			ProjectNames: []string{},
			AuditResults: make(map[ProjectType]*AuditResult),
		},
	}

	var projectNames []string
	seenTypes := make(map[ProjectType]bool)

	// Cross-file dedup: track vuln key → index in consolidated.Vulnerabilities
	seenVulns := make(map[string]int)

	for _, filePath := range filePaths {
		result, err := ReadAuditResultFromJSON(filePath)
		if err != nil {
			fmt.Printf("[!] warning: skipping %s: %v\n", filePath, err)
			continue
		}

		fmt.Printf("[>] merging: %s (%s, %d vulnerabilities)\n",
			filePath, result.ProjectName, result.Summary.TotalVulnerabilities)

		// Collect project info
		if result.ProjectName != "" {
			projectNames = append(projectNames, result.ProjectName)
			consolidated.MultiProjectInfo.ProjectNames = append(
				consolidated.MultiProjectInfo.ProjectNames, result.ProjectName)
		}
		if !seenTypes[result.ProjectType] {
			seenTypes[result.ProjectType] = true
			consolidated.MultiProjectInfo.ProjectTypes = append(
				consolidated.MultiProjectInfo.ProjectTypes, result.ProjectType)
		}

		// Store individual result keyed by project name (or type if name empty)
		key := result.ProjectType
		if result.ProjectName != "" {
			key = ProjectType(result.ProjectName)
		}
		consolidated.MultiProjectInfo.AuditResults[key] = result

		// Merge vulnerabilities with cross-file deduplication
		for _, vuln := range result.Vulnerabilities {
			// Build a dedup key: ID + packageName (covers both Snyk IDs and CVEs)
			vulnKey := fmt.Sprintf("%s:%s", vuln.ID, vuln.PackageName)
			// Fallback if ID is empty
			if vuln.ID == "" {
				vulnKey = fmt.Sprintf("%s:%s:%s", vuln.PackageName, vuln.Title, vuln.AdvisoryURL)
			}

			if existingIdx, seen := seenVulns[vulnKey]; seen {
				// Same vuln found across files — merge paths, don't duplicate
				existing := &consolidated.Vulnerabilities[existingIdx]
				for _, p := range vuln.Paths {
					if !containsString(existing.Paths, p) {
						existing.Paths = append(existing.Paths, p)
					}
				}
				// Also check the legacy Path field if Paths was empty
				if vuln.Path != "" && !containsString(existing.Paths, vuln.Path) {
					existing.Paths = append(existing.Paths, vuln.Path)
				}
				// Merge sources
				for _, s := range vuln.Sources {
					if !containsString(existing.Sources, s) {
						existing.Sources = append(existing.Sources, s)
					}
				}
				continue
			}

			// New vulnerability — ensure Paths is populated
			if len(vuln.Paths) == 0 && vuln.Path != "" {
				vuln.Paths = []string{vuln.Path}
			}

			seenVulns[vulnKey] = len(consolidated.Vulnerabilities)
			consolidated.Vulnerabilities = append(consolidated.Vulnerabilities, vuln)
		}
	}

	// Recalculate summary from deduplicated vulnerability list
	consolidated.Summary = AuditSummary{}
	for _, vuln := range consolidated.Vulnerabilities {
		consolidated.Summary.TotalVulnerabilities++
		switch strings.ToLower(vuln.Severity) {
		case "critical":
			consolidated.Summary.Critical++
		case "high":
			consolidated.Summary.High++
		case "medium":
			consolidated.Summary.Medium++
		case "low":
			consolidated.Summary.Low++
		default:
			consolidated.Summary.Info++
		}
	}

	// Set consolidated project name
	consolidated.ProjectName = strings.Join(projectNames, " + ")

	// Sort vulnerabilities by severity
	consolidated.Vulnerabilities = sortVulnerabilitiesBySeverity(consolidated.Vulnerabilities)

	return consolidated, nil
}

// generateJSONReport generates a JSON report from audit results
func GenerateJSONReport(result *AuditResult) error {
	// Use fixed filename
	filename := "ada-audit-report.json"

	// Marshal the result to JSON
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// Write to file
	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %v", err)
	}

	fmt.Printf("[>] JSON report saved to: %s\n", filename)
	return nil
}

// generateHTMLReport generates an HTML report from audit results
func GenerateHTMLReport(result *AuditResult) error {
	// Use fixed filename
	filename := "ada-report.html"

	// Generate HTML content
	htmlContent := generateHTMLContent(result)

	// Write to file
	if err := os.WriteFile(filename, []byte(htmlContent), 0644); err != nil {
		return fmt.Errorf("failed to write HTML file: %v", err)
	}

	fmt.Printf("[>] HTML report saved to: %s\n", filename)
	return nil
}

// generateHTMLContent generates the HTML content for the report
func generateHTMLContent(result *AuditResult) string {
	// Get configuration (user config or embedded config)
	config := GetConfig()

	// Count vulnerabilities by severity
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	infoCount := 0

	for _, vuln := range result.Vulnerabilities {
		switch strings.ToLower(vuln.Severity) {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		default:
			infoCount++
		}
	}

	totalVulns := len(result.Vulnerabilities)

	// Generate the HTML report based on the original structure
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">

<head>
  <meta http-equiv="Content-type" content="text/html; charset=utf-8">
  <meta http-equiv="Content-Language" content="en-us">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>%s</title>
  <meta name="description" content="%d known vulnerabilities found in %d vulnerable dependency paths.">
  <base target="_blank">
  <link rel="icon" type="image/png" href="%s" sizes="194x194">
  <link rel="shortcut icon" href="%s">
  <style type="text/css">
  
    body {
      -moz-font-feature-settings: "pnum";
      -webkit-font-feature-settings: "pnum";
      font-variant-numeric: proportional-nums;
      display: flex;
      flex-direction: column;
      font-feature-settings: "pnum";
      font-size: 85%%;
      line-height: 1.2;
      min-height: 100vh;
      -webkit-text-size-adjust: 100%%;
      margin: 0;
      padding: 0;
      background-color: #F5F5F5;
      font-family: 'Arial', 'Helvetica', Calibri, sans-serif;
    }
  
    h1, h2, h3, h4, h5, h6 {
      font-weight: 500;
    }
  
    a, a:link, a:visited {
      border-bottom: 1px solid #666;
      text-decoration: none;
      color: #666;
    }
  
    a:hover, a:focus, a:active {
      border-bottom: 1px solid #333;
      color: #333;
    }
  
    hr {
      border: none;
      margin: 0.5em 0;
      border-top: 1px solid #c5c5c5;
    }
  
    ul {
      padding: 0 0.5em;
      margin: 0.5em 0;
    }
  
    code {
      background-color: #EEE;
      color: #ffa127;
      padding: 0.25em 0.5em;
      border-radius: 0.25em;
    }
  
    pre {
      background-color: #333333;
      font-family: monospace;
      padding: 0.5em 1em 0.75em;
      border-radius: 0.25em;
      font-size: 14px;
    }
  
    pre code {
      padding: 0;
      background-color: transparent;
      color: #fff;
    }
  
    a code {
      border-radius: .125rem .125rem 0 0;
      padding-bottom: 0;
      color: #666;
    }
  
    a[href^="http://"]:after, a[href^="https://"]:after {
      background-image: linear-gradient(transparent,transparent),url("data:image/svg+xml,%%3Csvg%%20xmlns%%3D%%22http%%3A%%2F%%2Fwww.w3.org%%2F2000%%2Fsvg%%22%%20viewBox%%3D%%220%%200%%20112%%20109%%22%%3E%%3Cg%%20id%%3D%%22Page-1%%22%%20fill%%3D%%22none%%22%%20fill-rule%%3D%%22evenodd%%22%%3E%%3Cg%%20id%%3D%%22link-external%%22%%3E%%3Cg%%20id%%3D%%22arrow%%22%%3E%%3Cpath%%20id%%3D%%22Line%%22%%20stroke%%3D%%22%%23666%%22%%20stroke-width%%3D%%2215%%22%%20d%%3D%%22M88.5%%2021l-43%%2042.5%%22%%20stroke-linecap%%3D%%22square%%22%%2F%%3E%%3Cpath%%20id%%3D%%22Triangle%%22%%20fill%%3D%%22%%23666%%22%%20d%%3D%%22M111.2%%200v50L61%%200z%%22%%2F%%3E%%3C%%2Fg%%3E%%3Cpath%%20id%%3D%%22square%%22%%20fill%%3D%%22%%23666%%22%%20d%%3D%%22M66%%2015H0v94h94V44L79%%2059v35H15V30h36z%%22%%2F%%3E%%3C%%2Fg%%3E%%3C%%2Fg%%3E%%3C%%2Fsvg%%3E");
      background-repeat: no-repeat;
      background-size: .75rem;
      content: "";
      display: inline-block;
      height: .75rem;
      margin-left: .25rem;
      width: .75rem;
    }
  
  
  /* Layout */
  
    [class*=layout-container] {
      margin: 0 auto;
      max-width: 71.25em;
      padding: 1.5em 1.1em;
      position: relative;
    }
    .layout-container--short {
      padding-top: 0;
      padding-bottom: 0;
      max-width: 48.75em;
    }
  
    .layout-container--short:after {
      display: block;
      content: "";
      clear: both;
    }
  
  /* Header */
  
    .header {
      padding-bottom: 1px;
    }
  
    .paths {
      margin-left: 8px;
    }
    .header-wrap {
      display: flex;
      flex-direction: row;
      justify-content: space-between;
      padding-top: 1.5em;
    }
    .project__header {
      background-color: %s;
      color: %s;
      margin-bottom: -1px;
      padding-top: 0.8em;
      padding-bottom: 0.2em;
      border-bottom: 2px solid #BBB;
    }
  
    .project__header__title {
      overflow-wrap: break-word;
      word-wrap: break-word;
      word-break: break-all;
      margin-bottom: .1em;
      margin-top: 0;
    }
    

  
    .timestamp {
      float: right;
      clear: none;
      margin-bottom: 0;
    }
  
    .meta-counts {
      clear: both;
      display: block;
      flex-wrap: wrap;
      justify-content: space-between;
      margin: 0 0 1em;
      color: #fff;
      clear: both;
      font-size: 0.9em;
    }
  
    .meta-count {
      display: block;
      flex-basis: 100%%;
      margin: 0 0.8em 0.8em 0;
      float: left;
      padding-right: 0.8em;
      border-right: 2px solid #fff;
    }
  
    .meta-count:last-child {
      border-right: 0;
      padding-right: 0;
      margin-right: 0;
    }
  
  /* Card */
  
    .card {
      background-color: #fff;
      border: 1px solid #c5c5c5;
      border-radius: .25rem;
      margin: 0 0 1.5em 0;
      position: relative;
      min-height: 40px;
      padding: 1em;
    }
  
    .card__labels {
      position: absolute;
      top: 0.9em;
      left: 0;
      display: flex;
      align-items: center;
      gap: 6px;
    }
  
    .card .label {
      background-color: #767676;
      border: 2px solid #767676;
      color: white;
      padding: 0.2rem 0.6rem;
      font-size: 0.8rem;
      text-transform: uppercase;
      display: inline-block;
      margin: 0;
      border-radius: 0.25rem;
    }
  
    .card .label__text {
      vertical-align: text-top;
        font-weight: bold;
    }
  
    .card .label--critical {
      background-color: #AB1A1A;
      border-color: #AB1A1A;
    }
  
    .card .label--high {
      background-color: #CE5019;
      border-color: #CE5019;
    }
  
    .card .label--medium {
      background-color: #D68000;
      border-color: #D68000;
    }
  
    .card .label--low {
      background-color: #2E7D32;
      border-color: #2E7D32;
    }
  
    .severity--low {
      border-color: #2E7D32;
    }
  
    .severity--medium {
      border-color: #D68000;
    }
  
    .severity--high {
      border-color: #CE5019;
    }
  
    .severity--critical {
      border-color: #AB1A1A;
    }
    
    .severity-critical {
      color: #AB1A1A;
      font-weight: bold;
    }
    
    .severity-high {
      color: #CE5019;
      font-weight: bold;
    }
    
    .severity-medium {
      color: #D68000;
      font-weight: bold;
    }
    
    .severity-low {
      color: #2E7D32;
      font-weight: bold;
    }
    
    .severity-info {
      color: #666;
      font-weight: bold;
    }
    
    .fix-yes {
      color: #2E7D32;
      font-weight: bold;
    }
    
    .fix-no {
      color: #C62828;
      font-weight: bold;
    }
    
    .advisory-links {
      margin-top: 0.8em;
    }
    
    .advisory-link {
      display: inline-block;
      padding: 0.4rem 0.8rem;
      background: white;
      color: #666;
      text-decoration: none;
      border: 1px solid #666;
      border-radius: 4px;
      font-size: 0.8rem;
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-right: 0.4rem;
      margin-bottom: 0.4rem;
      transition: all 0.2s ease;
    }
    
    .advisory-link:hover,
    .advisory-link:focus,
    .advisory-link:active {
      background: #f5f5f5;
      border-color: #333;
      color: #333;
      text-decoration: none;
    }
    
    .details-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.6em;
      margin: 0.5em 0;
    }
    
    .details-column {
      min-width: 0;
    }
    
    .details-column ul {
      margin: 0;
      padding: 0;
    }
    
    .details-column .card__meta__item {
      margin-bottom: 0;
      padding: 0;
      background: transparent;
      border-radius: 0;
      line-height: inherit;
    }
    
    .details-column .card__meta__item:last-child {
      margin-bottom: 0;
    }
  
    .card--vuln {
      padding-top: 3em;
    }
  
    .card--vuln .card__labels > .label:first-child {
      padding-left: 1.5em;
      padding-right: 1.5em;
      border-radius: 0 0.25rem 0.25rem 0;
    }
  
    .card--vuln .card__section h2 {
      font-size: 18px;
      margin-bottom: 0.4em;
    }
  
    .card--vuln .card__section p {
      margin: 0 0 0.5em 0;
    }
  
        .card--vuln .card__meta {
      padding: 0 0 0 0.8em;
      margin: 0;
      font-size: 1em;
    }
    
    .card .card__meta__paths {
      font-size: 1em;
      margin: 0.8em 0;
    }
    
    .list-paths__item__introduced {
      font-size: 1em;
      font-weight: 500;
      color: #333;
    }
    
    .list-paths__item__arrow {
      font-size: 1.1em;
      font-weight: bold;
      color: #666;
      margin: 0 0.4em;
    }
    
    .card__section__title {
      font-size: 1.1em;
      font-weight: 600;
      color: #333;
      margin: 0.6em 0 0.3em 0;
      padding-bottom: 0.2em;
    }
    
    .card__section p {
      font-size: 1em;
      line-height: 1.1;
      color: #333;
      margin: 0.15em 0;
      font-weight: 500;
    }
  
    .card--vuln .card__title {
      font-size: 22px;
      margin-top: 0;
      margin-right: 100px; /* Ensure space for the risk score */
    }
  
    .card--vuln .card__cta p {
      margin: 0;
      text-align: right;
    }
  
    .risk-score-display {
      position: absolute;
      top: 1.2em;
      right: 1.2em;
      text-align: right;
      z-index: 10;
    }
  
    .risk-score-display__label {
      font-size: 0.6em;
      font-weight: bold;
      color: #586069;
      text-transform: uppercase;
      line-height: 1;
      margin-bottom: 2px;
    }
  
    .risk-score-display__value {
      font-size: 1.5em;
      font-weight: 600;
      color: #24292e;
      line-height: 1;
    }
  
    .source-panel {
      clear: both;
      display: flex;
      justify-content: flex-start;
      flex-direction: column;
      align-items: flex-start;
      padding: 0.4em 0;
      width: fit-content;
    }
    
    .company-logo {
      border: none;
      border-radius: 0;
      padding: 0;
      background-color: transparent;
    }
    
    .github-link {
      position: absolute;
      top: 1.5em;
      right: 1.5em;
      z-index: 10;
    }
    
    .github-link a {
      color: rgba(255, 255, 255, 0.8);
      transition: color 0.2s ease;
      text-decoration: none;
      border: none;
      outline: none;
    }
    
    .github-link a:hover {
      color: rgba(255, 255, 255, 1);
    }
    
    .github-link a:focus {
      outline: none;
      border: none;
    }
    
    .github-link a:active {
      border: none;
      outline: none;
    }
    
    /* Hide external link indicators */
    .github-link a::after {
      display: none !important;
      content: none !important;
    }
    
    .github-link a[href^="http"]::after {
      display: none !important;
      content: none !important;
    }
  
  
  
  </style>
  <style type="text/css">
    .metatable {
      text-size-adjust: 100%%;
      -webkit-font-smoothing: antialiased;
      -webkit-box-direction: normal;
      color: inherit;
      font-feature-settings: "pnum";
      box-sizing: border-box;
      background: transparent;
      border: 0;
      font: inherit;
      font-size: 85%%;
      margin: 0;
      outline: none;
      padding: 0;
      text-align: left;
      text-decoration: none;
      vertical-align: baseline;
      z-index: auto;
      margin-top: 10px;
      border-collapse: collapse;
      border-spacing: 0;
      font-variant-numeric: tabular-nums;
      max-width: 51.75em;
    }
  
    tbody {
      text-size-adjust: 100%%;
      -webkit-font-smoothing: antialiased;
      -webkit-box-direction: normal;
      color: inherit;
      font-feature-settings: "pnum";
      border-collapse: collapse;
      border-spacing: 0;
      box-sizing: border-box;
      background: transparent;
      border: 0;
      font: inherit;
      font-size: 85%%;
      margin: 0;
      outline: none;
      padding: 0;
      text-align: left;
      text-decoration: none;
      vertical-align: baseline;
      z-index: auto;
      display: flex;
      flex-wrap: wrap;
    }
  
    .meta-row {
      text-size-adjust: 100%%;
      -webkit-font-smoothing: antialiased;
      -webkit-box-direction: normal;
      color: inherit;
      font-feature-settings: "pnum";
      border-collapse: collapse;
      border-spacing: 0;
      box-sizing: border-box;
      background: transparent;
      border: 0;
      font: inherit;
      outline: none;
      text-align: left;
      text-decoration: none;
      vertical-align: baseline;
      z-index: auto;
      display: flex;
      align-items: start;
      border-top: 1px solid #d3d3d9;
      padding: 6px 0 0 0;
      border-bottom: none;
      margin: 6px;
      width: 47.75%%;
    }
  
    .meta-row-label {
      text-size-adjust: 100%%;
      -webkit-font-smoothing: antialiased;
      -webkit-box-direction: normal;
      font-feature-settings: "pnum";
      border-collapse: collapse;
      border-spacing: 0;
      color: #4c4a73;
      box-sizing: border-box;
      background: transparent;
      border: 0;
      font: inherit;
      margin: 0;
      outline: none;
      text-decoration: none;
      z-index: auto;
      align-self: start;
      flex: 1;
      font-size: 0.9rem;
      line-height: 1.3rem;
      padding: 0;
      text-align: left;
      vertical-align: top;
      text-transform: none;
      letter-spacing: 0;
    }
  
    .meta-row-value {
      text-size-adjust: 100%%;
      -webkit-font-smoothing: antialiased;
      -webkit-box-direction: normal;
      color: inherit;
      font-feature-settings: "pnum";
      border-collapse: collapse;
      border-spacing: 0;
      word-break: break-word;
      box-sizing: border-box;
      background: transparent;
      border: 0;
      font: inherit;
      font-size: 0.9rem;
      margin: 0;
      outline: none;
      padding: 0;
      text-align: right;
      text-decoration: none;
      vertical-align: baseline;
      z-index: auto;
    }
  </style>
</head>

<body class="section-projects">
  <main class="layout-stacked">
        <div class="layout-stacked__header header">
          <header class="project__header">
            <div class="layout-container">
               <img src="%s" width="180" class="company-logo">

              <div class="header-wrap">
                  <h1 class="project__header__title">%s</h1>
                <p class="timestamp">%s</p>
              </div>
              
              <div class="github-link">
                <a href="https://github.com/rvizx/ada" title="View on GitHub">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                  </svg>
                </a>
              </div>
    
              <div class="meta-counts">
                <div class="meta-count"><span>%d</span> <span>known vulnerabilities</span></div>
                <div class="meta-count"><span>%d</span> <span>vulnerable dependency paths</span></div>
              </div><!-- .meta-counts -->
            </div><!-- .layout-container--short -->
          </header><!-- .project__header -->
        </div><!-- .layout-stacked__header -->

    <div class="layout-container" style="padding-top: 25px;">
      <div class="cards--vuln filter--patch filter--ignore">`,
		config.Report.Title, totalVulns, totalVulns, config.Company.FaviconLink, config.Company.FaviconLink,
		config.Theme.HeaderBackground, config.Theme.HeaderTextColor,
		config.Company.LogoLink, config.Report.Title, formatDateWithOrdinal(time.Now()), totalVulns, totalVulns)

	// Add vulnerability cards
	if len(result.Vulnerabilities) == 0 {
		html += `
        <div class="card card--vuln">
          <h2 class="card__title">No vulnerabilities found</h2>
          <div class="card__section">
            <p>Your project appears to be secure based on the current audit.</p>
          </div>
        </div>`
	} else {
		for _, vuln := range result.Vulnerabilities {
			severityClass := "severity--" + strings.ToLower(vuln.Severity)
			labelClass := "label--" + strings.ToLower(vuln.Severity)

			html += fmt.Sprintf(`
        <div class="card card--vuln %s" data-snyk-test="%s">
            <h2 class="card__title">%s</h2>
            <div class="card__section">
        
                <div class="card__labels">
                    <div class="label %s">
                        <span class="label__text">%s severity</span>
                    </div>
                </div>
        
                <hr/>
        
                <ul class="card__meta">
                    <li class="card__meta__item">
                        Package Manager: %s
                    </li>
                    <li class="card__meta__item">
                            Vulnerable module:
        
                            %s
                    </li>
        
                    <li class="card__meta__item">Installed Version:
        
                                %s
        
                    </li>
                </ul>
        
                <hr/>
        
                <h3 class="card__section__title">Vulnerability Details</h3>
                <div class="details-grid">
                    <div class="details-column">
                        <ul class="card__meta">
                            <li class="card__meta__item">
                                Severity: <span class="severity-%s">%s</span>
                            </li>
                            <li class="card__meta__item">
                                CVE/Advisory: %s
                            </li>
                            <li class="card__meta__item">
                                CWE Codes: %s
                            </li>
                            <li class="card__meta__item">
                                Fix Available: <span class="%s">%s</span>
                            </li>
                            <li class="card__meta__item">
                                CVSS Score: %s
                            </li>
                        </ul>
                    </div>
                    <div class="details-column">
                        <ul class="card__meta">
                            <li class="card__meta__item">
                                Affected Versions: %s
                            </li>
                            <li class="card__meta__item">
                                Reported: %s
                            </li>
                            <li class="card__meta__item">
                                Sources: %s
                            </li>
                        </ul>
                    </div>
                </div>
        
                <hr/>
        
                <h3 class="card__section__title">Detailed paths</h3>
                <ul class="card__meta__paths">
                    %s
                </ul><!-- .list-paths -->
        
                <hr/>
        
                <h3 class="card__section__title">Description</h3>
                <p>%s</p>
        
                <hr/>
        
                <h3 class="card__section__title">Advisory Links</h3>
                <div class="advisory-links">
                    %s
                </div>
        
            </div><!-- .card__section -->
        
        </div><!-- .card -->`,
				sanitizeCSSClass(severityClass), strings.ToLower(vuln.Severity), sanitizeHTML(vuln.Title), sanitizeCSSClass(labelClass), sanitizeHTML(strings.ToLower(vuln.Severity)),
				sanitizeHTML(string(vuln.ProjectType)), sanitizeHTML(vuln.PackageName), getInstalledVersionText(vuln),
				sanitizeCSSClass(strings.ToLower(vuln.Severity)), sanitizeHTML(vuln.Severity), sanitizeHTML(getCVEOrAdvisoryText(vuln)),
				sanitizeHTML(getCWEText(vuln)), sanitizeCSSClass(getFixAvailableClass(vuln)), sanitizeHTML(getFixAvailableText(vuln)), sanitizeHTML(getCVSSText(vuln)),
				getAffectedVersionsText(vuln), sanitizeHTML(getReportedText(vuln)), sanitizeHTML(getSourcesText(vuln)),
				getDetailedPathsHTML(vuln),
				sanitizeHTML(cleanDescription(vuln.Description)), getAdvisoryLinksHTML(vuln))
		}
	}

	// Add footer
	footerLogo := GetLogoLinkFooter()
	footerText := GetFooterText()

	// Convert \n to <br> in footer text, then sanitize
	footerTextHTML := strings.ReplaceAll(footerText, "\\n", "<br>")
	footerTextHTML = strings.ReplaceAll(footerTextHTML, "\n", "<br>")
	footerTextHTML = sanitizeHTML(footerTextHTML)
	// Convert back the <br> tags after sanitization
	footerTextHTML = strings.ReplaceAll(footerTextHTML, "&lt;br&gt;", "<br>")

	html += `
      </div><!-- cards -->
    </div>
    
    <!-- Footer -->
    <footer style="margin-top: 2em; padding: 1.5em; background-color: #f8f9fa; border-top: 1px solid #e9ecef; text-align: center;">
      <div style="max-width: 71.25em; margin: 0 auto;">
        <img src="` + sanitizeURL(footerLogo) + `" alt="Company Logo" style="max-height: 40px; margin-bottom: 0.5em;">
        <p style="margin: 0; color: #666; font-size: 0.9em;">` + footerTextHTML + `</p>
      </div>
    </footer>
  </main><!-- .layout-stacked__content -->
</body>

</html>`

	return html
}

// cleanDescription cleans up the vulnerability description by removing duplicate information
func cleanDescription(description string) string {
	// Remove duplicate "Affected Versions" and "Advisory" entries
	parts := strings.Split(description, " | ")
	seen := make(map[string]bool)
	var cleanParts []string

	for _, part := range parts {
		if strings.HasPrefix(part, "Affected Versions:") || strings.HasPrefix(part, "Advisory:") {
			if !seen[part] {
				cleanParts = append(cleanParts, sanitizeHTML(part))
				seen[part] = true
			}
		} else {
			cleanParts = append(cleanParts, sanitizeHTML(part))
		}
	}

	return strings.Join(cleanParts, " | ")
}

// getFixAvailableClassAndText returns the CSS class and text for fix availability
func getFixAvailableClassAndText(vuln Vulnerability) (string, string) {
	if vuln.FixAvailable {
		return "fix-yes", "Yes"
	}
	return "fix-no", "No"
}

// getFixAvailableClass returns just the CSS class for fix availability
func getFixAvailableClass(vuln Vulnerability) string {
	if vuln.FixAvailable {
		return "fix-yes"
	}
	return "fix-no"
}

// getFixAvailableText returns just the text for fix availability
func getFixAvailableText(vuln Vulnerability) string {
	if vuln.FixAvailable {
		return "Yes"
	}
	return "No"
}

// getCVEOrAdvisoryText returns CVE ID or advisory ID
func getCVEOrAdvisoryText(vuln Vulnerability) string {
	if vuln.CVE != "" {
		return sanitizeHTML(vuln.CVE)
	}
	if vuln.ID != "" {
		return sanitizeHTML(vuln.ID)
	}
	return "N/A"
}

// getCVSSText returns CVSS score and vector
func getCVSSText(vuln Vulnerability) string {
	if vuln.CVSSScore > 0 {
		if vuln.CVSSVector != "" {
			return fmt.Sprintf("%.1f (%s)", vuln.CVSSScore, sanitizeHTML(vuln.CVSSVector))
		}
		return fmt.Sprintf("%.1f", vuln.CVSSScore)
	}
	return "N/A"
}

// getCWEText returns CWE codes
func getCWEText(vuln Vulnerability) string {
	if len(vuln.CWECodes) > 0 {
		sanitizedCodes := make([]string, len(vuln.CWECodes))
		for i, code := range vuln.CWECodes {
			sanitizedCodes[i] = sanitizeHTML(code)
		}
		return strings.Join(sanitizedCodes, ", ")
	}
	return "N/A"
}

// getAffectedVersionsText returns affected versions
func getAffectedVersionsText(vuln Vulnerability) string {
	if vuln.AffectedVersions != "" {
		return sanitizeVersion(vuln.AffectedVersions)
	}
	if vuln.Version != "" {
		return sanitizeVersion(vuln.Version)
	}
	return "N/A"
}

// getReportedText returns reported date
func getReportedText(vuln Vulnerability) string {
	if vuln.ReportedAt != "" {
		return sanitizeHTML(vuln.ReportedAt)
	}
	return "N/A"
}

// getSourcesText returns sources
func getSourcesText(vuln Vulnerability) string {
	if len(vuln.Sources) > 0 {
		sanitizedSources := make([]string, len(vuln.Sources))
		for i, source := range vuln.Sources {
			sanitizedSources[i] = sanitizeHTML(source)
		}
		return strings.Join(sanitizedSources, ", ")
	}
	return "N/A"
}

// getInstalledVersionText returns installed version
func getInstalledVersionText(vuln Vulnerability) string {
	if vuln.InstalledVersion != "" {
		return sanitizeVersion(vuln.InstalledVersion)
	}
	return "Unknown"
}

// getDetailedPathsHTML returns HTML list items for all dependency paths where a vulnerability was found
func getDetailedPathsHTML(vuln Vulnerability) string {
	paths := vuln.Paths

	// Fallback to legacy Path field if Paths is empty
	if len(paths) == 0 && vuln.Path != "" {
		paths = []string{vuln.Path}
	}

	// Final fallback: show package type > package name
	if len(paths) == 0 {
		paths = []string{string(vuln.ProjectType) + " > " + vuln.PackageName}
	}

	var items []string
	for i, p := range paths {
		// Split the path into segments for display
		segments := strings.Split(p, " > ")
		if len(segments) <= 1 {
			// Single-segment path (e.g. node_modules/pkg or vendor > pkg)
			items = append(items, fmt.Sprintf(
				`<li>
					<span class="list-paths__item__introduced">
						<strong>#%d</strong> Introduced through: %s
					</span>
				</li>`, i+1, sanitizeHTML(p)))
		} else {
			// Multi-segment dependency chain
			sanitizedSegments := make([]string, len(segments))
			for j, seg := range segments {
				sanitizedSegments[j] = sanitizeHTML(strings.TrimSpace(seg))
			}
			chain := strings.Join(sanitizedSegments, ` <span class="list-paths__item__arrow">›</span> `)
			items = append(items, fmt.Sprintf(
				`<li>
					<span class="list-paths__item__introduced">
						<strong>#%d</strong> Introduced through: %s
					</span>
				</li>`, i+1, chain))
		}
	}

	return strings.Join(items, "\n")
}

// getAdvisoryLinksHTML returns HTML for advisory links
func getAdvisoryLinksHTML(vuln Vulnerability) string {
	var links []string

	if vuln.AdvisoryURL != "" {
		linkText := "View Advisory"
		if vuln.CVE != "" {
			linkText = "View " + vuln.CVE
		}
		links = append(links, fmt.Sprintf(`<a href="%s" target="_blank" class="advisory-link">%s</a>`, sanitizeURL(vuln.AdvisoryURL), sanitizeHTML(linkText)))
	}

	if vuln.CVE != "" && !strings.Contains(vuln.CVE, "GHSA-") {
		// Add NIST CVE link for non-GitHub advisories
		nistURL := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vuln.CVE)
		links = append(links, fmt.Sprintf(`<a href="%s" target="_blank" class="advisory-link">View NIST CVE</a>`, sanitizeURL(nistURL)))
	}

	if len(links) == 0 {
		return "No advisory links available"
	}

	return strings.Join(links, " ")
}
