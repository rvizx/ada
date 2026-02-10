package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const osvAPIURL = "https://api.osv.dev/v1/query"

// OSVQuery is the request body for the OSV API
type OSVQuery struct {
	Package OSVPackage `json:"package"`
	Version string     `json:"version"`
}

// OSVPackage identifies a package in the OSV database
type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// OSVResponse is the response from the OSV API
type OSVResponse struct {
	Vulns []OSVVuln `json:"vulns"`
}

// OSVVuln represents a single vulnerability from OSV
type OSVVuln struct {
	ID       string         `json:"id"`
	Summary  string         `json:"summary"`
	Details  string         `json:"details"`
	Aliases  []string       `json:"aliases"`
	Severity []OSVSeverity  `json:"severity"`
	Affected []OSVAffected  `json:"affected"`
	References []OSVReference `json:"references"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
}

// OSVSeverity holds CVSS scoring info
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// OSVAffected holds affected version ranges
type OSVAffected struct {
	Package  OSVPackage     `json:"package"`
	Ranges   []OSVRange     `json:"ranges"`
	Versions []string       `json:"versions"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
}

// OSVRange represents a version range for affected packages
type OSVRange struct {
	Type   string      `json:"type"`
	Events []OSVEvent  `json:"events"`
}

// OSVEvent is a version event (introduced/fixed)
type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// OSVReference holds advisory/reference URLs
type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// osvEcosystemMap maps Ada ecosystem names to OSV ecosystem names
var osvEcosystemMap = map[string]string{
	"npm":      "npm",
	"composer": "Packagist",
}

// QueryOSV queries the OSV.dev API for vulnerabilities in a specific package+version
func QueryOSV(packageName, version, ecosystem string) (*OSVResponse, error) {
	osvEcosystem, ok := osvEcosystemMap[ecosystem]
	if !ok {
		return nil, fmt.Errorf("unsupported ecosystem for OSV: %s", ecosystem)
	}

	query := OSVQuery{
		Package: OSVPackage{
			Name:      packageName,
			Ecosystem: osvEcosystem,
		},
		Version: version,
	}

	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV query: %v", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(osvAPIURL, "application/json", bytes.NewReader(queryJSON))
	if err != nil {
		return nil, fmt.Errorf("OSV API request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OSV response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned %d: %s", resp.StatusCode, string(body))
	}

	var osvResp OSVResponse
	if err := json.Unmarshal(body, &osvResp); err != nil {
		return nil, fmt.Errorf("failed to parse OSV response: %v", err)
	}

	return &osvResp, nil
}

// ScanVendoredTargets queries OSV for all vendored (non-scannable) targets
// and returns an AuditResult compatible with Ada's report system
func ScanVendoredTargets(collectResult *CollectResult) (*AuditResult, error) {
	result := &AuditResult{
		ProjectType: ProjectType("osv-vendored"),
		ProjectName: "Vendored Dependencies (OSV)",
		Timestamp:   time.Now(),
	}

	vendoredCount := 0
	scannedCount := 0
	skippedCount := 0
	vulnCount := 0

	for _, target := range collectResult.Targets {
		// Only process vendored (non-scannable) targets
		if target.Scannable {
			continue
		}
		vendoredCount++

		// Must have both name and version to query
		if target.PackageName == "" || target.PackageVersion == "" {
			fmt.Printf("[>] osv: skipping %s — missing name or version\n", target.RelPath)
			skippedCount++
			continue
		}

		fmt.Printf("[>] osv: checking %s@%s (%s)... ", target.PackageName, target.PackageVersion, target.Ecosystem)

		osvResp, err := QueryOSV(target.PackageName, target.PackageVersion, target.Ecosystem)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			skippedCount++
			continue
		}
		scannedCount++

		if len(osvResp.Vulns) == 0 {
			fmt.Printf("clean ✓\n")
			continue
		}

		fmt.Printf("⚠ %d vulnerabilities found\n", len(osvResp.Vulns))

		// Convert OSV vulns to Ada Vulnerability format
		for _, osvVuln := range osvResp.Vulns {
			vuln := convertOSVVuln(osvVuln, target)
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
			vulnCount++

			// Update summary
			result.Summary.TotalVulnerabilities++
			switch strings.ToLower(vuln.Severity) {
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
	}

	// Sort by severity
	result.Vulnerabilities = sortVulnerabilitiesBySeverity(result.Vulnerabilities)

	fmt.Println("")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  Ada OSV — Vendored Library Vulnerability Scan")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Printf("  Vendored targets:  %d\n", vendoredCount)
	fmt.Printf("  Queried OSV:       %d\n", scannedCount)
	fmt.Printf("  Skipped (no info): %d\n", skippedCount)
	fmt.Printf("  Vulnerabilities:   %d\n", vulnCount)
	if vulnCount > 0 {
		fmt.Printf("    Critical: %d  High: %d  Medium: %d  Low: %d\n",
			result.Summary.Critical, result.Summary.High,
			result.Summary.Medium, result.Summary.Low)
	}
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("")

	return result, nil
}

// convertOSVVuln converts an OSV vulnerability to Ada's Vulnerability format
func convertOSVVuln(osvVuln OSVVuln, target CollectTarget) Vulnerability {
	// Extract CVE from aliases
	cve := ""
	var ghsa []string
	for _, alias := range osvVuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") && cve == "" {
			cve = alias
		}
		if strings.HasPrefix(alias, "GHSA-") {
			ghsa = append(ghsa, alias)
		}
	}

	// Use OSV ID if no CVE found
	vulnID := osvVuln.ID
	if cve != "" {
		vulnID = cve
	}

	// Determine severity from CVSS or database_specific
	severity := extractOSVSeverity(osvVuln)

	// Extract CVSS score and vector
	cvssScore := 0.0
	cvssVector := ""
	for _, sev := range osvVuln.Severity {
		if sev.Type == "CVSS_V3" {
			cvssVector = sev.Score
			cvssScore = parseCVSSScore(sev.Score)
		}
	}

	// Extract affected version ranges
	affectedVersions := extractAffectedVersions(osvVuln)

	// Extract fixed version
	fixedIn := extractFixedVersion(osvVuln)

	// Build advisory URL
	advisoryURL := ""
	for _, ref := range osvVuln.References {
		if ref.Type == "ADVISORY" {
			advisoryURL = ref.URL
			break
		}
	}
	if advisoryURL == "" && len(ghsa) > 0 {
		advisoryURL = fmt.Sprintf("https://github.com/advisories/%s", ghsa[0])
	}
	if advisoryURL == "" {
		advisoryURL = fmt.Sprintf("https://osv.dev/vulnerability/%s", osvVuln.ID)
	}

	// Extract CWE codes from database_specific
	cweCodes := extractCWECodes(osvVuln)

	// Build description
	description := osvVuln.Summary
	if description == "" {
		description = osvVuln.Details
	}
	// Truncate very long descriptions
	if len(description) > 500 {
		description = description[:497] + "..."
	}

	// Build the dependency path
	depPath := fmt.Sprintf("vendored > %s@%s (in %s)", target.PackageName, target.PackageVersion, target.RelPath)

	return Vulnerability{
		ID:               vulnID,
		Title:            osvVuln.Summary,
		Severity:         severity,
		PackageName:      target.PackageName,
		Version:          target.PackageVersion,
		FixedIn:          fixedIn,
		Description:      description,
		Path:             depPath,
		Paths:            []string{depPath},
		ProjectType:      ProjectType(target.Ecosystem),
		CVE:              cve,
		AdvisoryURL:      advisoryURL,
		CVSSScore:        cvssScore,
		CVSSVector:       cvssVector,
		CWECodes:         cweCodes,
		AffectedVersions: affectedVersions,
		InstalledVersion: target.PackageVersion,
		FixAvailable:     fixedIn != "",
		Sources:          []string{"osv"},
	}
}

// extractOSVSeverity determines severity from OSV vuln data
func extractOSVSeverity(vuln OSVVuln) string {
	// Try CVSS v3 score first
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V3" {
			score := parseCVSSScore(sev.Score)
			return cvssToSeverity(score)
		}
	}

	// Try database_specific severity
	if dbSpec := vuln.DatabaseSpecific; dbSpec != nil {
		if sev, ok := dbSpec["severity"].(string); ok {
			return normalizeSeverity(sev)
		}
	}

	// Try affected[].database_specific
	for _, affected := range vuln.Affected {
		if dbSpec := affected.DatabaseSpecific; dbSpec != nil {
			if sev, ok := dbSpec["severity"].(string); ok {
				return normalizeSeverity(sev)
			}
		}
	}

	return "medium" // default if we can't determine
}

// parseCVSSScore extracts the numeric score from a CVSS vector string
func parseCVSSScore(vector string) float64 {
	// CVSS vectors don't contain the score directly
	// We need to estimate from the vector or find it in the response
	// For now, try simple extraction from common formats
	// If the "score" field is just a number, parse it
	var score float64
	if _, err := fmt.Sscanf(vector, "%f", &score); err == nil && score > 0 && score <= 10 {
		return score
	}
	return 0
}

// cvssToSeverity converts a CVSS score to a severity string
func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "medium"
	}
}

// normalizeSeverity normalizes severity strings to lowercase
func normalizeSeverity(sev string) string {
	s := strings.ToLower(strings.TrimSpace(sev))
	switch s {
	case "critical", "high", "medium", "moderate", "low", "info":
		if s == "moderate" {
			return "medium"
		}
		return s
	default:
		return "medium"
	}
}

// extractAffectedVersions builds a human-readable affected version string
func extractAffectedVersions(vuln OSVVuln) string {
	var ranges []string
	for _, affected := range vuln.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Introduced != "" {
					rangeStr := ">=" + event.Introduced
					ranges = append(ranges, rangeStr)
				}
				if event.Fixed != "" {
					rangeStr := "<" + event.Fixed
					ranges = append(ranges, rangeStr)
				}
				if event.LastAffected != "" {
					rangeStr := "<=" + event.LastAffected
					ranges = append(ranges, rangeStr)
				}
			}
		}
	}
	if len(ranges) == 0 {
		return ""
	}
	return strings.Join(ranges, ", ")
}

// extractFixedVersion extracts the fixed version from OSV data
func extractFixedVersion(vuln OSVVuln) string {
	var fixed []string
	for _, affected := range vuln.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					fixed = append(fixed, event.Fixed)
				}
			}
		}
	}
	if len(fixed) == 0 {
		return ""
	}
	return strings.Join(fixed, ", ")
}

// extractCWECodes extracts CWE codes from database_specific
func extractCWECodes(vuln OSVVuln) []string {
	var cwes []string

	if dbSpec := vuln.DatabaseSpecific; dbSpec != nil {
		if cweList, ok := dbSpec["cwe_ids"].([]interface{}); ok {
			for _, c := range cweList {
				if cweStr, ok := c.(string); ok {
					cwes = append(cwes, cweStr)
				}
			}
		}
	}

	return cwes
}

// GenerateOSVJSONReport writes the OSV audit result to ada-osv-report.json
func GenerateOSVJSONReport(result *AuditResult) error {
	filename := "ada-osv-report.json"

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %v", err)
	}

	fmt.Printf("[>] OSV JSON report saved to: %s\n", filename)
	return nil
}

// ReadCollectManifest reads an ada-collect-manifest.json file
func ReadCollectManifest(path string) (*CollectResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %v", err)
	}

	var result CollectResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %v", err)
	}

	return &result, nil
}

