package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type AuditResult struct {
	ProjectType      ProjectType       `json:"projectType"`
	ProjectName      string            `json:"projectName"`
	Timestamp        time.Time         `json:"timestamp"`
	Vulnerabilities  []Vulnerability   `json:"vulnerabilities"`
	Summary          AuditSummary      `json:"summary"`
	MultiProjectInfo *MultiProjectInfo `json:"multiProjectInfo,omitempty"`
}

type MultiProjectInfo struct {
	ProjectTypes []ProjectType                `json:"projectTypes"`
	ProjectNames []string                     `json:"projectNames"`
	AuditResults map[ProjectType]*AuditResult `json:"auditResults"`
}

type Vulnerability struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Severity    string      `json:"severity"`
	PackageName string      `json:"packageName"`
	Version     string      `json:"version"`
	FixedIn     string      `json:"fixedIn,omitempty"`
	Description string      `json:"description,omitempty"`
	Path        string      `json:"path,omitempty"`
	Paths       []string    `json:"paths,omitempty"`
	ProjectType ProjectType `json:"projectType,omitempty"`

	// Additional detailed fields
	CVE              string   `json:"cve,omitempty"`
	AdvisoryURL      string   `json:"advisoryUrl,omitempty"`
	CVSSScore        float64  `json:"cvssScore,omitempty"`
	CVSSVector       string   `json:"cvssVector,omitempty"`
	CWECodes         []string `json:"cweCodes,omitempty"`
	AffectedVersions string   `json:"affectedVersions,omitempty"`
	InstalledVersion string   `json:"installedVersion,omitempty"`
	FixAvailable     bool     `json:"fixAvailable,omitempty"`
	ReportedAt       string   `json:"reportedAt,omitempty"`
	Sources          []string `json:"sources,omitempty"`
}

type AuditSummary struct {
	TotalVulnerabilities int `json:"totalVulnerabilities"`
	Critical             int `json:"critical"`
	High                 int `json:"high"`
	Medium               int `json:"medium"`
	Low                  int `json:"low"`
	Info                 int `json:"info"`
}

// runAudits runs the appropriate audit command based on project type
func RunAudits(dir string, projectType ProjectType) (*AuditResult, error) {
	projectInfo, err := GetProjectInfo(dir)
	if err != nil {
		return nil, err
	}

	if projectType == ProjectTypeMulti {
		return RunMultiProjectAudits(dir, projectInfo)
	}

	// Single project type
	projectName, err := GetProjectName(dir, projectType)
	if err != nil {
		return nil, err
	}

	result := &AuditResult{
		ProjectType: projectType,
		ProjectName: projectName,
		Timestamp:   time.Now(),
	}

	switch projectType {
	case ProjectTypeNPM:
		vulns, summary, err := runNpmAudit(dir)
		if err != nil {
			return nil, err
		}
		result.Vulnerabilities = sortVulnerabilitiesBySeverity(vulns)
		result.Summary = summary

	case ProjectTypeComposer:
		vulns, summary, err := runComposerAudit(dir)
		if err != nil {
			return nil, err
		}
		result.Vulnerabilities = sortVulnerabilitiesBySeverity(vulns)
		result.Summary = summary

	default:
		return nil, fmt.Errorf("unsupported project type: %s", projectType)
	}

	return result, nil
}

// runMultiProjectAudits runs audits for multiple project types
func RunMultiProjectAudits(dir string, projectInfo *ProjectInfo) (*AuditResult, error) {
	result := &AuditResult{
		ProjectType: ProjectTypeMulti,
		ProjectName: strings.Join(projectInfo.ProjectNames, " + "),
		Timestamp:   time.Now(),
		MultiProjectInfo: &MultiProjectInfo{
			ProjectTypes: projectInfo.ProjectTypes,
			ProjectNames: projectInfo.ProjectNames,
			AuditResults: make(map[ProjectType]*AuditResult),
		},
	}

	// Run audits for each project type
	for _, projectType := range projectInfo.ProjectTypes {
		projectName, err := GetProjectName(dir, projectType)
		if err != nil {
			continue
		}

		var vulns []Vulnerability
		var summary AuditSummary

		switch projectType {
		case ProjectTypeNPM:
			vulns, summary, err = runNpmAudit(dir)
		case ProjectTypeComposer:
			vulns, summary, err = runComposerAudit(dir)
		}

		if err == nil {
			// Add project type to vulnerabilities
			for i := range vulns {
				vulns[i].ProjectType = projectType
			}

			// Store individual results
			result.MultiProjectInfo.AuditResults[projectType] = &AuditResult{
				ProjectType:     projectType,
				ProjectName:     projectName,
				Vulnerabilities: vulns,
				Summary:         summary,
			}

			// Aggregate vulnerabilities and summary
			result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
			result.Summary.TotalVulnerabilities += summary.TotalVulnerabilities
			result.Summary.Critical += summary.Critical
			result.Summary.High += summary.High
			result.Summary.Medium += summary.Medium
			result.Summary.Low += summary.Low
			result.Summary.Info += summary.Info
		}
	}

	// Sort vulnerabilities by severity
	result.Vulnerabilities = sortVulnerabilitiesBySeverity(result.Vulnerabilities)

	return result, nil
}

// runNpmAudit runs npm audit and parses the JSON output
func runNpmAudit(dir string) ([]Vulnerability, AuditSummary, error) {
	// Check if npm is installed
	if _, err := exec.LookPath("npm"); err != nil {
		// Try to install npm in a temporary location
		return installAndRunNpmAudit(dir)
	}

	// First try to run npm audit
	cmd := exec.Command("npm", "audit", "--json")
	cmd.Dir = dir

	output, err := cmd.Output()
	if err != nil {
		// Check if the error is due to missing lockfile
		errorOutput := ""
		if exitErr, ok := err.(*exec.ExitError); ok {
			errorOutput = string(exitErr.Stderr)
		}

		if strings.Contains(errorOutput, "ENOLOCK") ||
			strings.Contains(errorOutput, "requires an existing lockfile") ||
			strings.Contains(errorOutput, "shrinkwrap file") {

			// Generate lockfile first
			fmt.Printf("[>] Generating npm lockfile...\n")
			lockCmd := exec.Command("npm", "i", "--package-lock-only")
			lockCmd.Dir = dir
			lockCmd.Stdout = os.Stdout
			lockCmd.Stderr = os.Stderr

			if lockErr := lockCmd.Run(); lockErr != nil {
				return nil, AuditSummary{}, fmt.Errorf("failed to generate lockfile: %v", lockErr)
			}

			// Now try npm audit again
			fmt.Printf("[>] Running npm audit...\n")
			cmd = exec.Command("npm", "audit", "--json")
			cmd.Dir = dir
			output, err = cmd.Output()
			if err != nil {
				// npm audit returns non-zero exit code when vulnerabilities are found
				// This is expected behavior, so we continue processing
			}
		} else {
			// npm audit returns non-zero exit code when vulnerabilities are found
			// This is expected behavior, so we continue processing
		}
	}

	return parseNpmAuditOutput(output, dir)
}

// runComposerAudit runs composer audit and parses the output
func runComposerAudit(dir string) ([]Vulnerability, AuditSummary, error) {
	// Check if composer is installed
	if _, err := exec.LookPath("composer"); err != nil {
		// Try to install composer in a temporary location
		return installAndRunComposerAudit(dir)
	}

	cmd := exec.Command("composer", "audit", "--format=json")
	cmd.Dir = dir

	output, err := cmd.Output()
	if err != nil {
		// composer audit returns non-zero exit code when vulnerabilities are found
		// This is expected behavior, so we continue processing
	}

	return parseComposerAuditOutput(output, dir)
}

// installAndRunNpmAudit installs npm in a temporary location and runs audit
func installAndRunNpmAudit(dir string) ([]Vulnerability, AuditSummary, error) {
	// This is a simplified version - in production you'd want more robust handling
	tmpDir, err := os.MkdirTemp("", "ada-npm-*")
	if err != nil {
		return nil, AuditSummary{}, err
	}
	defer os.RemoveAll(tmpDir)

	// For now, return empty results with a note
	// In production, you'd install Node.js/npm and run the audit
	return []Vulnerability{}, AuditSummary{}, nil
}

// installAndRunComposerAudit installs composer in a temporary location and runs audit
func installAndRunComposerAudit(dir string) ([]Vulnerability, AuditSummary, error) {
	// This is a simplified version - in production you'd want more robust handling
	tmpDir, err := os.MkdirTemp("", "ada-composer-*")
	if err != nil {
		return nil, AuditSummary{}, err
	}
	defer os.RemoveAll(tmpDir)

	// For now, return empty results with a note
	// In production, you'd install PHP/Composer and run the audit
	return []Vulnerability{}, AuditSummary{}, nil
}

// parseNpmLockfile reads package-lock.json and returns a map of package name -> installed version
func parseNpmLockfile(dir string) map[string]string {
	versions := make(map[string]string)

	lockfilePath := filepath.Join(dir, "package-lock.json")
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return versions
	}

	var lockfile struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal(data, &lockfile); err != nil {
		return versions
	}

	// Try v2/v3 format first (packages field)
	pathLengths := make(map[string]int)
	for pkgPath, pkg := range lockfile.Packages {
		if pkgPath == "" {
			continue // skip root entry
		}
		// Extract package name from path like "node_modules/express"
		// or nested "node_modules/body-parser/node_modules/qs"
		name := pkgPath
		if idx := strings.LastIndex(pkgPath, "node_modules/"); idx >= 0 {
			name = pkgPath[idx+len("node_modules/"):]
		}
		if pkg.Version != "" {
			// Prefer the top-level (shorter path) version when duplicates exist
			if prevLen, ok := pathLengths[name]; !ok || len(pkgPath) < prevLen {
				versions[name] = pkg.Version
				pathLengths[name] = len(pkgPath)
			}
		}
	}

	// Fallback to v1 format (dependencies field)
	if len(versions) == 0 {
		for name, dep := range lockfile.Dependencies {
			if dep.Version != "" {
				versions[name] = dep.Version
			}
		}
	}

	return versions
}

// parseComposerLockfile reads composer.lock and returns a map of package name -> installed version
func parseComposerLockfile(dir string) map[string]string {
	versions := make(map[string]string)

	lockfilePath := filepath.Join(dir, "composer.lock")
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return versions
	}

	var lockfile struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages-dev"`
	}

	if err := json.Unmarshal(data, &lockfile); err != nil {
		return versions
	}

	for _, pkg := range lockfile.Packages {
		if pkg.Name != "" && pkg.Version != "" {
			versions[pkg.Name] = strings.TrimPrefix(pkg.Version, "v")
		}
	}
	for _, pkg := range lockfile.PackagesDev {
		if pkg.Name != "" && pkg.Version != "" {
			versions[pkg.Name] = strings.TrimPrefix(pkg.Version, "v")
		}
	}

	return versions
}

// parseNpmAuditOutput parses the JSON output from npm audit
func parseNpmAuditOutput(output []byte, dir string) ([]Vulnerability, AuditSummary, error) {
	var npmAudit struct {
		Vulnerabilities map[string]struct {
			Name         string        `json:"name"`
			Severity     string        `json:"severity"`
			Via          []interface{} `json:"via"`
			Effects      []string      `json:"effects"`
			Range        string        `json:"range"`
			Nodes        []string      `json:"nodes"`
			FixAvailable interface{}   `json:"fixAvailable"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(output, &npmAudit); err != nil {
		outputStr := string(output)
		if strings.Contains(strings.ToLower(outputStr), "no vulnerabilities") ||
			strings.Contains(strings.ToLower(outputStr), "no security") ||
			strings.Contains(strings.ToLower(outputStr), "audit endpoint") {
			return []Vulnerability{}, AuditSummary{}, nil
		}
		return nil, AuditSummary{}, fmt.Errorf("failed to parse npm audit output: %v\nOutput: %s", err, string(output))
	}

	// Get actual installed versions from lockfile
	lockfileVersions := parseNpmLockfile(dir)

	var vulns []Vulnerability
	summary := AuditSummary{}

	// Track seen vulnerabilities — map key to index in vulns slice for path accumulation
	seenVulns := make(map[string]int)
	// Track which package names have at least one resolved advisory (object via processed)
	resolvedPackages := make(map[string]bool)

	// ── Pass 1: Process all entries that have object via references (real advisories) ──
	for _, vuln := range npmAudit.Vulnerabilities {
		severity := vuln.Severity
		if strings.ToLower(severity) == "moderate" {
			severity = "Medium"
		}

		// Handle fixAvailable
		fixAvailable := false
		if vuln.FixAvailable != nil {
			if fixBool, ok := vuln.FixAvailable.(bool); ok {
				fixAvailable = fixBool
			} else if fixObj, ok := vuln.FixAvailable.(map[string]interface{}); ok {
				if _, hasVersion := fixObj["version"]; hasVersion {
					fixAvailable = true
				}
			}
		}

		// Resolve installed version from lockfile
		installedVersion := "Unknown"
		if v, ok := lockfileVersions[vuln.Name]; ok {
			installedVersion = v
		}

		for _, via := range vuln.Via {
			viaMap, isObject := via.(map[string]interface{})
			if !isObject {
				// String via references are handled in Pass 2
				continue
			}

			// Extract vulnerability details from via object
			title := ""
			url := ""
			cve := ""
			cvssScore := 0.0
			cvssVector := ""
			cweCodes := []string{}
			affectedVersions := ""
			viaPackageName := vuln.Name

			if t, ok := viaMap["title"].(string); ok {
				title = t
			}
			if n, ok := viaMap["name"].(string); ok {
				viaPackageName = n
			}
			if u, ok := viaMap["url"].(string); ok {
				url = u
				// Extract advisory ID from GitHub URL
				if strings.Contains(url, "github.com/advisories/") {
					parts := strings.Split(url, "/")
					if len(parts) > 0 {
						cve = parts[len(parts)-1]
					}
				}
			}
			if cvss, ok := viaMap["cvss"].(map[string]interface{}); ok {
				if score, ok := cvss["score"].(float64); ok {
					cvssScore = score
				}
				if vector, ok := cvss["vectorString"].(string); ok {
					cvssVector = vector
				}
			}
			if cwe, ok := viaMap["cwe"].([]interface{}); ok {
				for _, c := range cwe {
					if cweStr, ok := c.(string); ok {
						cweCodes = append(cweCodes, cweStr)
					}
				}
			}
			if r, ok := viaMap["range"].(string); ok {
				affectedVersions = r
			}

			// Get actual installed version for the via package from lockfile
			viaInstalledVersion := installedVersion
			if v, ok := lockfileVersions[viaPackageName]; ok {
				viaInstalledVersion = v
			}

			// Get severity from via object if available
			viaSeverity := severity
			if viaSev, ok := viaMap["severity"].(string); ok {
				viaSeverity = viaSev
				if strings.ToLower(viaSeverity) == "moderate" {
					viaSeverity = "Medium"
				}
			}

			// Create unique key for deduplication
			// Use URL as fallback if CVE is empty (URL is always unique per advisory)
			uniqueID := cve
			if uniqueID == "" {
				uniqueID = url
			}
			vulnKey := fmt.Sprintf("%s:%s", viaPackageName, uniqueID)

			// Build dependency paths from nodes
			var nodePaths []string
			if len(vuln.Nodes) > 0 {
				for _, node := range vuln.Nodes {
					nodePaths = append(nodePaths, node)
				}
			} else {
				nodePaths = []string{viaPackageName}
			}

			// If we've seen this vuln before, accumulate new paths into the existing record
			if existingIdx, seen := seenVulns[vulnKey]; seen {
				for _, np := range nodePaths {
					if !containsString(vulns[existingIdx].Paths, np) {
						vulns[existingIdx].Paths = append(vulns[existingIdx].Paths, np)
					}
				}
				continue
			}

			// New vulnerability — create record with all paths
			seenVulns[vulnKey] = len(vulns)
			resolvedPackages[viaPackageName] = true

			v := Vulnerability{
				ID:               cve,
				Title:            title,
				Severity:         viaSeverity,
				PackageName:      viaPackageName,
				Version:          affectedVersions,
				FixedIn:          "",
				Description:      title,
				Path:             strings.Join(nodePaths, ", "),
				Paths:            nodePaths,
				ProjectType:      ProjectTypeNPM,
				CVE:              cve,
				AdvisoryURL:      url,
				CVSSScore:        cvssScore,
				CVSSVector:       cvssVector,
				CWECodes:         cweCodes,
				AffectedVersions: affectedVersions,
				InstalledVersion: viaInstalledVersion,
				FixAvailable:     fixAvailable,
			}
			vulns = append(vulns, v)

			// Update summary
			summary.TotalVulnerabilities++
			switch strings.ToLower(viaSeverity) {
			case "critical":
				summary.Critical++
			case "high":
				summary.High++
			case "moderate", "medium":
				summary.Medium++
			case "low":
				summary.Low++
			case "info":
				summary.Info++
			}
		}
	}

	// ── Pass 2: Catch string-via-only entries whose references were NOT resolved ──
	// If a package only has string via refs (e.g. via: ["lodash"]) and the referenced
	// package WAS resolved in Pass 1, we're fine — the advisory is already captured.
	// But if any referenced package was NOT resolved, we must create a fallback entry
	// so no vulnerability is silently missed.
	for _, vuln := range npmAudit.Vulnerabilities {
		// Check what kind of via entries this package has
		hasObjectVia := false
		var stringVias []string

		for _, via := range vuln.Via {
			if _, ok := via.(map[string]interface{}); ok {
				hasObjectVia = true
			} else if s, ok := via.(string); ok {
				stringVias = append(stringVias, s)
			}
		}

		// Skip if this entry had object vias — already fully processed in Pass 1
		if hasObjectVia {
			continue
		}

		// Skip if no via references at all
		if len(stringVias) == 0 {
			continue
		}

		// Skip if this package itself already has a resolved advisory
		if resolvedPackages[vuln.Name] {
			continue
		}

		// Check if ALL string via references were resolved in Pass 1
		allResolved := true
		for _, ref := range stringVias {
			if !resolvedPackages[ref] {
				allResolved = false
				break
			}
		}

		if allResolved {
			// The actual advisories are captured on the referenced packages — safe to skip
			continue
		}

		// ⚠ UNRESOLVED: at least one via reference has no advisory captured
		// Create a fallback vulnerability entry so nothing is missed
		severity := vuln.Severity
		if strings.ToLower(severity) == "moderate" {
			severity = "Medium"
		}

		fixAvailable := false
		if vuln.FixAvailable != nil {
			if fixBool, ok := vuln.FixAvailable.(bool); ok {
				fixAvailable = fixBool
			} else if fixObj, ok := vuln.FixAvailable.(map[string]interface{}); ok {
				if _, hasVersion := fixObj["version"]; hasVersion {
					fixAvailable = true
				}
			}
		}

		installedVersion := lockfileVersions[vuln.Name]
		if installedVersion == "" {
			installedVersion = "Unknown"
		}

		var nodePaths []string
		if len(vuln.Nodes) > 0 {
			nodePaths = vuln.Nodes
		} else {
			nodePaths = []string{vuln.Name}
		}

		vulnKey := fmt.Sprintf("%s:transitive:%s", vuln.Name, strings.Join(stringVias, "+"))
		if _, seen := seenVulns[vulnKey]; seen {
			continue
		}
		seenVulns[vulnKey] = len(vulns)

		v := Vulnerability{
			ID:               vuln.Name,
			Title:            fmt.Sprintf("Vulnerability in %s (via %s)", vuln.Name, strings.Join(stringVias, ", ")),
			Severity:         severity,
			PackageName:      vuln.Name,
			Version:          vuln.Range,
			FixedIn:          "",
			Description:      fmt.Sprintf("Transitive vulnerability introduced through: %s. Affected versions: %s", strings.Join(stringVias, ", "), vuln.Range),
			Path:             strings.Join(nodePaths, ", "),
			Paths:            nodePaths,
			ProjectType:      ProjectTypeNPM,
			AffectedVersions: vuln.Range,
			InstalledVersion: installedVersion,
			FixAvailable:     fixAvailable,
		}
		vulns = append(vulns, v)

		summary.TotalVulnerabilities++
		switch strings.ToLower(severity) {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "moderate", "medium":
			summary.Medium++
		case "low":
			summary.Low++
		case "info":
			summary.Info++
		}
	}

	return vulns, summary, nil
}

// parseComposerAuditOutput parses the output from composer audit
func parseComposerAuditOutput(output []byte, dir string) ([]Vulnerability, AuditSummary, error) {
	// Check if output is empty or whitespace only
	if len(strings.TrimSpace(string(output))) == 0 {
		// No vulnerabilities found, return empty results
		return []Vulnerability{}, AuditSummary{}, nil
	}

	// Try to parse as JSON
	var composerAudit struct {
		Advisories map[string][]struct {
			AdvisoryID       string `json:"advisoryId"`
			PackageName      string `json:"packageName"`
			AffectedVersions string `json:"affectedVersions"`
			Title            string `json:"title"`
			CVE              string `json:"cve"`
			Link             string `json:"link"`
			ReportedAt       string `json:"reportedAt"`
			Sources          []struct {
				Name     string `json:"name"`
				RemoteID string `json:"remoteId"`
			} `json:"sources"`
			Severity string `json:"severity"`
		} `json:"advisories"`
	}

	if err := json.Unmarshal(output, &composerAudit); err != nil {
		// If JSON parsing fails, check if it's a "no vulnerabilities" message
		outputStr := string(output)
		if strings.Contains(strings.ToLower(outputStr), "no vulnerabilities") ||
			strings.Contains(strings.ToLower(outputStr), "no security") ||
			strings.Contains(strings.ToLower(outputStr), "no advisories") {
			return []Vulnerability{}, AuditSummary{}, nil
		}

		// Log the actual output for debugging
		return nil, AuditSummary{}, fmt.Errorf("failed to parse composer audit output: %v\nOutput: %s", err, string(output))
	}

	// Parse lockfile to get actual installed versions
	lockfileVersions := parseComposerLockfile(dir)

	var vulns []Vulnerability
	summary := AuditSummary{}

	for packageName, advisories := range composerAudit.Advisories {
		// Resolve the actual installed version from the lockfile
		installedVersion := "Unknown"
		if v, ok := lockfileVersions[packageName]; ok {
			installedVersion = v
		}

		for _, advisory := range advisories {
			// Extract source names
			sourceNames := make([]string, 0)
			for _, source := range advisory.Sources {
				sourceNames = append(sourceNames, source.Name)
			}

			composerPath := "vendor > " + packageName
			v := Vulnerability{
				ID:               advisory.AdvisoryID,
				Title:            advisory.Title,
				Severity:         advisory.Severity,
				PackageName:      packageName,
				Version:          installedVersion,
				FixedIn:          "",
				Description:      advisory.Title,
				Path:             composerPath,
				Paths:            []string{composerPath},
				ProjectType:      ProjectTypeComposer,
				CVE:              advisory.CVE,
				AdvisoryURL:      advisory.Link,
				AffectedVersions: advisory.AffectedVersions,
				InstalledVersion: installedVersion,
				ReportedAt:       advisory.ReportedAt,
				Sources:          sourceNames,
			}
			vulns = append(vulns, v)

			// Update summary
			summary.TotalVulnerabilities++
			switch strings.ToLower(advisory.Severity) {
			case "critical":
				summary.Critical++
			case "high":
				summary.High++
			case "medium":
				summary.Medium++
			case "low":
				summary.Low++
			case "info":
				summary.Info++
			}
		}
	}

	return vulns, summary, nil
}

// containsString checks if a string slice contains a specific value
func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// sortVulnerabilitiesBySeverity sorts vulnerabilities by severity (highest to lowest)
func sortVulnerabilitiesBySeverity(vulns []Vulnerability) []Vulnerability {
	severityOrder := map[string]int{
		"critical":    1,
		"high":        2,
		"medium":      3,
		"low":         4,
		"info":        5,
		"informative": 5,
	}

	// Sort vulnerabilities by severity
	sort.Slice(vulns, func(i, j int) bool {
		severityI := strings.ToLower(vulns[i].Severity)
		severityJ := strings.ToLower(vulns[j].Severity)
		return severityOrder[severityI] < severityOrder[severityJ]
	})

	return vulns
}
