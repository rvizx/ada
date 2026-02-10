package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CollectResult holds the complete result of a dependency file collection
type CollectResult struct {
	SourceDir   string          `json:"sourceDir"`
	OutputDir   string          `json:"outputDir"`
	Targets     []CollectTarget `json:"targets"`
	SkippedDirs []string        `json:"skippedDirs"`
	TotalFiles  int             `json:"totalFiles"`
}

// CollectTarget represents a single dependency target discovered during collection
type CollectTarget struct {
	// Path relative to source root (e.g. "src/client")
	RelPath string `json:"relPath"`
	// Ecosystem: "npm" or "composer"
	Ecosystem string `json:"ecosystem"`
	// Files collected for this target (relative to target dir)
	Files []string `json:"files"`
	// Whether a lockfile was found
	HasLockfile bool `json:"hasLockfile"`
	// Whether this target is worth scanning (has actual dependencies)
	Scannable bool `json:"scannable"`
	// Reason for classification
	Reason string `json:"reason"`
	// Package name extracted from manifest (for vendored libs)
	PackageName string `json:"packageName,omitempty"`
	// Package version extracted from manifest (for vendored libs)
	PackageVersion string `json:"packageVersion,omitempty"`
}

// knownDepFiles maps filenames to their ecosystem
var knownDepFiles = map[string]string{
	"package.json":      "npm",
	"package-lock.json": "npm",
	"yarn.lock":         "npm",
	"pnpm-lock.yaml":    "npm",
	"npm-shrinkwrap.json": "npm",
	"composer.json":     "composer",
	"composer.lock":     "composer",
}

// lockfileNames identifies which files are lockfiles
var lockfileNames = map[string]bool{
	"package-lock.json":   true,
	"yarn.lock":           true,
	"pnpm-lock.yaml":      true,
	"npm-shrinkwrap.json": true,
	"composer.lock":       true,
}

// skippedDirNames lists directories that should be skipped during walking
var skippedDirNames = map[string]bool{
	"node_modules":  true,
	"vendor":        true,
	".git":          true,
	".svn":          true,
	".hg":           true,
	"dist":          true,
	"build":         true,
	"out":           true,
	"target":        true,
	".next":         true,
	".nuxt":         true,
	"__pycache__":   true,
	".cache":        true,
	".tmp":          true,
	"tmp":           true,
	"temp":          true,
	"coverage":      true,
	".nyc_output":   true,
	"bower_components": true,
	".gradle":       true,
	".idea":         true,
	".vscode":       true,
	".DS_Store":     true,
}

// CollectDependencyFiles walks sourceDir, finds dependency manifests/lockfiles,
// copies them to outputDir preserving directory structure, and classifies each target.
func CollectDependencyFiles(sourceDir, outputDir string) (*CollectResult, error) {
	// Normalize paths
	sourceDir, err := filepath.Abs(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve source path: %v", err)
	}
	outputDir, err = filepath.Abs(outputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve output path: %v", err)
	}

	// Ensure source exists
	if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("source directory does not exist: %s", sourceDir)
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	result := &CollectResult{
		SourceDir: sourceDir,
		OutputDir: outputDir,
	}

	// targetMap groups discovered files by their parent directory (relative to sourceDir)
	// key = relative dir path, value = list of filenames found there
	targetMap := make(map[string][]string)

	// Walk the source tree
	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}

		// Skip output directory if it's inside source
		if strings.HasPrefix(path, outputDir) {
			return filepath.SkipDir
		}

		if info.IsDir() {
			if isSkippedDir(info.Name(), path, sourceDir) {
				result.SkippedDirs = append(result.SkippedDirs, mustRelPath(sourceDir, path))
				return filepath.SkipDir
			}
			return nil
		}

		// Check if this file is a known dependency file
		if _, known := knownDepFiles[info.Name()]; known {
			relDir := mustRelPath(sourceDir, filepath.Dir(path))
			targetMap[relDir] = append(targetMap[relDir], info.Name())
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk source directory: %v", err)
	}

	// Process each target directory
	for relDir, files := range targetMap {
		target := processTarget(sourceDir, outputDir, relDir, files)
		result.Targets = append(result.Targets, target)
		result.TotalFiles += len(target.Files)
	}

	// Sort targets for deterministic output
	sort.Slice(result.Targets, func(i, j int) bool {
		return result.Targets[i].RelPath < result.Targets[j].RelPath
	})
	sort.Strings(result.SkippedDirs)

	// Write manifest JSON
	manifestPath := filepath.Join(outputDir, "ada-collect-manifest.json")
	manifestData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return nil, fmt.Errorf("failed to write manifest: %v", err)
	}

	return result, nil
}

// processTarget creates a CollectTarget for one directory, copies files, and classifies it
func processTarget(sourceDir, outputDir, relDir string, files []string) CollectTarget {
	// Determine ecosystem from first manifest file
	ecosystem := ""
	hasLockfile := false
	var copiedFiles []string

	for _, f := range files {
		if eco, ok := knownDepFiles[f]; ok {
			if ecosystem == "" {
				ecosystem = eco
			}
		}
		if lockfileNames[f] {
			hasLockfile = true
		}
	}

	// Copy files to output, preserving directory structure
	srcFullDir := filepath.Join(sourceDir, relDir)
	dstFullDir := filepath.Join(outputDir, relDir)

	if err := os.MkdirAll(dstFullDir, 0755); err == nil {
		for _, f := range files {
			srcFile := filepath.Join(srcFullDir, f)
			dstFile := filepath.Join(dstFullDir, f)
			if err := copyFile(srcFile, dstFile); err == nil {
				copiedFiles = append(copiedFiles, f)
			}
		}
	}

	// Classify target
	target := CollectTarget{
		RelPath:     relDir,
		Ecosystem:   ecosystem,
		Files:       copiedFiles,
		HasLockfile: hasLockfile,
	}

	classifyTarget(srcFullDir, &target)

	return target
}

// classifyTarget determines whether a target is scannable and extracts package metadata
func classifyTarget(srcFullDir string, target *CollectTarget) {
	// Always extract package name and version from manifest
	manifestFile := ""
	switch target.Ecosystem {
	case "npm":
		manifestFile = filepath.Join(srcFullDir, "package.json")
	case "composer":
		manifestFile = filepath.Join(srcFullDir, "composer.json")
	}

	if manifestFile != "" {
		name, version := extractPackageInfo(manifestFile, target.Ecosystem)
		target.PackageName = name
		target.PackageVersion = version
	}

	// Classification logic
	if target.HasLockfile {
		target.Scannable = true
		target.Reason = "has lockfile"
		return
	}

	// No lockfile — check if manifest declares any dependencies
	hasDeps := manifestHasDependencies(srcFullDir, target.Ecosystem)
	if hasDeps {
		target.Scannable = true
		target.Reason = "manifest declares dependencies (no lockfile)"
		return
	}

	// No lockfile, no dependencies → vendored/bundled library
	target.Scannable = false
	target.Reason = "vendored/bundled library (no dependencies declared)"
}

// extractPackageInfo reads name and version from a manifest file
func extractPackageInfo(manifestPath, ecosystem string) (name, version string) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", ""
	}

	var manifest map[string]interface{}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", ""
	}

	if n, ok := manifest["name"].(string); ok {
		name = n
	}
	if v, ok := manifest["version"].(string); ok {
		version = v
	}

	return name, version
}

// manifestHasDependencies checks if a manifest file declares any actual dependencies
func manifestHasDependencies(dir, ecosystem string) bool {
	switch ecosystem {
	case "npm":
		return npmManifestHasDeps(filepath.Join(dir, "package.json"))
	case "composer":
		return composerManifestHasDeps(filepath.Join(dir, "composer.json"))
	}
	return false
}

// npmManifestHasDeps checks if package.json has non-empty dependencies or devDependencies
func npmManifestHasDeps(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	var pkg map[string]interface{}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return false
	}

	if deps, ok := pkg["dependencies"].(map[string]interface{}); ok && len(deps) > 0 {
		return true
	}
	if deps, ok := pkg["devDependencies"].(map[string]interface{}); ok && len(deps) > 0 {
		return true
	}
	if deps, ok := pkg["peerDependencies"].(map[string]interface{}); ok && len(deps) > 0 {
		return true
	}
	if deps, ok := pkg["optionalDependencies"].(map[string]interface{}); ok && len(deps) > 0 {
		return true
	}

	return false
}

// composerManifestHasDeps checks if composer.json has non-empty require or require-dev
func composerManifestHasDeps(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	var composer map[string]interface{}
	if err := json.Unmarshal(data, &composer); err != nil {
		return false
	}

	if deps, ok := composer["require"].(map[string]interface{}); ok && len(deps) > 0 {
		return true
	}
	if deps, ok := composer["require-dev"].(map[string]interface{}); ok && len(deps) > 0 {
		return true
	}

	return false
}

// isSkippedDir determines if a directory should be skipped during walking
func isSkippedDir(name, fullPath, sourceDir string) bool {
	// Never skip the root
	if fullPath == sourceDir {
		return false
	}

	// Check against known skip names
	if skippedDirNames[name] {
		return true
	}

	// Skip hidden directories (except .config and similar useful ones)
	if strings.HasPrefix(name, ".") && name != "." && name != ".." {
		return true
	}

	return false
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	return dstFile.Sync()
}

// mustRelPath returns the relative path or "." on error
func mustRelPath(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return "."
	}
	return rel
}

// PrintCollectSummary prints a human-readable summary of the collection result
func PrintCollectSummary(result *CollectResult) {
	fmt.Println("")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  Ada Collect — Dependency File Collection Summary")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Printf("  Source:  %s\n", result.SourceDir)
	fmt.Printf("  Output:  %s\n", result.OutputDir)
	fmt.Printf("  Targets: %d\n", len(result.Targets))
	fmt.Printf("  Files:   %d\n", result.TotalFiles)
	fmt.Printf("  Skipped: %d directories\n", len(result.SkippedDirs))
	fmt.Println("")

	// Count scannable vs vendored
	scannableCount := 0
	vendoredCount := 0
	noVersionCount := 0
	for _, t := range result.Targets {
		if t.Scannable {
			scannableCount++
		} else {
			vendoredCount++
			if t.PackageVersion == "" {
				noVersionCount++
			}
		}
	}

	fmt.Println("── Scannable Targets ──────────────────────────────────")
	fmt.Printf("  %d targets with actual dependencies (Snyk will scan these)\n\n", scannableCount)
	for _, t := range result.Targets {
		if !t.Scannable {
			continue
		}
		lockIcon := "🔒"
		if !t.HasLockfile {
			lockIcon = "📦"
		}
		fmt.Printf("  %s  %-50s  [%s]  %s\n", lockIcon, t.RelPath, t.Ecosystem, t.Reason)
		if t.PackageName != "" {
			fmt.Printf("      name: %s", t.PackageName)
			if t.PackageVersion != "" {
				fmt.Printf("  version: %s", t.PackageVersion)
			}
			fmt.Println()
		}
	}

	fmt.Println("")
	fmt.Println("── Vendored/Bundled Libraries ─────────────────────────")
	fmt.Printf("  %d libraries (Ada/OSV will check these by name+version)\n", vendoredCount)
	if noVersionCount > 0 {
		fmt.Printf("  ⚠ %d without version — cannot check for vulnerabilities\n", noVersionCount)
	}
	fmt.Println("")
	for _, t := range result.Targets {
		if t.Scannable {
			continue
		}
		versionStr := t.PackageVersion
		if versionStr == "" {
			versionStr = "⚠ no version"
		}
		fmt.Printf("  📚  %-40s  %-20s  [%s]\n", t.PackageName, versionStr, t.Ecosystem)
	}

	fmt.Println("")
	fmt.Println("── Skipped Directories ────────────────────────────────")
	fmt.Printf("  %d directories skipped (node_modules, vendor, .git, etc.)\n\n", len(result.SkippedDirs))
	for _, d := range result.SkippedDirs {
		fmt.Printf("  ⊘  %s\n", d)
	}

	fmt.Println("")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Printf("  Manifest: %s/ada-collect-manifest.json\n", result.OutputDir)
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("")
}

