package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/rvizx/ada/internal"
)

// version will be set during build via ldflags
var Version = "dev"

func printUsage() {
	fmt.Println("ada - audit aggregator")
	fmt.Println("")
	fmt.Println("usage:")
	fmt.Println("  ada audit                              generate both json and html reports")
	fmt.Println("  ada audit --json                       generate json report only")
	fmt.Println("  ada audit --html                       generate html report only")
	fmt.Println("  ada audit --help                       show this help message")
	fmt.Println("")
	fmt.Println("  ada collect --source <dir> --out <dir>  collect dependency files from source")
	fmt.Println("")
	fmt.Println("  ada osv --manifest <file>               scan vendored libs via OSV.dev")
	fmt.Println("  ada osv --manifest <file> --json        also output merged json")
	fmt.Println("")
	fmt.Println("  ada report --from-json <file>           generate html report from existing json")
	fmt.Println("  ada report --from-json <f1> <f2> ...    merge multiple jsons into one html report")
	fmt.Println("  ada report --from-json <f1> --json      also output merged json")
	fmt.Println("")
	fmt.Println("  ada --version                          show version information")
	fmt.Println("")
	fmt.Println("the tool automatically detects project types (npm, composer, etc.)")
	fmt.Println("and runs appropriate security audits.")
}

func main() {
	args := os.Args[1:]

	// check for version and help flags first (before any command)
	for _, arg := range args {
		switch arg {
		case "--help", "-help":
			printUsage()
			os.Exit(0)
		case "--version", "-version", "-v":
			fmt.Printf("ada version %s\n", Version)
			os.Exit(0)
		}
	}

	// no command provided
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "audit":
		runAuditCommand(args[1:])
	case "collect":
		runCollectCommand(args[1:])
	case "osv":
		runOSVCommand(args[1:])
	case "report":
		runReportCommand(args[1:])
	default:
		printUsage()
		os.Exit(1)
	}
}

// runAuditCommand handles: ada audit [--json] [--html]
func runAuditCommand(args []string) {
	var jsonOutput bool
	var htmlOutput bool

	for _, arg := range args {
		switch arg {
		case "--json", "-j":
			jsonOutput = true
		case "--html", "-h":
			htmlOutput = true
		case "--help":
			printUsage()
			os.Exit(0)
		default:
			fmt.Printf("[!] unknown flag: %s\n", arg)
			fmt.Println("Use 'ada audit --help' for usage information")
			os.Exit(1)
		}
	}

	// if no flags specified, generate both
	if !jsonOutput && !htmlOutput {
		jsonOutput = true
		htmlOutput = true
	}

	// get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal("[!] failed to get current working directory:", err)
	}

	// detect project type and run audits
	projectType, err := internal.DetectProjectType(cwd)
	if err != nil {
		log.Fatal("[!] failed to detect project type:", err)
	}

	if projectType == "unknown" {
		log.Fatal("[!] no supported project type detected in current directory")
	}

	// get detailed project information
	projectInfo, err := internal.GetProjectInfo(cwd)
	if err != nil {
		log.Fatal("[!] failed to get project info:", err)
	}

	// display project information
	if projectType == "multi" {
		fmt.Printf("[>] detected multi-project: %s\n", strings.Join(projectInfo.ProjectNames, " + "))
		fmt.Printf("[>] project types: %s\n", strings.Join(func() []string {
			var types []string
			for _, t := range projectInfo.ProjectTypes {
				types = append(types, string(t))
			}
			return types
		}(), ", "))
	} else {
		fmt.Printf("[>] detected project type: %s\n", projectType)
		fmt.Printf("[>] project name: %s\n", projectInfo.PrimaryName)
	}

	// run audits based on project type
	auditResults, err := internal.RunAudits(cwd, projectType)
	if err != nil {
		log.Fatal("[!] failed to run audits:", err)
	}

	// check if no vulnerabilities found
	if auditResults.Summary.TotalVulnerabilities == 0 {
		fmt.Println("[>] No vulnerabilities found - project is secure!")
		os.Exit(0)
	}

	// generate reports
	reportsGenerated := 0

	if jsonOutput {
		if err := internal.GenerateJSONReport(auditResults); err != nil {
			log.Fatal("[!] failed to generate JSON report:", err)
		} else {
			fmt.Println("[>] json report generated successfully")
			reportsGenerated++
		}
	}

	if htmlOutput {
		if err := internal.GenerateHTMLReport(auditResults); err != nil {
			log.Fatal("[!] failed to generate HTML report:", err)
		} else {
			fmt.Println("[>] html report generated successfully")
			reportsGenerated++
		}
	}

	// ensure at least one report was generated
	if reportsGenerated == 0 {
		log.Fatal("[!] no reports were generated successfully")
	}
}

// runCollectCommand handles: ada collect --source <dir> --out <dir>
func runCollectCommand(args []string) {
	var sourceDir string
	var outDir string

	i := 0
	for i < len(args) {
		switch args[i] {
		case "--source", "-s":
			if i+1 < len(args) {
				sourceDir = args[i+1]
				i += 2
				continue
			}
			fmt.Println("[!] --source requires a directory path")
			os.Exit(1)
		case "--out", "-o":
			if i+1 < len(args) {
				outDir = args[i+1]
				i += 2
				continue
			}
			fmt.Println("[!] --out requires a directory path")
			os.Exit(1)
		case "--help":
			fmt.Println("usage: ada collect --source <source-dir> --out <output-dir>")
			fmt.Println("")
			fmt.Println("Walks the source directory, finds dependency manifest and lock files,")
			fmt.Println("copies them to the output directory preserving structure, and classifies")
			fmt.Println("each target as scannable or vendored/bundled.")
			fmt.Println("")
			fmt.Println("Output: ada-collect-manifest.json in the output directory")
			os.Exit(0)
		default:
			fmt.Printf("[!] unknown flag: %s\n", args[i])
			fmt.Println("Use 'ada collect --help' for usage information")
			os.Exit(1)
		}
		i++
	}

	if sourceDir == "" {
		fmt.Println("[!] --source is required")
		fmt.Println("usage: ada collect --source <source-dir> --out <output-dir>")
		os.Exit(1)
	}
	if outDir == "" {
		fmt.Println("[!] --out is required")
		fmt.Println("usage: ada collect --source <source-dir> --out <output-dir>")
		os.Exit(1)
	}

	fmt.Printf("[>] collecting dependency files from: %s\n", sourceDir)
	fmt.Printf("[>] output directory: %s\n", outDir)

	result, err := internal.CollectDependencyFiles(sourceDir, outDir)
	if err != nil {
		log.Fatalf("[!] collect failed: %v", err)
	}

	internal.PrintCollectSummary(result)
}

// runOSVCommand handles: ada osv --manifest <file> [--json] [--html]
func runOSVCommand(args []string) {
	var manifestPath string
	var jsonOutput bool
	var htmlOutput bool

	i := 0
	for i < len(args) {
		switch args[i] {
		case "--manifest", "-m":
			if i+1 < len(args) {
				manifestPath = args[i+1]
				i += 2
				continue
			}
			fmt.Println("[!] --manifest requires a file path")
			os.Exit(1)
		case "--json", "-j":
			jsonOutput = true
		case "--html", "-h":
			htmlOutput = true
		case "--help":
			fmt.Println("usage: ada osv --manifest <ada-collect-manifest.json> [--json] [--html]")
			fmt.Println("")
			fmt.Println("Reads the collect manifest, queries OSV.dev for each vendored library,")
			fmt.Println("and produces a vulnerability report compatible with 'ada report --from-json'.")
			fmt.Println("")
			fmt.Println("flags:")
			fmt.Println("  --json    output JSON report (ada-osv-report.json)")
			fmt.Println("  --html    output HTML report")
			fmt.Println("  (default: --json)")
			os.Exit(0)
		default:
			fmt.Printf("[!] unknown flag: %s\n", args[i])
			fmt.Println("Use 'ada osv --help' for usage information")
			os.Exit(1)
		}
		i++
	}

	if manifestPath == "" {
		fmt.Println("[!] --manifest is required")
		fmt.Println("usage: ada osv --manifest <ada-collect-manifest.json> [--json] [--html]")
		os.Exit(1)
	}

	// Default to JSON output
	if !jsonOutput && !htmlOutput {
		jsonOutput = true
	}

	fmt.Printf("[>] reading collect manifest: %s\n", manifestPath)

	collectResult, err := internal.ReadCollectManifest(manifestPath)
	if err != nil {
		log.Fatalf("[!] failed to read manifest: %v", err)
	}

	// Count vendored targets
	vendoredCount := 0
	for _, t := range collectResult.Targets {
		if !t.Scannable {
			vendoredCount++
		}
	}

	if vendoredCount == 0 {
		fmt.Println("[>] no vendored targets found — nothing to scan via OSV")
		os.Exit(0)
	}

	fmt.Printf("[>] found %d vendored targets to check against OSV.dev\n", vendoredCount)

	auditResult, err := internal.ScanVendoredTargets(collectResult)
	if err != nil {
		log.Fatalf("[!] OSV scan failed: %v", err)
	}

	if auditResult.Summary.TotalVulnerabilities == 0 {
		fmt.Println("[>] no vulnerabilities found in vendored dependencies — all clean!")

		if jsonOutput {
			// Still write an empty result file so the pipeline can merge it
			if err := internal.GenerateOSVJSONReport(auditResult); err != nil {
				log.Fatalf("[!] failed to write JSON: %v", err)
			}
		}
		os.Exit(0)
	}

	// Generate reports
	if jsonOutput {
		if err := internal.GenerateOSVJSONReport(auditResult); err != nil {
			log.Fatalf("[!] failed to generate JSON report: %v", err)
		}
		fmt.Println("[>] osv json report generated successfully")
	}

	if htmlOutput {
		if err := internal.GenerateHTMLReport(auditResult); err != nil {
			log.Fatalf("[!] failed to generate HTML report: %v", err)
		}
		fmt.Println("[>] osv html report generated successfully")
	}
}

// runReportCommand handles: ada report --from-json <file1> [file2 ...] [--json] [--html]
func runReportCommand(args []string) {
	var fromJSON bool
	var jsonOutput bool
	var htmlOutput bool
	var jsonFiles []string

	i := 0
	for i < len(args) {
		switch args[i] {
		case "--from-json":
			fromJSON = true
			// collect all following arguments that are not flags as json file paths
			i++
			for i < len(args) && !strings.HasPrefix(args[i], "--") && !strings.HasPrefix(args[i], "-") {
				jsonFiles = append(jsonFiles, args[i])
				i++
			}
			continue // don't increment i again
		case "--json", "-j":
			jsonOutput = true
		case "--html", "-h":
			htmlOutput = true
		case "--help":
			printUsage()
			os.Exit(0)
		default:
			// could be a json file path without --from-json flag
			if strings.HasSuffix(args[i], ".json") {
				jsonFiles = append(jsonFiles, args[i])
			} else {
				fmt.Printf("[!] unknown flag: %s\n", args[i])
				fmt.Println("Use 'ada report --help' for usage information")
				os.Exit(1)
			}
		}
		i++
	}

	if !fromJSON || len(jsonFiles) == 0 {
		fmt.Println("[!] usage: ada report --from-json <file1.json> [file2.json ...] [--html] [--json]")
		os.Exit(1)
	}

	// default to html output if no flags specified
	if !jsonOutput && !htmlOutput {
		htmlOutput = true
	}

	// Verify all json files exist
	for _, f := range jsonFiles {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			log.Fatalf("[!] json file not found: %s", f)
		}
	}

	var auditResult *internal.AuditResult
	var err error

	if len(jsonFiles) == 1 {
		// Single file - just read it
		fmt.Printf("[>] reading audit data from: %s\n", jsonFiles[0])
		auditResult, err = internal.ReadAuditResultFromJSON(jsonFiles[0])
		if err != nil {
			log.Fatalf("[!] failed to read json: %v", err)
		}
	} else {
		// Multiple files - merge them
		fmt.Printf("[>] merging %d json report(s)...\n", len(jsonFiles))
		auditResult, err = internal.MergeAuditResults(jsonFiles)
		if err != nil {
			log.Fatalf("[!] failed to merge json reports: %v", err)
		}
	}

	fmt.Printf("[>] project: %s\n", auditResult.ProjectName)
	fmt.Printf("[>] total vulnerabilities: %d (critical: %d, high: %d, medium: %d, low: %d)\n",
		auditResult.Summary.TotalVulnerabilities,
		auditResult.Summary.Critical,
		auditResult.Summary.High,
		auditResult.Summary.Medium,
		auditResult.Summary.Low)

	if auditResult.Summary.TotalVulnerabilities == 0 {
		fmt.Println("[>] No vulnerabilities found in input data")
		os.Exit(0)
	}

	// generate reports
	reportsGenerated := 0

	if jsonOutput {
		if err := internal.GenerateJSONReport(auditResult); err != nil {
			log.Fatal("[!] failed to generate JSON report:", err)
		} else {
			fmt.Println("[>] json report generated successfully")
			reportsGenerated++
		}
	}

	if htmlOutput {
		if err := internal.GenerateHTMLReport(auditResult); err != nil {
			log.Fatal("[!] failed to generate HTML report:", err)
		} else {
			fmt.Println("[>] html report generated successfully")
			reportsGenerated++
		}
	}

	if reportsGenerated == 0 {
		log.Fatal("[!] no reports were generated successfully")
	}
}
