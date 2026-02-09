package internal

import (
	"os"
	"path/filepath"
	"strings"
)

type ProjectType string

const (
	ProjectTypeNPM      ProjectType = "npm"
	ProjectTypeComposer ProjectType = "composer"
	ProjectTypeMulti    ProjectType = "multi"
	ProjectTypeUnknown  ProjectType = "unknown"
)

// ProjectInfo represents information about detected projects
type ProjectInfo struct {
	ProjectTypes []ProjectType
	ProjectNames []string
	Primary      ProjectType
	PrimaryName  string
}

// detectProjectType detects the type of project in the given directory
func DetectProjectType(dir string) (ProjectType, error) {
	var projectTypes []ProjectType
	var projectNames []string
	
	// Check for package.json (npm)
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		projectTypes = append(projectTypes, ProjectTypeNPM)
		if name, err := GetProjectName(dir, ProjectTypeNPM); err == nil {
			projectNames = append(projectNames, name)
		}
	}
	
	// Check for composer.json (PHP Composer)
	if _, err := os.Stat(filepath.Join(dir, "composer.json")); err == nil {
		projectTypes = append(projectTypes, ProjectTypeComposer)
		if name, err := GetProjectName(dir, ProjectTypeComposer); err == nil {
			projectNames = append(projectNames, name)
		}
	}
	
	// Check for go.mod (Go)
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		// For now, we'll focus on npm and composer, but could extend this
		// projectTypes = append(projectTypes, ProjectTypeGo)
	}
	
	// Check for requirements.txt (Python pip)
	if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err == nil {
		// For now, we'll focus on npm and composer, but could extend this
		// projectTypes = append(projectTypes, ProjectTypePython)
	}
	
	// Check for Gemfile (Ruby)
	if _, err := os.Stat(filepath.Join(dir, "Gemfile")); err == nil {
		// For now, we'll focus on npm and composer, but could extend this
		// projectTypes = append(projectTypes, ProjectTypeRuby)
	}
	
	if len(projectTypes) == 0 {
		return ProjectTypeUnknown, nil
	}
	
	if len(projectTypes) == 1 {
		return projectTypes[0], nil
	}
	
	// Multiple project types detected
	return ProjectTypeMulti, nil
}

// getProjectInfo gets detailed information about detected projects
func GetProjectInfo(dir string) (*ProjectInfo, error) {
	info := &ProjectInfo{}
	
	// Check for package.json (npm)
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		info.ProjectTypes = append(info.ProjectTypes, ProjectTypeNPM)
		if name, err := GetProjectName(dir, ProjectTypeNPM); err == nil {
			info.ProjectNames = append(info.ProjectNames, name)
		}
	}
	
	// Check for composer.json (PHP Composer)
	if _, err := os.Stat(filepath.Join(dir, "composer.json")); err == nil {
		info.ProjectTypes = append(info.ProjectTypes, ProjectTypeComposer)
		if name, err := GetProjectName(dir, ProjectTypeComposer); err == nil {
			info.ProjectNames = append(info.ProjectNames, name)
		}
	}
	
	if len(info.ProjectTypes) > 0 {
		info.Primary = info.ProjectTypes[0]
		if len(info.ProjectNames) > 0 {
			info.PrimaryName = info.ProjectNames[0]
		}
	}
	
	return info, nil
}

// getProjectName extracts the project name from the project files
func GetProjectName(dir string, projectType ProjectType) (string, error) {
	switch projectType {
	case ProjectTypeNPM:
		// Read package.json and extract name
		content, err := os.ReadFile(filepath.Join(dir, "package.json"))
		if err != nil {
			return "", err
		}
		// Simple extraction - in production you'd want proper JSON parsing
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.Contains(line, `"name"`) {
				parts := strings.Split(line, `"`)
				if len(parts) >= 4 {
					return strings.TrimSpace(parts[3]), nil
				}
			}
		}
		return "npm-project", nil
		
	case ProjectTypeComposer:
		// Read composer.json and extract name
		content, err := os.ReadFile(filepath.Join(dir, "composer.json"))
		if err != nil {
			return "", err
		}
		// Simple extraction - in production you'd want proper JSON parsing
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.Contains(line, `"name"`) {
				parts := strings.Split(line, `"`)
				if len(parts) >= 4 {
					return strings.TrimSpace(parts[3]), nil
				}
			}
		}
		return "composer-project", nil
		
	default:
		return "unknown-project", nil
	}
}
