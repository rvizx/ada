package internal

import (
	_ "embed"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
)

//go:embed config.json
var configFile []byte

type Config struct {
	Theme   ThemeConfig   `json:"theme"`
	Company CompanyConfig `json:"company"`
	Report  ReportConfig  `json:"report"`
}

type ThemeConfig struct {
	PrimaryColor     string `json:"primaryColor"`
	HeaderBackground string `json:"headerBackground"`
	HeaderTextColor  string `json:"headerTextColor"`
}

type CompanyConfig struct {
	Title          string `json:"title"`
	ReportHeading  string `json:"report_heading"`
	LogoLink       string `json:"logo_link"`
	LogoLinkFooter string `json:"logo_link_footer"`
	FaviconLink    string `json:"favicon_link"`
	Website        string `json:"website"`
}

type ReportConfig struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Footer      string `json:"footer"`
}

var embeddedConfig *Config

// getUserConfigPath returns the path to the user's config file
func getUserConfigPath() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, ".config", "ada.config"), nil
}

// loadConfig loads configuration from user config file or falls back to embedded config
func loadConfig() *Config {
	// Try to load user config first
	userConfigPath, err := getUserConfigPath()
	if err == nil {
		if data, err := os.ReadFile(userConfigPath); err == nil {
			var userConfig Config
			if err := json.Unmarshal(data, &userConfig); err == nil {
				return &userConfig
			}
		}
	}

	// Fall back to embedded config
	return embeddedConfig
}

func init() {
	// Parse the embedded config.json file
	var err error
	embeddedConfig = &Config{}
	err = json.Unmarshal(configFile, embeddedConfig)
	if err != nil {
		// Fallback to default config if parsing fails
		embeddedConfig = &Config{
			Theme: ThemeConfig{
				PrimaryColor:     "#1a1a1a",
				HeaderBackground: "#1a1a1a",
				HeaderTextColor:  "#fff",
			},
			Company: CompanyConfig{
				Title:          "Zyenra Security",
				ReportHeading:  "Software Dependency Security Analysis Report",
				LogoLink:       "https://www.zyenra.com/assets/img/logo.png",
				LogoLinkFooter: "https://www.zyenra.com/assets/img/logo.png",
				FaviconLink:    "https://www.zyenra.com/favicon.ico",
				Website:        "https://www.zyenra.com",
			},
			Report: ReportConfig{
				Title:       "Software Dependency Security Analysis Report",
				Description: "Security vulnerability analysis report for Zyenra Security dependencies",
				Footer:      "All Rights Reserved - Zyenra Security \n www.zyenra.com",
			},
		}
	}
}

func GetConfig() *Config {
	return loadConfig()
}

// GetEmbeddedConfig returns the embedded config (for backward compatibility)
func GetEmbeddedConfig() *Config {
	return embeddedConfig
}

// GetThemeColor returns the primary theme color
func GetThemeColor() string {
	config := GetConfig()
	return config.Theme.PrimaryColor
}

// GetCompanyTitle returns the company title
func GetCompanyTitle() string {
	config := GetConfig()
	return config.Company.Title
}

// GetReportHeading returns the report heading
func GetReportHeading() string {
	config := GetConfig()
	return config.Company.ReportHeading
}

// GetLogoLink returns the logo link
func GetLogoLink() string {
	config := GetConfig()
	return config.Company.LogoLink
}

// GetLogoLinkFooter returns the footer logo link
func GetLogoLinkFooter() string {
	config := GetConfig()
	return config.Company.LogoLinkFooter
}

// GetFooterText returns the footer text
func GetFooterText() string {
	config := GetConfig()
	return config.Report.Footer
}

// GetGithubURL returns the GitHub URL (hardcoded to ada repository)
func GetGithubURL() string {
	return "https://github.com/rvizx/ada"
}
