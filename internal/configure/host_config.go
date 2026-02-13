package configure

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type hostConfig struct {
	name                 string
	mcpGlobalConfigPath  string // Path to MCP server configuration JSON
	localRulesPath       string // Relative path for local workspace rules
	globalRulesPath      string // Absolute path for global user rules (delimited)
	globalSkillsPath     string // Absolute path for global user skills (no delimiters)
	legacyLocalRulesPath string // Old local rules path to clean up during migration
}

// getHostConfig returns MCP-Host-specific configuration based on the host name
func getHostConfig(hostName string) (*hostConfig, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	hostLower := strings.ToLower(hostName)
	switch hostLower {
	case "cursor":
		return &hostConfig{
			name:                 hostName,
			mcpGlobalConfigPath:  filepath.Join(homeDir, ".cursor", "mcp.json"),
			globalSkillsPath:     filepath.Join(homeDir, ".cursor", "skills", "snyk-rules", "SKILL.md"),
			legacyLocalRulesPath: filepath.Join(".cursor", "rules", "snyk_rules.mdc"),
		}, nil
	case "windsurf":
		return &hostConfig{
			name:                 hostName,
			mcpGlobalConfigPath:  filepath.Join(homeDir, ".codeium", "windsurf", "mcp_config.json"),
			globalRulesPath:      filepath.Join(homeDir, ".codeium", "windsurf", "memories", "global_rules.md"),
			legacyLocalRulesPath: filepath.Join(".windsurf", "rules", "snyk_rules.md"),
		}, nil
	case "antigravity":
		return &hostConfig{
			name:                 hostName,
			mcpGlobalConfigPath:  filepath.Join(homeDir, ".gemini", "antigravity", "mcp_config.json"),
			globalRulesPath:      filepath.Join(homeDir, ".gemini", "GEMINI.md"),
			legacyLocalRulesPath: filepath.Join(".agent", "rules", "snyk_rules.md"),
		}, nil
	case "visual studio code", "visual studio code - insiders", "vs_code":
		configDir, configDirErr := os.UserConfigDir()
		if configDirErr != nil {
			return nil, fmt.Errorf("failed to get user config directory: %w", configDirErr)
		}

		vscodeDir := "Code"
		if hostLower == "visual studio code - insiders" {
			vscodeDir = "Code - Insiders"
		}

		return &hostConfig{
			name:                 hostName,
			globalRulesPath:      filepath.Join(configDir, vscodeDir, "User", "prompts", "snyk_rules.instructions.md"),
			legacyLocalRulesPath: filepath.Join(".github", "instructions", "snyk_rules.instructions.md"),
		}, nil
	case "gemini-cli":
		return &hostConfig{
			name:                hostName,
			mcpGlobalConfigPath: filepath.Join(homeDir, ".gemini", "settings.json"),
			globalRulesPath:     filepath.Join(homeDir, ".gemini", "GEMINI.md"),
		}, nil
	case "claude-cli":
		return &hostConfig{
			name:                hostName,
			mcpGlobalConfigPath: filepath.Join(homeDir, ".claude.json"),
			globalRulesPath:     filepath.Join(homeDir, ".claude", "CLAUDE.md"),
		}, nil
	}
	return nil, fmt.Errorf("unsupported Tool: %s", hostName)
}
