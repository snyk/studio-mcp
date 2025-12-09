package configure

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type hostConfig struct {
	name                string
	mcpGlobalConfigPath string // Path to MCP server configuration JSON
	localRulesPath      string // Relative path for local workspace rules
	globalRulesPath     string // Absolute path for global user rules
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
			name:                hostName,
			mcpGlobalConfigPath: filepath.Join(homeDir, ".cursor", "mcp.json"),
			localRulesPath:      filepath.Join(".cursor", "rules", "snyk_rules.mdc"),
		}, nil
	case "windsurf":
		return &hostConfig{
			name:                hostName,
			mcpGlobalConfigPath: filepath.Join(homeDir, ".codeium", "windsurf", "mcp_config.json"),
			localRulesPath:      filepath.Join(".windsurf", "rules", "snyk_rules.md"),
		}, nil
	case "antigravity":
		return &hostConfig{
			name:                hostName,
			mcpGlobalConfigPath: filepath.Join(homeDir, ".gemini", "antigravity", "mcp_config.json"),
			localRulesPath:      filepath.Join(".agent", "rules", "snyk_rules.md"),
		}, nil
	case "visual studio code":
	case "visual studio code - insider":
	case "vs_code":
		return &hostConfig{
			name:           hostName,
			localRulesPath: filepath.Join(".github", "instructions", "snyk_rules.instructions.md"),
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
