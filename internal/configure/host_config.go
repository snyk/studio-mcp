package configure

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type hostConfig struct {
	name                     string
	mcpGlobalConfigPath      string // Path to MCP server configuration JSON
	localRulesPath           string // Relative path for local workspace rules
	globalRulesPath          string // Absolute path for global user rules (delimited block in a shared file)
	globalSkillsPath         string // Absolute path for a host-native skill file (e.g. Cursor SKILL.md, no delimiters)
	globalDedicatedRulesPath string // Absolute path for a dedicated host-native rules file (e.g. Claude Code ~/.claude/rules/*.md, no delimiters)
	legacyLocalRulesPath     string // Old local rules path to clean up during migration (whole file removed)
	legacyGlobalRulesPath    string // Old global rules file to clean up during migration (delimited block removed in place; surrounding user content preserved)
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
		// Claude Code auto-loads any *.md file in ~/.claude/rules/ on every session
		// (see https://code.claude.com/docs/en/memory#user-level-rules), so the rules
		// belong in their own dedicated file rather than injected into the user's
		// global ~/.claude/CLAUDE.md. globalDedicatedRulesPath is distinct from
		// globalSkillsPath (Cursor's SKILL.md slot) so each host gets content
		// formatted for its own loader — Claude Code rules need no frontmatter,
		// while Cursor's SKILL.md expects name/description keys.
		// legacyGlobalRulesPath cleans up the old in-place injection from prior
		// installs that wrote a delimited block into ~/.claude/CLAUDE.md.
		return &hostConfig{
			name:                     hostName,
			mcpGlobalConfigPath:      filepath.Join(homeDir, ".claude.json"),
			globalDedicatedRulesPath: filepath.Join(homeDir, ".claude", "rules", "snyk-security.md"),
			legacyGlobalRulesPath:    filepath.Join(homeDir, ".claude", "CLAUDE.md"),
		}, nil
	}
	return nil, fmt.Errorf("unsupported Tool: %s", hostName)
}
