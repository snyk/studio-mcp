package configure

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/studio-mcp/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopUserInterface satisfies ui.UserInterface for tests; every method
// discards. configure.go only calls Output(), but the interface contract
// requires the rest, so each method returns a benign zero value.
type noopUserInterface struct{}

func (noopUserInterface) Output(string) error                                 { return nil }
func (noopUserInterface) OutputError(error, ...ui.Opts) error                 { return nil }
func (noopUserInterface) NewProgressBar() ui.ProgressBar                      { return nil }
func (noopUserInterface) Input(string) (string, error)                        { return "", nil }
func (noopUserInterface) SelectOptions(string, []string) (int, string, error) { return 0, "", nil }

func TestUpsertDelimitedBlock(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected string
	}{
		{
			name:     "empty source",
			source:   "",
			expected: RuleStart + "\ntest content\n" + RuleEnd + "\n",
		},
		{
			name:     "source without markers",
			source:   "existing content\n",
			expected: "existing content\n\n" + RuleStart + "\ntest content\n" + RuleEnd + "\n",
		},
		{
			name:     "source with markers",
			source:   "before\n" + RuleStart + "\nold content\n" + RuleEnd + "\nafter\n",
			expected: "before\n" + RuleStart + "\ntest content\n" + RuleEnd + "\nafter\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := RuleStart + "\ntest content\n" + RuleEnd + "\n"
			result := upsertDelimitedBlock(tt.source, RuleStart, RuleEnd, block)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetHostConfig(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name                           string
		hostName                       string
		expectError                    bool
		expectedName                   string
		expectMcpGlobalConfig          bool
		expectLocalRulesPath           bool
		expectGlobalRulesPath          bool
		expectGlobalSkillsPath         bool
		expectGlobalDedicatedRulesPath bool
		expectLegacyLocalRulesPath     bool
		expectLegacyGlobalRulesPath    bool
	}{
		{
			name:                   "cursor",
			hostName:               "cursor",
			expectError:            false,
			expectedName:           "cursor",
			expectMcpGlobalConfig:  true,
			expectGlobalSkillsPath: true,
		},
		{
			name:                       "windsurf",
			hostName:                   "windsurf",
			expectError:                false,
			expectedName:               "windsurf",
			expectMcpGlobalConfig:      true,
			expectGlobalRulesPath:      true,
			expectLegacyLocalRulesPath: true,
		},
		{
			name:                       "antigravity",
			hostName:                   "antigravity",
			expectError:                false,
			expectedName:               "antigravity",
			expectMcpGlobalConfig:      true,
			expectGlobalRulesPath:      true,
			expectLegacyLocalRulesPath: true,
		},
		{
			name:                       "visual studio code",
			hostName:                   "visual studio code",
			expectError:                false,
			expectedName:               "visual studio code",
			expectGlobalRulesPath:      true,
			expectLegacyLocalRulesPath: true,
		},
		{
			name:                       "visual studio code - insiders",
			hostName:                   "visual studio code - insiders",
			expectError:                false,
			expectedName:               "visual studio code - insiders",
			expectGlobalRulesPath:      true,
			expectLegacyLocalRulesPath: true,
		},
		{
			name:                  "gemini-cli",
			hostName:              "gemini-cli",
			expectError:           false,
			expectedName:          "gemini-cli",
			expectMcpGlobalConfig: true,
			expectGlobalRulesPath: true,
		},
		{
			name:                           "claude-cli",
			hostName:                       "claude-cli",
			expectError:                    false,
			expectedName:                   "claude-cli",
			expectMcpGlobalConfig:          true,
			expectGlobalDedicatedRulesPath: true,
			expectLegacyGlobalRulesPath:    true,
		},
		{
			name:        "unsupported",
			hostName:    "unsupported",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := getHostConfig(tt.hostName)
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectedName, config.name)

			if tt.expectMcpGlobalConfig {
				assert.NotEmpty(t, config.mcpGlobalConfigPath)
				assert.Contains(t, config.mcpGlobalConfigPath, homeDir)
			}
			if tt.expectLocalRulesPath {
				assert.NotEmpty(t, config.localRulesPath)
			}
			if tt.expectGlobalRulesPath {
				assert.NotEmpty(t, config.globalRulesPath)
				assert.Contains(t, config.globalRulesPath, homeDir)
			}
			if tt.expectGlobalSkillsPath {
				assert.NotEmpty(t, config.globalSkillsPath)
				assert.Contains(t, config.globalSkillsPath, homeDir)
			}
			if tt.expectGlobalDedicatedRulesPath {
				assert.NotEmpty(t, config.globalDedicatedRulesPath)
				assert.Contains(t, config.globalDedicatedRulesPath, homeDir)
			}
			if tt.expectLegacyLocalRulesPath {
				assert.NotEmpty(t, config.legacyLocalRulesPath)
			}
			if tt.expectLegacyGlobalRulesPath {
				assert.NotEmpty(t, config.legacyGlobalRulesPath)
				assert.Contains(t, config.legacyGlobalRulesPath, homeDir)
			}
		})
	}
}

func TestGetHostConfig_ClaudeCliPaths(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	config, err := getHostConfig("claude-cli")
	require.NoError(t, err)

	// MCP server entry continues to live in ~/.claude.json
	assert.Equal(t, filepath.Join(homeDir, ".claude.json"), config.mcpGlobalConfigPath)

	// Rules live in a dedicated, auto-loaded file under ~/.claude/rules/
	// (per https://code.claude.com/docs/en/memory#user-level-rules) — distinct
	// from globalSkillsPath, which is reserved for Cursor's SKILL.md slot.
	assert.Equal(t, filepath.Join(homeDir, ".claude", "rules", "snyk-security.md"), config.globalDedicatedRulesPath)

	// CLAUDE.md is preserved as a legacy path so prior installs get cleaned up.
	assert.Equal(t, filepath.Join(homeDir, ".claude", "CLAUDE.md"), config.legacyGlobalRulesPath)

	// Delimited globalRulesPath is no longer used for claude-cli — the rules
	// file is now Snyk-owned and should be written without delimiters.
	assert.Empty(t, config.globalRulesPath)

	// globalSkillsPath is the Cursor-specific SKILL.md slot; claude-cli must
	// not piggyback on it (we use the dedicated rules path instead).
	assert.Empty(t, config.globalSkillsPath)

	// claude-cli has never used local workspace rules.
	assert.Empty(t, config.localRulesPath)
	assert.Empty(t, config.legacyLocalRulesPath)
}

func TestRemoveGlobalRulesIsClaudeCliMigrationSafe(t *testing.T) {
	// Verifies the migration path: a CLAUDE.md containing both pre-existing user
	// content AND a Snyk delimited block (left by an older install) gets the
	// Snyk block stripped while user content is preserved verbatim. This is the
	// behavior addConfiguration / removeConfiguration rely on for claude-cli.
	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger

	tempDir := t.TempDir()
	claudeMd := filepath.Join(tempDir, "CLAUDE.md")

	userContent := "# My personal preferences\n\n- Use tabs for indentation\n- Prefer Go over Rust\n"
	snykBlock := RuleStart + "\n# Snyk Security At Inception\nDo the snyk thing.\n" + RuleEnd
	combined := userContent + "\n" + snykBlock + "\n"
	require.NoError(t, os.WriteFile(claudeMd, []byte(combined), 0644))

	require.NoError(t, removeGlobalRules(claudeMd, logger))

	result, err := os.ReadFile(claudeMd)
	require.NoError(t, err)
	resultStr := string(result)

	assert.Contains(t, resultStr, "Use tabs for indentation")
	assert.Contains(t, resultStr, "Prefer Go over Rust")
	assert.NotContains(t, resultStr, RuleStart)
	assert.NotContains(t, resultStr, RuleEnd)
	assert.NotContains(t, resultStr, "Snyk Security At Inception")
}

func TestGetHostConfig_VSCodePaths(t *testing.T) {
	configDir, err := os.UserConfigDir()
	require.NoError(t, err)

	tests := []struct {
		name                        string
		hostName                    string
		expectedGlobalRulesDir      string
		expectedGlobalRulesFilename string
		expectedLegacyLocalPath     string
	}{
		{
			name:                        "visual studio code uses Code directory under UserConfigDir",
			hostName:                    "visual studio code",
			expectedGlobalRulesDir:      filepath.Join(configDir, "Code", "User", "prompts"),
			expectedGlobalRulesFilename: "snyk_rules.instructions.md",
			expectedLegacyLocalPath:     filepath.Join(".github", "instructions", "snyk_rules.instructions.md"),
		},
		{
			name:                        "visual studio code insiders uses Code - Insiders directory",
			hostName:                    "visual studio code - insiders",
			expectedGlobalRulesDir:      filepath.Join(configDir, "Code - Insiders", "User", "prompts"),
			expectedGlobalRulesFilename: "snyk_rules.instructions.md",
			expectedLegacyLocalPath:     filepath.Join(".github", "instructions", "snyk_rules.instructions.md"),
		},
		{
			name:                        "vs_code alias uses Code directory",
			hostName:                    "vs_code",
			expectedGlobalRulesDir:      filepath.Join(configDir, "Code", "User", "prompts"),
			expectedGlobalRulesFilename: "snyk_rules.instructions.md",
			expectedLegacyLocalPath:     filepath.Join(".github", "instructions", "snyk_rules.instructions.md"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := getHostConfig(tt.hostName)
			require.NoError(t, err)

			// Verify global rules path is constructed from UserConfigDir
			assert.Equal(t, filepath.Join(tt.expectedGlobalRulesDir, tt.expectedGlobalRulesFilename), config.globalRulesPath)
			assert.Contains(t, config.globalRulesPath, configDir)

			// Verify no local rules path (migrated to global)
			assert.Empty(t, config.localRulesPath)

			// Verify legacy local rules path for cleanup
			assert.Equal(t, tt.expectedLegacyLocalPath, config.legacyLocalRulesPath)

			// Verify no MCP config path (VS Code uses its own extension mechanism)
			assert.Empty(t, config.mcpGlobalConfigPath)

			// Verify no skills path (VS Code uses rules, not skills)
			assert.Empty(t, config.globalSkillsPath)
		})
	}
}

func TestEnsureMcpServerInJson(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "mcp.json")

	env := shared.McpEnvMap{
		"SNYK_CFG_ORG": "test-org",
		"SNYK_API":     "https://api.snyk.io",
	}

	// Create a logger that discards output
	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger

	t.Run("creates new config", func(t *testing.T) {
		err := ensureMcpServerInJson(configPath, "Snyk", "/path/to/cli", []string{"mcp", "-t", "stdio"}, env, logger)
		require.NoError(t, err)

		// Verify file was created
		assert.FileExists(t, configPath)

		// Verify content
		data, err := os.ReadFile(configPath)
		require.NoError(t, err)

		var config McpConfig
		err = json.Unmarshal(data, &config)
		require.NoError(t, err)

		assert.Contains(t, config.McpServers, "Snyk")
		server := config.McpServers["Snyk"]
		assert.Equal(t, "/path/to/cli", server.Command)
		assert.Equal(t, []string{"mcp", "-t", "stdio"}, server.Args)
		assert.Equal(t, "test-org", server.Env["SNYK_CFG_ORG"])
	})

	t.Run("updates existing config", func(t *testing.T) {
		newEnv := shared.McpEnvMap{
			"SNYK_CFG_ORG": "updated-org",
			"SNYK_API":     "https://api.snyk.io",
		}

		err := ensureMcpServerInJson(configPath, "Snyk", "/new/path/to/cli", []string{"mcp", "-t", "stdio"}, newEnv, logger)
		require.NoError(t, err)

		// Verify updated content
		data, err := os.ReadFile(configPath)
		require.NoError(t, err)

		var config McpConfig
		err = json.Unmarshal(data, &config)
		require.NoError(t, err)

		server := config.McpServers["Snyk"]
		assert.Equal(t, "/new/path/to/cli", server.Command)
		assert.Equal(t, "updated-org", server.Env["SNYK_CFG_ORG"])
	})

	t.Run("preserves other servers", func(t *testing.T) {
		// Add another server manually
		data, err := os.ReadFile(configPath)
		require.NoError(t, err)

		var config McpConfig
		err = json.Unmarshal(data, &config)
		require.NoError(t, err)

		config.McpServers["OtherServer"] = McpServer{
			Command: "/other/cli",
			Args:    []string{"arg1"},
			Env:     shared.McpEnvMap{"KEY": "value"},
		}

		data, err = json.MarshalIndent(config, "", "  ")
		require.NoError(t, err)
		err = os.WriteFile(configPath, data, 0644)
		require.NoError(t, err)

		// Update Snyk server
		err = ensureMcpServerInJson(configPath, "Snyk", "/path/to/cli", []string{"mcp", "-t", "stdio"}, env, logger)
		require.NoError(t, err)

		// Verify both servers exist
		data, err = os.ReadFile(configPath)
		require.NoError(t, err)
		err = json.Unmarshal(data, &config)
		require.NoError(t, err)

		assert.Contains(t, config.McpServers, "Snyk")
		assert.Contains(t, config.McpServers, "OtherServer")
		assert.Equal(t, "/other/cli", config.McpServers["OtherServer"].Command)
	})

	t.Run("preserves other root-level JSON fields", func(t *testing.T) {
		// Create a config file with additional root-level fields
		configWithOtherFields := map[string]interface{}{
			"customField": "customValue",
			"settings": map[string]interface{}{
				"enabled": true,
				"timeout": 5000,
			},
			"mcpServers": map[string]interface{}{
				"Snyk": map[string]interface{}{
					"command": "/path/to/cli",
					"args":    []string{"mcp", "-t", "stdio"},
					"env": map[string]interface{}{
						"SNYK_CFG_ORG": "test-org",
					},
				},
			},
		}

		data, err := json.MarshalIndent(configWithOtherFields, "", "  ")
		require.NoError(t, err)
		err = os.WriteFile(configPath, data, 0644)
		require.NoError(t, err)

		// Update Snyk server
		newEnv := shared.McpEnvMap{"SNYK_CFG_ORG": "updated-org"}
		err = ensureMcpServerInJson(configPath, "Snyk", "/updated/path", []string{"mcp", "-t", "stdio"}, newEnv, logger)
		require.NoError(t, err)

		// Read and verify all fields are preserved
		data, err = os.ReadFile(configPath)
		require.NoError(t, err)

		var genericConfig map[string]interface{}
		err = json.Unmarshal(data, &genericConfig)
		require.NoError(t, err)

		// Verify custom fields are preserved
		assert.Equal(t, "customValue", genericConfig["customField"])
		assert.NotNil(t, genericConfig["settings"])
		settings := genericConfig["settings"].(map[string]interface{})
		assert.Equal(t, true, settings["enabled"])
		assert.Equal(t, float64(5000), settings["timeout"])

		// Verify mcpServers was updated correctly
		assert.NotNil(t, genericConfig["mcpServers"])
		mcpServers := genericConfig["mcpServers"].(map[string]interface{})
		assert.Contains(t, mcpServers, "Snyk")

		snykServer := mcpServers["Snyk"].(map[string]interface{})
		assert.Equal(t, "/updated/path", snykServer["command"])
	})

	t.Run("preserves additional server properties", func(t *testing.T) {
		// Create a config with additional properties on the server
		configWithServerProps := map[string]interface{}{
			"mcpServers": map[string]interface{}{
				"Snyk": map[string]interface{}{
					"command": "/path/to/cli",
					"args":    []interface{}{"mcp", "-t", "stdio"},
					"env": map[string]interface{}{
						"SNYK_CFG_ORG": "test-org",
					},
					// Additional properties that should be preserved
					"customProperty": "customValue",
					"metadata": map[string]interface{}{
						"version": "1.0.0",
						"author":  "test",
					},
					"enabled": true,
					"timeout": 5000,
				},
			},
		}

		data, err := json.MarshalIndent(configWithServerProps, "", "  ")
		require.NoError(t, err)
		err = os.WriteFile(configPath, data, 0644)
		require.NoError(t, err)

		// Update only command and env
		newEnv := shared.McpEnvMap{"SNYK_CFG_ORG": "updated-org", "SNYK_API": "https://api.snyk.io"}
		err = ensureMcpServerInJson(configPath, "Snyk", "/updated/cli", []string{"mcp", "-t", "stdio"}, newEnv, logger)
		require.NoError(t, err)

		// Read and verify all server properties are preserved
		data, err = os.ReadFile(configPath)
		require.NoError(t, err)

		var genericConfig map[string]interface{}
		err = json.Unmarshal(data, &genericConfig)
		require.NoError(t, err)

		mcpServers := genericConfig["mcpServers"].(map[string]interface{})
		snykServer := mcpServers["Snyk"].(map[string]interface{})

		// Verify updated fields
		assert.Equal(t, "/updated/cli", snykServer["command"])
		assert.Equal(t, []interface{}{"mcp", "-t", "stdio"}, snykServer["args"])

		serverEnv := snykServer["env"].(map[string]interface{})
		assert.Equal(t, "updated-org", serverEnv["SNYK_CFG_ORG"])
		assert.Equal(t, "https://api.snyk.io", serverEnv["SNYK_API"])

		// Verify preserved custom properties
		assert.Equal(t, "customValue", snykServer["customProperty"])
		assert.Equal(t, true, snykServer["enabled"])
		assert.Equal(t, float64(5000), snykServer["timeout"])

		metadata := snykServer["metadata"].(map[string]interface{})
		assert.Equal(t, "1.0.0", metadata["version"])
		assert.Equal(t, "test", metadata["author"])
	})
}

func TestWriteLocalRules(t *testing.T) {
	tempGitRoot := t.TempDir()
	_, err := git.PlainInit(tempGitRoot, false)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tempGitRoot, ".gitignore"), []byte("Thumbs.db\n.DS_Store\n"), 0644)
	require.NoError(t, err)

	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger
	rulesContent := "# Test Rules\nRule 1\nRule 2"

	t.Run("creates local rules file", func(t *testing.T) {
		relativeRulesPath := filepath.Join(".cursor", "rules", "snyk_rules.mdc")

		// Make sure 'relativeRulesPath' is not in the root .gitignore
		gitIgnorePath := filepath.Join(tempGitRoot, ".gitignore")
		assert.FileExists(t, gitIgnorePath)
		gitIgnoreContent, err := os.ReadFile(gitIgnorePath)
		require.NoError(t, err)
		assert.NotContains(t, string(gitIgnoreContent), relativeRulesPath)

		// Write local rules
		err = writeLocalRules(tempGitRoot, relativeRulesPath, rulesContent, logger)
		require.NoError(t, err)

		err = gitIgnoreLocalRulesFile(tempGitRoot, relativeRulesPath, logger)
		require.NoError(t, err)

		// Verify that local rules were written
		fullPath := filepath.Join(tempGitRoot, relativeRulesPath)
		assert.FileExists(t, fullPath)
		content, err := os.ReadFile(fullPath)
		require.NoError(t, err)
		assert.Equal(t, rulesContent, string(content))

		// Verify that local rules were added to root .gitignore
		gitIgnoreContent, err = os.ReadFile(gitIgnorePath)
		require.NoError(t, err)
		assert.Contains(t, string(gitIgnoreContent), relativeRulesPath)
	})

	t.Run("skips if content unchanged", func(t *testing.T) {
		relativeRulesPath := filepath.Join(".cursor", "rules", "snyk_rules.mdc")
		err := writeLocalRules(tempGitRoot, relativeRulesPath, rulesContent, logger)
		require.NoError(t, err)

		// Should not error - content already exists
		fullPath := filepath.Join(tempGitRoot, relativeRulesPath)
		content, err := os.ReadFile(fullPath)
		require.NoError(t, err)
		assert.Equal(t, rulesContent, string(content))
	})
}

func TestWriteGlobalRules(t *testing.T) {
	tempDir := t.TempDir()
	targetFile := filepath.Join(tempDir, "global_rules.md")
	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger
	rulesContent := "# Global Rules\nRule 1"

	t.Run("creates global rules file with delimiters", func(t *testing.T) {
		err := writeGlobalRules(targetFile, rulesContent, logger)
		require.NoError(t, err)

		assert.FileExists(t, targetFile)

		content, err := os.ReadFile(targetFile)
		require.NoError(t, err)
		contentStr := string(content)

		assert.Contains(t, contentStr, RuleStart)
		assert.Contains(t, contentStr, RuleEnd)
		assert.Contains(t, contentStr, rulesContent)
	})

	t.Run("updates existing global rules", func(t *testing.T) {
		// Write initial content
		initial := "Some existing content\n"
		err := os.WriteFile(targetFile, []byte(initial), 0644)
		require.NoError(t, err)

		err = writeGlobalRules(targetFile, rulesContent, logger)
		require.NoError(t, err)

		content, err := os.ReadFile(targetFile)
		require.NoError(t, err)
		contentStr := string(content)

		assert.Contains(t, contentStr, "Some existing content")
		assert.Contains(t, contentStr, RuleStart)
		assert.Contains(t, contentStr, rulesContent)
	})

	t.Run("replaces existing delimited block", func(t *testing.T) {
		// Write content with existing delimited block
		existing := "Before\n" + RuleStart + "\nOld rules\n" + RuleEnd + "\nAfter\n"
		err := os.WriteFile(targetFile, []byte(existing), 0644)
		require.NoError(t, err)

		newRules := "# New Rules\nUpdated content"
		err = writeGlobalRules(targetFile, newRules, logger)
		require.NoError(t, err)

		content, err := os.ReadFile(targetFile)
		require.NoError(t, err)
		contentStr := string(content)

		assert.Contains(t, contentStr, "Before")
		assert.Contains(t, contentStr, "After")
		assert.Contains(t, contentStr, newRules)
		assert.NotContains(t, contentStr, "Old rules")
	})
}

func TestStringSlicesEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{
			name:     "equal slices",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "b", "c"},
			expected: true,
		},
		{
			name:     "different length",
			a:        []string{"a", "b"},
			b:        []string{"a", "b", "c"},
			expected: false,
		},
		{
			name:     "different content",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "x", "c"},
			expected: false,
		},
		{
			name:     "both empty",
			a:        []string{},
			b:        []string{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stringSlicesEqual(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnvMapsEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        shared.McpEnvMap
		b        shared.McpEnvMap
		expected bool
	}{
		{
			name:     "equal maps",
			a:        shared.McpEnvMap{"key1": "val1", "key2": "val2"},
			b:        shared.McpEnvMap{"key1": "val1", "key2": "val2"},
			expected: true,
		},
		{
			name:     "different values",
			a:        shared.McpEnvMap{"key1": "val1", "key2": "val2"},
			b:        shared.McpEnvMap{"key1": "val1", "key2": "different"},
			expected: false,
		},
		{
			name:     "different keys",
			a:        shared.McpEnvMap{"key1": "val1"},
			b:        shared.McpEnvMap{"key2": "val1"},
			expected: false,
		},
		{
			name:     "both empty",
			a:        shared.McpEnvMap{},
			b:        shared.McpEnvMap{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := envMapsEqual(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTrimFunctions(t *testing.T) {
	t.Run("trimTrailingNewlines", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"text\n", "text"},
			{"text\n\n\n", "text"},
			{"text\r\n", "text"},
			{"text", "text"},
			{"text with spaces   \n", "text with spaces"},
		}

		for _, tt := range tests {
			result := trimTrailingNewlines(tt.input)
			assert.Equal(t, tt.expected, result)
		}
	})

	t.Run("trimLeadingNewlines", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"\ntext", "text"},
			{"\n\n\ntext", "text"},
			{"\r\ntext", "text"},
			{"text", "text"},
		}

		for _, tt := range tests {
			result := trimLeadingNewlines(tt.input)
			assert.Equal(t, tt.expected, result)
		}
	})
}

func TestRemoveMcpServerFromJson(t *testing.T) {
	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger

	t.Run("removes server from config", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "mcp.json")

		// Create a config with Snyk server
		config := map[string]interface{}{
			"mcpServers": map[string]interface{}{
				"Snyk": map[string]interface{}{
					"command": "/path/to/cli",
					"args":    []string{"mcp", "-t", "stdio"},
				},
				"OtherServer": map[string]interface{}{
					"command": "/other/cli",
					"args":    []string{"arg1"},
				},
			},
		}
		data, err := json.MarshalIndent(config, "", "  ")
		require.NoError(t, err)
		err = os.WriteFile(configPath, data, 0644)
		require.NoError(t, err)

		// Remove Snyk server
		err = removeMcpServerFromJson(configPath, "Snyk", logger)
		require.NoError(t, err)

		// Verify Snyk was removed but OtherServer remains
		data, err = os.ReadFile(configPath)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		mcpServers := result["mcpServers"].(map[string]interface{})
		assert.NotContains(t, mcpServers, "Snyk")
		assert.Contains(t, mcpServers, "OtherServer")
	})

	t.Run("preserves other root-level fields", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "mcp.json")

		// Create a config with additional fields
		config := map[string]interface{}{
			"customField": "customValue",
			"settings": map[string]interface{}{
				"enabled": true,
			},
			"mcpServers": map[string]interface{}{
				"Snyk": map[string]interface{}{
					"command": "/path/to/cli",
				},
			},
		}
		data, err := json.MarshalIndent(config, "", "  ")
		require.NoError(t, err)
		err = os.WriteFile(configPath, data, 0644)
		require.NoError(t, err)

		// Remove Snyk server
		err = removeMcpServerFromJson(configPath, "Snyk", logger)
		require.NoError(t, err)

		// Verify other fields are preserved
		data, err = os.ReadFile(configPath)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "customValue", result["customField"])
		assert.NotNil(t, result["settings"])
	})

	t.Run("handles non-existent file gracefully", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "nonexistent.json")

		err := removeMcpServerFromJson(configPath, "Snyk", logger)
		require.NoError(t, err)
	})

	t.Run("handles non-existent server gracefully", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "mcp.json")

		// Create a config without Snyk server
		config := map[string]interface{}{
			"mcpServers": map[string]interface{}{
				"OtherServer": map[string]interface{}{
					"command": "/other/cli",
				},
			},
		}
		data, err := json.MarshalIndent(config, "", "  ")
		require.NoError(t, err)
		err = os.WriteFile(configPath, data, 0644)
		require.NoError(t, err)

		// Try to remove non-existent Snyk server
		err = removeMcpServerFromJson(configPath, "Snyk", logger)
		require.NoError(t, err)

		// Verify OtherServer still exists
		data, err = os.ReadFile(configPath)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		mcpServers := result["mcpServers"].(map[string]interface{})
		assert.Contains(t, mcpServers, "OtherServer")
	})

	t.Run("case-insensitive server key matching", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "mcp.json")

		// Create a config with lowercase "snyk" server
		config := map[string]interface{}{
			"mcpServers": map[string]interface{}{
				"snyk": map[string]interface{}{
					"command": "/path/to/cli",
				},
			},
		}
		data, err := json.MarshalIndent(config, "", "  ")
		require.NoError(t, err)
		err = os.WriteFile(configPath, data, 0644)
		require.NoError(t, err)

		// Remove using "Snyk" (different case)
		err = removeMcpServerFromJson(configPath, "Snyk", logger)
		require.NoError(t, err)

		// Verify server was removed
		data, err = os.ReadFile(configPath)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		mcpServers := result["mcpServers"].(map[string]interface{})
		assert.NotContains(t, mcpServers, "snyk")
		assert.NotContains(t, mcpServers, "Snyk")
	})
}

func TestRemoveLocalRules(t *testing.T) {
	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger

	t.Run("removes existing local rules file", func(t *testing.T) {
		tempDir := t.TempDir()
		relativeRulesPath := filepath.Join(".cursor", "rules", "snyk_rules.mdc")
		fullPath := filepath.Join(tempDir, relativeRulesPath)

		// Create the rules file
		err := os.MkdirAll(filepath.Dir(fullPath), 0755)
		require.NoError(t, err)
		err = os.WriteFile(fullPath, []byte("# Test Rules"), 0644)
		require.NoError(t, err)

		// Verify file exists
		assert.FileExists(t, fullPath)

		// Remove the rules
		err = removeLocalRules(tempDir, relativeRulesPath, logger)
		require.NoError(t, err)

		// Verify file was removed
		_, err = os.Stat(fullPath)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("handles non-existent file gracefully", func(t *testing.T) {
		tempDir := t.TempDir()
		relativeRulesPath := filepath.Join(".cursor", "rules", "snyk_rules.mdc")

		// Try to remove non-existent file
		err := removeLocalRules(tempDir, relativeRulesPath, logger)
		require.NoError(t, err)
	})
}

func TestRemoveGlobalRules(t *testing.T) {
	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger

	t.Run("removes snyk block from file with other content", func(t *testing.T) {
		tempDir := t.TempDir()
		targetFile := filepath.Join(tempDir, "global_rules.md")

		// Create file with Snyk block and other content
		content := "# Other Rules\nSome other content\n\n" + RuleStart + "\n# Snyk Rules\nRule 1\n" + RuleEnd + "\n\n# More content\nMore rules\n"
		err := os.WriteFile(targetFile, []byte(content), 0644)
		require.NoError(t, err)

		// Remove Snyk rules
		err = removeGlobalRules(targetFile, logger)
		require.NoError(t, err)

		// Verify Snyk block was removed but other content remains
		result, err := os.ReadFile(targetFile)
		require.NoError(t, err)
		resultStr := string(result)

		assert.NotContains(t, resultStr, RuleStart)
		assert.NotContains(t, resultStr, RuleEnd)
		assert.NotContains(t, resultStr, "# Snyk Rules")
		assert.Contains(t, resultStr, "# Other Rules")
		assert.Contains(t, resultStr, "# More content")
	})

	t.Run("removes all content when file only has snyk block", func(t *testing.T) {
		tempDir := t.TempDir()
		targetFile := filepath.Join(tempDir, "global_rules.md")

		// Create file with only Snyk block
		content := RuleStart + "\n# Snyk Rules\nRule 1\n" + RuleEnd + "\n"
		err := os.WriteFile(targetFile, []byte(content), 0644)
		require.NoError(t, err)

		// Remove Snyk rules
		err = removeGlobalRules(targetFile, logger)
		require.NoError(t, err)

		// Verify file is either deleted or empty
		data, err := os.ReadFile(targetFile)
		if err == nil {
			// File exists - verify it's empty or only whitespace
			assert.Empty(t, strings.TrimSpace(string(data)))
		} else {
			// File was deleted - that's also acceptable
			assert.True(t, os.IsNotExist(err))
		}
	})

	t.Run("handles non-existent file gracefully", func(t *testing.T) {
		tempDir := t.TempDir()
		targetFile := filepath.Join(tempDir, "nonexistent.md")

		err := removeGlobalRules(targetFile, logger)
		require.NoError(t, err)
	})

	t.Run("handles file without snyk block gracefully", func(t *testing.T) {
		tempDir := t.TempDir()
		targetFile := filepath.Join(tempDir, "global_rules.md")

		// Create file without Snyk block
		content := "# Other Rules\nSome content\n"
		err := os.WriteFile(targetFile, []byte(content), 0644)
		require.NoError(t, err)

		// Try to remove Snyk rules
		err = removeGlobalRules(targetFile, logger)
		require.NoError(t, err)

		// Verify file content unchanged
		result, err := os.ReadFile(targetFile)
		require.NoError(t, err)
		assert.Equal(t, content, string(result))
	})
}

func TestGitIgnoreLocalRulesFile(t *testing.T) {
	nopLogger := zerolog.Nop()
	logger := &nopLogger

	t.Run("adds gitignore entry for file detected by git", func(t *testing.T) {
		tempGitRoot := t.TempDir()
		_, err := git.PlainInit(tempGitRoot, false)
		require.NoError(t, err)

		// Create .gitignore file
		gitIgnorePath := filepath.Join(tempGitRoot, ".gitignore")
		err = os.WriteFile(gitIgnorePath, []byte("# Initial gitignore\n"), 0644)
		require.NoError(t, err)

		// Create a rules file using OS-native path separator (filepath.Join)
		// On Windows this will use backslashes, on Linux forward slashes
		relativeRulesPath := filepath.Join(".cursor", "rules", "snyk_rules.mdc")
		fullPath := filepath.Join(tempGitRoot, relativeRulesPath)
		err = os.MkdirAll(filepath.Dir(fullPath), 0755)
		require.NoError(t, err)
		err = os.WriteFile(fullPath, []byte("# Test Rules"), 0644)
		require.NoError(t, err)

		// Call gitIgnoreLocalRulesFile
		err = gitIgnoreLocalRulesFile(tempGitRoot, relativeRulesPath, logger)
		require.NoError(t, err)

		// Verify gitignore was updated with forward slashes (normalized for gitignore compatibility)
		gitIgnoreContent, err := os.ReadFile(gitIgnorePath)
		require.NoError(t, err)
		assert.Contains(t, string(gitIgnoreContent), ".cursor/rules/snyk_rules.mdc")
		assert.Contains(t, string(gitIgnoreContent), "# Snyk Security Extension - AI Rules (auto-generated)")
		// Gitignore should never contain backslashes
		assert.NotContains(t, string(gitIgnoreContent), "\\")
	})

	t.Run("does not add gitignore entry if file is already ignored", func(t *testing.T) {
		tempGitRoot := t.TempDir()
		_, err := git.PlainInit(tempGitRoot, false)
		require.NoError(t, err)

		// Create .gitignore file that already ignores the rules file (use forward slashes for gitignore)
		gitIgnorePath := filepath.Join(tempGitRoot, ".gitignore")
		err = os.WriteFile(gitIgnorePath, []byte("# Initial gitignore\n.cursor/rules/snyk_rules.mdc\n"), 0644)
		require.NoError(t, err)

		// Create a rules file using OS-native path separator
		relativeRulesPath := filepath.Join(".cursor", "rules", "snyk_rules.mdc")
		fullPath := filepath.Join(tempGitRoot, relativeRulesPath)
		err = os.MkdirAll(filepath.Dir(fullPath), 0755)
		require.NoError(t, err)
		err = os.WriteFile(fullPath, []byte("# Test Rules"), 0644)
		require.NoError(t, err)

		// Call gitIgnoreLocalRulesFile
		err = gitIgnoreLocalRulesFile(tempGitRoot, relativeRulesPath, logger)
		require.NoError(t, err)

		// Verify gitignore was NOT updated (file was already ignored, so not visible to git)
		gitIgnoreContent, err := os.ReadFile(gitIgnorePath)
		require.NoError(t, err)
		// Should not contain the auto-generated comment since file was already ignored
		assert.NotContains(t, string(gitIgnoreContent), "# Snyk Security Extension - AI Rules (auto-generated)")
	})

	t.Run("returns error for non-git directory", func(t *testing.T) {
		tempDir := t.TempDir()
		// Don't initialize git

		relativeRulesPath := filepath.Join(".cursor", "rules", "snyk_rules.mdc")
		err := gitIgnoreLocalRulesFile(tempDir, relativeRulesPath, logger)
		assert.Error(t, err)
	})
}

func TestWriteGlobalSkills(t *testing.T) {
	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger
	skillsContent := "---\nname: snyk-rules\ndescription: Test skill\n---\n\n# Test Skills\nSkill content"

	t.Run("creates skills file without delimiters", func(t *testing.T) {
		tempDir := t.TempDir()
		targetFile := filepath.Join(tempDir, "snyk-rules", "SKILL.md")

		err := writeGlobalSkills(targetFile, skillsContent, logger)
		require.NoError(t, err)

		assert.FileExists(t, targetFile)

		content, err := os.ReadFile(targetFile)
		require.NoError(t, err)
		contentStr := string(content)

		// Verify raw content without delimiters
		assert.Equal(t, skillsContent, contentStr)
		assert.NotContains(t, contentStr, RuleStart)
		assert.NotContains(t, contentStr, RuleEnd)
	})

	t.Run("skips if content unchanged", func(t *testing.T) {
		tempDir := t.TempDir()
		targetFile := filepath.Join(tempDir, "snyk-rules", "SKILL.md")

		// Write initial content
		err := writeGlobalSkills(targetFile, skillsContent, logger)
		require.NoError(t, err)

		// Write same content again - should not error
		err = writeGlobalSkills(targetFile, skillsContent, logger)
		require.NoError(t, err)

		// Verify content unchanged
		content, err := os.ReadFile(targetFile)
		require.NoError(t, err)
		assert.Equal(t, skillsContent, string(content))
	})

	t.Run("overwrites with new content", func(t *testing.T) {
		tempDir := t.TempDir()
		targetFile := filepath.Join(tempDir, "snyk-rules", "SKILL.md")

		// Write initial content
		err := writeGlobalSkills(targetFile, skillsContent, logger)
		require.NoError(t, err)

		// Write new content
		newContent := "---\nname: snyk-rules\ndescription: Updated skill\n---\n\n# Updated Skills"
		err = writeGlobalSkills(targetFile, newContent, logger)
		require.NoError(t, err)

		content, err := os.ReadFile(targetFile)
		require.NoError(t, err)
		assert.Equal(t, newContent, string(content))
	})

	t.Run("creates nested directories", func(t *testing.T) {
		tempDir := t.TempDir()
		targetFile := filepath.Join(tempDir, "deep", "nested", "dir", "SKILL.md")

		err := writeGlobalSkills(targetFile, skillsContent, logger)
		require.NoError(t, err)

		assert.FileExists(t, targetFile)
	})
}

func TestRemoveGlobalSkills(t *testing.T) {
	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger

	t.Run("removes existing skills file", func(t *testing.T) {
		tempDir := t.TempDir()
		targetFile := filepath.Join(tempDir, "SKILL.md")

		// Create the file
		err := os.WriteFile(targetFile, []byte("# Skills"), 0644)
		require.NoError(t, err)
		assert.FileExists(t, targetFile)

		// Remove it
		err = removeGlobalSkills(targetFile, logger)
		require.NoError(t, err)

		// Verify file was removed
		_, err = os.Stat(targetFile)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("handles non-existent file gracefully", func(t *testing.T) {
		tempDir := t.TempDir()
		targetFile := filepath.Join(tempDir, "nonexistent.md")

		err := removeGlobalSkills(targetFile, logger)
		require.NoError(t, err)
	})
}

func TestRemoveDelimitedBlock(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected string
	}{
		{
			name:     "removes block from middle",
			source:   "before\n" + RuleStart + "\ncontent\n" + RuleEnd + "\nafter\n",
			expected: "before\nafter\n",
		},
		{
			name:     "removes block from start",
			source:   RuleStart + "\ncontent\n" + RuleEnd + "\nafter\n",
			expected: "after\n",
		},
		{
			name:     "removes block from end",
			source:   "before\n" + RuleStart + "\ncontent\n" + RuleEnd,
			expected: "before\n",
		},
		{
			name:     "returns unchanged if no block",
			source:   "some content\nmore content\n",
			expected: "some content\nmore content\n",
		},
		{
			name:     "returns unchanged if only start marker",
			source:   "content\n" + RuleStart + "\nmore content\n",
			expected: "content\n" + RuleStart + "\nmore content\n",
		},
		{
			name:     "returns unchanged if only end marker",
			source:   "content\n" + RuleEnd + "\nmore content\n",
			expected: "content\n" + RuleEnd + "\nmore content\n",
		},
		{
			name:     "handles empty source",
			source:   "",
			expected: "",
		},
		{
			name:     "removes entire content when only block exists",
			source:   RuleStart + "\ncontent\n" + RuleEnd + "\n",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeDelimitedBlock(tt.source, RuleStart, RuleEnd)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRemoveDelimitedBlock_LineAnchored_PreservesUserQuotedMarkers is a
// regression for the security finding that prior first-occurrence matching
// could destroy user content. Pre-fix: a CLAUDE.md that quoted the literal
// marker text inline (e.g. in a how-to doc) before the real Snyk block
// would have everything between the user's quote and Snyk's real end
// marker silently deleted. Post-fix (line-anchored matching): the inline
// quote does not match (markers must be on their own line), so user
// content above the real block survives intact.
func TestRemoveDelimitedBlock_LineAnchored_PreservesUserQuotedMarkers(t *testing.T) {
	t.Run("user quotes marker inline in a sentence above real block", func(t *testing.T) {
		userPreamble := "# How Snyk migration works\n\n" +
			"Snyk wraps its rules with `" + RuleStart + "` and `" + RuleEnd + "` markers.\n" +
			"Cleanup of legacy installs strips that delimited block.\n\n"
		realBlock := RuleStart + "\n# Snyk Security At Inception\nReal content.\n" + RuleEnd + "\n"
		userTrailer := "\n# More notes\nAfter the block.\n"

		source := userPreamble + realBlock + userTrailer
		result := removeDelimitedBlock(source, RuleStart, RuleEnd)

		// User prose around the real block survives intact.
		assert.Contains(t, result, "# How Snyk migration works")
		assert.Contains(t, result, "Cleanup of legacy installs strips")
		assert.Contains(t, result, "# More notes")
		assert.Contains(t, result, "After the block.")

		// The quoted marker tokens INSIDE the user's sentence are preserved
		// (they're user-authored prose, not Snyk's actual delimiters).
		assert.Contains(t, result, "Snyk wraps its rules with `"+RuleStart+"`")

		// Real block content is gone.
		assert.NotContains(t, result, "Real content.")
		// AND no orphan Snyk block markers should remain on their own line.
		// (We can't simply NotContains the marker tokens — they survive in
		// the user's quoted prose. Verify line-anchored absence instead.)
		for _, line := range strings.Split(result, "\n") {
			assert.NotEqual(t, RuleStart, line, "no orphan RuleStart line should remain")
			assert.NotEqual(t, RuleEnd, line, "no orphan RuleEnd line should remain")
		}
	})

	t.Run("user has marker on its own line AFTER real block — last-start-with-matching-end picks the real one", func(t *testing.T) {
		realBlock := RuleStart + "\n# Real Snyk\nReal content.\n" + RuleEnd
		// User pasted the start marker on its own line below, e.g. in a code
		// block they were writing. There's no matching end after it, so the
		// real block above is the only complete pair.
		userBelow := "\n\n```\n" + RuleStart + "\n```\n\nMy notes.\n"

		source := realBlock + userBelow
		result := removeDelimitedBlock(source, RuleStart, RuleEnd)

		// Real block stripped.
		assert.NotContains(t, result, "Real content.")
		// Orphan user-pasted marker survives (it's inside a fenced code block).
		assert.Contains(t, result, "```\n"+RuleStart+"\n```")
		assert.Contains(t, result, "My notes.")
	})
}

// TestConfigure_ClaudeCliEndToEnd exercises the full add → remove cycle for
// the claude-cli host. It pins three behaviors that helper-level tests do
// NOT cover: that addConfiguration writes the new dedicated rules file,
// that the new file is removed by removeConfiguration, and that the
// migration cleanup wired into configure.go actually strips the legacy
// delimited block from a pre-existing CLAUDE.md while preserving
// surrounding user content. A future refactor that drops the migration
// call sites would slip past every other test in this package — this is
// the one that catches it.
func TestConfigure_ClaudeCliEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		// os.UserHomeDir() resolves via USERPROFILE on Windows; t.Setenv("HOME",...)
		// would not redirect it. The migration logic is platform-agnostic, so we
		// rely on Linux/macOS for this integration test.
		t.Skip("integration test relies on $HOME-driven UserHomeDir resolution")
	}

	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger
	uiStub := noopUserInterface{}

	// Construct a fresh, isolated HOME for each subtest. addConfiguration and
	// removeConfiguration both call os.UserHomeDir() via getHostConfig, which
	// on Linux/macOS reads $HOME — t.Setenv lets us redirect those reads
	// without touching the developer's actual ~/.claude tree.
	setupTempHome := func(t *testing.T) string {
		t.Helper()
		home := t.TempDir()
		t.Setenv("HOME", home)
		require.NoError(t, os.MkdirAll(filepath.Join(home, ".claude"), 0755))
		return home
	}

	// makeConfig returns a configuration.Configuration populated with the
	// minimum keys Configure() reads. ruleType always-apply is the default
	// payload Snyk ships; configureMcp+configureRules both true exercises
	// the full add path.
	makeConfig := func(removeMode bool) configuration.Configuration {
		c := configuration.New()
		c.Set(shared.ToolNameParam, "claude-cli")
		c.Set(shared.RemoveParam, removeMode)
		c.Set(shared.RuleTypeParam, shared.RuleTypeAlwaysApply)
		c.Set(shared.RulesScopeParam, shared.RulesGlobalScope)
		c.Set(shared.WorkspacePathParam, "")
		c.Set(shared.ConfigureMcpParam, true)
		c.Set(shared.ConfigureRulesParam, true)
		return c
	}

	t.Run("add: writes dedicated rules file and strips legacy CLAUDE.md block", func(t *testing.T) {
		home := setupTempHome(t)

		// Pre-seed CLAUDE.md with the exact shape a prior install would have
		// left behind: user content above and below a delimited Snyk block.
		// Migration must remove ONLY the block.
		userTop := "# My personal preferences\n\n- Always tabs, never spaces\n"
		userBottom := "\n## Personal projects\n\n- Be terse\n"
		legacyBlock := RuleStart + "\n# Snyk Security At Inception\nDo the snyk thing.\n" + RuleEnd
		claudeMd := filepath.Join(home, ".claude", "CLAUDE.md")
		require.NoError(t, os.WriteFile(claudeMd, []byte(userTop+legacyBlock+userBottom), 0644))

		require.NoError(t, Configure(logger, makeConfig(false), uiStub, "/usr/local/bin/snyk"))

		// New dedicated rules file exists with the embedded Claude-Code rules
		// content (no Cursor SKILL frontmatter).
		rulesFile := filepath.Join(home, ".claude", "rules", "snyk-security.md")
		assert.FileExists(t, rulesFile)
		got, err := os.ReadFile(rulesFile)
		require.NoError(t, err)
		assert.Equal(t, snykClaudeRulesAlwaysApply, string(got),
			"new rules file should contain the Claude-Code-shaped content embed")
		assert.NotContains(t, string(got), "name: snyk-rules",
			"Cursor SKILL frontmatter must not appear in the Claude rules file")

		// Legacy block is gone but user content survives.
		md, err := os.ReadFile(claudeMd)
		require.NoError(t, err)
		mds := string(md)
		assert.NotContains(t, mds, RuleStart, "legacy block start marker should be stripped")
		assert.NotContains(t, mds, RuleEnd, "legacy block end marker should be stripped")
		assert.NotContains(t, mds, "Do the snyk thing", "legacy Snyk content body should be stripped")
		assert.Contains(t, mds, "Always tabs, never spaces", "user content above the legacy block must survive")
		assert.Contains(t, mds, "Be terse", "user content below the legacy block must survive")

		// MCP server entry was written to ~/.claude.json.
		claudeJSON := filepath.Join(home, ".claude.json")
		assert.FileExists(t, claudeJSON)
		jsonBytes, err := os.ReadFile(claudeJSON)
		require.NoError(t, err)
		var parsed McpConfig
		require.NoError(t, json.Unmarshal(jsonBytes, &parsed))
		assert.Contains(t, parsed.McpServers, shared.ServerNameKey,
			"~/.claude.json should contain the Snyk MCP server entry")
	})

	t.Run("remove: deletes dedicated rules file and strips legacy CLAUDE.md block", func(t *testing.T) {
		home := setupTempHome(t)

		// Pre-create both the new rules file (as if a prior add had run) AND a
		// CLAUDE.md still carrying the legacy block. removeConfiguration must
		// take care of both.
		rulesFile := filepath.Join(home, ".claude", "rules", "snyk-security.md")
		require.NoError(t, os.MkdirAll(filepath.Dir(rulesFile), 0755))
		require.NoError(t, os.WriteFile(rulesFile, []byte(snykClaudeRulesAlwaysApply), 0644))

		userContent := "# Personal\n\n- A\n- B\n"
		legacyBlock := RuleStart + "\n# Old Snyk\nOld.\n" + RuleEnd + "\n"
		claudeMd := filepath.Join(home, ".claude", "CLAUDE.md")
		require.NoError(t, os.WriteFile(claudeMd, []byte(userContent+legacyBlock), 0644))

		// Pre-seed an MCP server entry so removeConfiguration has something to
		// strip.
		claudeJSON := filepath.Join(home, ".claude.json")
		seed := []byte(`{"mcpServers":{"Snyk":{"command":"/x","args":["mcp","-t","stdio"],"env":{}}}}`)
		require.NoError(t, os.WriteFile(claudeJSON, seed, 0644))

		require.NoError(t, Configure(logger, makeConfig(true), uiStub, "/usr/local/bin/snyk"))

		// Dedicated rules file is gone.
		_, statErr := os.Stat(rulesFile)
		assert.True(t, os.IsNotExist(statErr), "dedicated rules file should be removed")

		// Legacy block stripped, user content preserved.
		md, err := os.ReadFile(claudeMd)
		require.NoError(t, err)
		assert.NotContains(t, string(md), RuleStart)
		assert.NotContains(t, string(md), "Old Snyk")
		assert.Contains(t, string(md), "# Personal")

		// MCP entry removed from ~/.claude.json.
		jsonBytes, err := os.ReadFile(claudeJSON)
		require.NoError(t, err)
		var parsed McpConfig
		require.NoError(t, json.Unmarshal(jsonBytes, &parsed))
		assert.NotContains(t, parsed.McpServers, shared.ServerNameKey)
	})

	t.Run("MCP-only configure (configureRules=false) still runs legacy cleanup", func(t *testing.T) {
		// Pins F12: migration housekeeping must run regardless of whether the
		// user is configuring rules this invocation. A user running
		// `--configure-rules=false --configure-mcp=true` who previously
		// installed the delimited variant should still get their CLAUDE.md
		// cleaned up.
		home := setupTempHome(t)

		userContent := "# Personal\n"
		legacyBlock := RuleStart + "\n# stale snyk\n" + RuleEnd + "\n"
		claudeMd := filepath.Join(home, ".claude", "CLAUDE.md")
		require.NoError(t, os.WriteFile(claudeMd, []byte(userContent+legacyBlock), 0644))

		c := configuration.New()
		c.Set(shared.ToolNameParam, "claude-cli")
		c.Set(shared.RemoveParam, false)
		c.Set(shared.RuleTypeParam, shared.RuleTypeAlwaysApply)
		c.Set(shared.RulesScopeParam, shared.RulesGlobalScope)
		c.Set(shared.WorkspacePathParam, "")
		c.Set(shared.ConfigureMcpParam, true)
		c.Set(shared.ConfigureRulesParam, false) // <- the gate the legacy cleanup must NOT respect
		require.NoError(t, Configure(logger, c, uiStub, "/usr/local/bin/snyk"))

		// Dedicated rules file should NOT have been written (configureRules=false).
		_, statErr := os.Stat(filepath.Join(home, ".claude", "rules", "snyk-security.md"))
		assert.True(t, os.IsNotExist(statErr), "rules file must not be written when configureRules=false")

		// But the legacy block in CLAUDE.md MUST still be cleaned up.
		md, err := os.ReadFile(claudeMd)
		require.NoError(t, err)
		assert.NotContains(t, string(md), RuleStart, "legacy cleanup must run even when configureRules=false")
		assert.NotContains(t, string(md), "stale snyk")
		assert.Contains(t, string(md), "# Personal")
	})
}
