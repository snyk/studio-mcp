package configure

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/studio-mcp/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigure(t *testing.T) {
	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger

	// Snyk entry as the IDE CLI wrote it: a "/snyk-" binary running "mcp -t stdio".
	snykMcpConfig := `{"mcpServers":{"Snyk":{"command":"/data/snyk/vscode-cli/snyk-macos-arm64","args":["mcp","-t","stdio"]},"Other":{"command":"other"}}}`
	rulesContent := "# My rules\n\n" + RuleStart + "\n# Snyk Rules\n" + RuleEnd + "\n"

	newUi := func(t *testing.T) *mocks.MockUserInterface {
		t.Helper()
		userInterface := mocks.NewMockUserInterface(gomock.NewController(t))
		userInterface.EXPECT().Output(gomock.Any()).AnyTimes()
		return userInterface
	}

	// setUpWindsurf points the home directory at a temp dir and writes the
	// artifacts an older IDE extension left for Windsurf.
	setUpWindsurf := func(t *testing.T) (mcpPath, globalRulesPath, workspace, legacyRulesPath string) {
		t.Helper()
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		windsurfDir := filepath.Join(home, ".codeium", "windsurf")
		mcpPath = filepath.Join(windsurfDir, "mcp_config.json")
		globalRulesPath = filepath.Join(windsurfDir, "memories", "global_rules.md")
		workspace = t.TempDir()
		legacyRulesPath = filepath.Join(workspace, ".windsurf", "rules", "snyk_rules.md")

		for path, content := range map[string]string{
			mcpPath:         snykMcpConfig,
			globalRulesPath: rulesContent,
			legacyRulesPath: "# Snyk Rules",
		} {
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
			require.NoError(t, os.WriteFile(path, []byte(content), 0644))
		}
		return mcpPath, globalRulesPath, workspace, legacyRulesPath
	}

	readMcpServers := func(t *testing.T, path string) map[string]interface{} {
		t.Helper()
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		var config map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &config))
		servers, ok := config["mcpServers"].(map[string]interface{})
		require.True(t, ok)
		return servers
	}

	t.Run("rejects calls without --rm and writes nothing", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		config := configuration.NewWithOpts()
		config.Set(shared.ToolNameParam, "cursor")
		config.Set(shared.ConfigureMcpParam, true)
		config.Set(shared.ConfigureRulesParam, true)

		err := Configure(logger, config, newUi(t))

		assert.ErrorIs(t, err, ErrConfigureRemoved)
		entries, err := os.ReadDir(home)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("removes the Cursor skill and workspace rules as snyk-ls calls it", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		mcpPath := filepath.Join(home, ".cursor", "mcp.json")
		skillPath := filepath.Join(home, ".cursor", "skills", "snyk-rules", "SKILL.md")
		workspace := t.TempDir()
		legacyRulesPath := filepath.Join(workspace, ".cursor", "rules", "snyk_rules.mdc")
		for path, content := range map[string]string{
			mcpPath:         snykMcpConfig,
			skillPath:       "# Snyk Rules",
			legacyRulesPath: "# Snyk Rules",
		} {
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
			require.NoError(t, os.WriteFile(path, []byte(content), 0644))
		}

		// snyk-ls's removal call: the editor's name as the tool, once per trusted folder.
		config := configuration.NewWithOpts()
		config.Set(shared.ToolNameParam, "Cursor")
		config.Set(shared.RemoveParam, true)
		config.Set(shared.RulesScopeParam, shared.RulesGlobalScope)
		config.Set(shared.WorkspacePathParam, workspace)
		config.Set(shared.ConfigureMcpParam, false)
		config.Set(shared.ConfigureRulesParam, true)

		err := Configure(logger, config, newUi(t))
		require.NoError(t, err)

		assert.NoFileExists(t, skillPath)
		assert.NoFileExists(t, legacyRulesPath)
		assert.Contains(t, readMcpServers(t, mcpPath), shared.ServerNameKey)
	})

	t.Run("removes rules and keeps MCP when configure-mcp is false", func(t *testing.T) {
		mcpPath, globalRulesPath, workspace, legacyRulesPath := setUpWindsurf(t)

		config := configuration.NewWithOpts()
		config.Set(shared.ToolNameParam, "windsurf")
		config.Set(shared.RemoveParam, true)
		config.Set(shared.RulesScopeParam, shared.RulesGlobalScope)
		config.Set(shared.WorkspacePathParam, workspace)
		config.Set(shared.ConfigureMcpParam, false)
		config.Set(shared.ConfigureRulesParam, true)

		err := Configure(logger, config, newUi(t))
		require.NoError(t, err)

		rules, err := os.ReadFile(globalRulesPath)
		require.NoError(t, err)
		assert.Equal(t, "# My rules\n", string(rules))
		assert.NoFileExists(t, legacyRulesPath)
		assert.Contains(t, readMcpServers(t, mcpPath), shared.ServerNameKey)
	})

	t.Run("removes MCP and keeps rules when configure-rules is false", func(t *testing.T) {
		mcpPath, globalRulesPath, workspace, legacyRulesPath := setUpWindsurf(t)

		config := configuration.NewWithOpts()
		config.Set(shared.ToolNameParam, "windsurf")
		config.Set(shared.RemoveParam, true)
		config.Set(shared.RulesScopeParam, shared.RulesGlobalScope)
		config.Set(shared.WorkspacePathParam, workspace)
		config.Set(shared.ConfigureMcpParam, true)
		config.Set(shared.ConfigureRulesParam, false)

		err := Configure(logger, config, newUi(t))
		require.NoError(t, err)

		servers := readMcpServers(t, mcpPath)
		assert.NotContains(t, servers, shared.ServerNameKey)
		assert.Contains(t, servers, "Other")
		rules, err := os.ReadFile(globalRulesPath)
		require.NoError(t, err)
		assert.Equal(t, rulesContent, string(rules))
		assert.FileExists(t, legacyRulesPath)
	})

	t.Run("returns an error for an unsupported tool", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(shared.ToolNameParam, "unsupported")
		config.Set(shared.RemoveParam, true)

		err := Configure(logger, config, newUi(t))

		assert.ErrorContains(t, err, "unsupported Tool")
	})
}

func TestGetHostConfig(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name                       string
		hostName                   string
		expectError                bool
		expectedName               string
		expectMcpGlobalConfig      bool
		expectGlobalRulesPath      bool
		expectGlobalSkillsPath     bool
		expectLegacyLocalRulesPath bool
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
			name:                  "claude-cli",
			hostName:              "claude-cli",
			expectError:           false,
			expectedName:          "claude-cli",
			expectMcpGlobalConfig: true,
			expectGlobalRulesPath: true,
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
			if tt.expectGlobalRulesPath {
				assert.NotEmpty(t, config.globalRulesPath)
				assert.Contains(t, config.globalRulesPath, homeDir)
			}
			if tt.expectGlobalSkillsPath {
				assert.NotEmpty(t, config.globalSkillsPath)
				assert.Contains(t, config.globalSkillsPath, homeDir)
			}
			if tt.expectLegacyLocalRulesPath {
				assert.NotEmpty(t, config.legacyLocalRulesPath)
			}
		})
	}
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

			// Verify legacy local rules path for cleanup
			assert.Equal(t, tt.expectedLegacyLocalPath, config.legacyLocalRulesPath)

			// Verify no MCP config path (VS Code uses its own extension mechanism)
			assert.Empty(t, config.mcpGlobalConfigPath)

			// Verify no skills path (VS Code uses rules, not skills)
			assert.Empty(t, config.globalSkillsPath)
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

	t.Run("removes server by matching command and args", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "mcp.json")

		snykCommand := "/usr/local/bin/snyk-macos-arm64"
		config := map[string]interface{}{
			"mcpServers": map[string]interface{}{
				"Snyk": map[string]interface{}{
					"command": snykCommand,
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

		// Remove Snyk server by its command/args signature
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

	t.Run("does not remove when multiple SAI servers exist", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "mcp.json")

		config := map[string]interface{}{
			"mcpServers": map[string]interface{}{
				"Snyk1": map[string]interface{}{
					"command": "/Users/test1/Library/Application Support/snyk/vscode-cli/snyk-macos-arm64",
					"args":    []string{"mcp", "-t", "stdio"},
				},
				"Snyk2": map[string]interface{}{
					"command": "/usr/local/bin/snyk-linux-x64",
					"args":    []string{"mcp", "-t", "stdio"},
				},
			},
		}
		data, err := json.MarshalIndent(config, "", "  ")
		require.NoError(t, err)
		err = os.WriteFile(configPath, data, 0644)
		require.NoError(t, err)

		// Try to remove - should not remove anything since multiple SAI servers exist
		err = removeMcpServerFromJson(configPath, "Snyk", logger)
		require.NoError(t, err)

		// Verify both servers still exist
		data, err = os.ReadFile(configPath)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		mcpServers := result["mcpServers"].(map[string]interface{})
		assert.Contains(t, mcpServers, "Snyk1")
		assert.Contains(t, mcpServers, "Snyk2")
	})

	t.Run("preserves other root-level fields", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "mcp.json")

		config := map[string]interface{}{
			"customField": "customValue",
			"settings": map[string]interface{}{
				"enabled": true,
			},
			"mcpServers": map[string]interface{}{
				"Snyk": map[string]interface{}{
					"command": "/usr/local/bin/snyk-windows-x64",
					"args":    []string{"mcp", "-t", "stdio"},
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

	t.Run("identifies SAI server regardless of key case", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "mcp.json")

		snykCommand := "/usr/local/bin/snyk-macos-arm64"
		config := map[string]interface{}{
			"mcpServers": map[string]interface{}{
				"snyk": map[string]interface{}{
					"command": snykCommand,
					"args":    []string{"mcp", "-t", "stdio"},
				},
			},
		}
		data, err := json.MarshalIndent(config, "", "  ")
		require.NoError(t, err)
		err = os.WriteFile(configPath, data, 0644)
		require.NoError(t, err)

		// Remove using "Snyk" (different case) - should find and remove the lowercase "snyk" key
		err = removeMcpServerFromJson(configPath, "Snyk", logger)
		require.NoError(t, err)

		// Verify server was removed
		data, err = os.ReadFile(configPath)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		mcpServers := result["mcpServers"].(map[string]interface{})
		assert.Empty(t, mcpServers, "snyk server should be removed regardless of case")
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
