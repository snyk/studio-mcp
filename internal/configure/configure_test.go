package configure

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog"
	"github.com/snyk/studio-mcp/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		name                  string
		hostName              string
		expectError           bool
		expectedName          string
		expectMcpGlobalConfig bool
		expectLocalRulesPath  bool
		expectGlobalRulesPath bool
	}{
		{
			name:                  "cursor",
			hostName:              "cursor",
			expectError:           false,
			expectedName:          "cursor",
			expectMcpGlobalConfig: true,
			expectLocalRulesPath:  true,
		},
		{
			name:                  "windsurf",
			hostName:              "windsurf",
			expectError:           false,
			expectedName:          "windsurf",
			expectMcpGlobalConfig: true,
			expectLocalRulesPath:  true,
		},
		{
			name:                  "antigravity",
			hostName:              "antigravity",
			expectError:           false,
			expectedName:          "antigravity",
			expectMcpGlobalConfig: true,
			expectLocalRulesPath:  true,
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
			name:                 "visual studio code",
			hostName:             "visual studio code",
			expectError:          false,
			expectedName:         "visual studio code",
			expectLocalRulesPath: true,
		},
		{
			name:                 "vs_code",
			hostName:             "vs_code",
			expectError:          false,
			expectedName:         "vs_code",
			expectLocalRulesPath: true,
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

func TestRemoveDelimitedBlock(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected string
	}{
		{
			name:     "removes block from middle",
			source:   "before\n" + RuleStart + "\ncontent\n" + RuleEnd + "\nafter\n",
			expected: "beforeafter\n",
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
