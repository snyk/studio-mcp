package configure

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
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
			expected: "<!--# BEGIN SNYK GLOBAL RULE-->\ntest content\n<!--# END SNYK GLOBAL RULE-->\n",
		},
		{
			name:     "source without markers",
			source:   "existing content\n",
			expected: "existing content\n\n<!--# BEGIN SNYK GLOBAL RULE-->\ntest content\n<!--# END SNYK GLOBAL RULE-->\n",
		},
		{
			name:     "source with markers",
			source:   "before\n<!--# BEGIN SNYK GLOBAL RULE-->\nold content\n<!--# END SNYK GLOBAL RULE-->\nafter\n",
			expected: "before\n<!--# BEGIN SNYK GLOBAL RULE-->\ntest content\n<!--# END SNYK GLOBAL RULE-->\nafter\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := "<!--# BEGIN SNYK GLOBAL RULE-->\ntest content\n<!--# END SNYK GLOBAL RULE-->\n"
			result := upsertDelimitedBlock(tt.source, RuleStart, RuleEnd, block)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetIdeConfig(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name         string
		hostName     string
		expectError  bool
		expectedName string
	}{
		{
			name:         "cursor",
			hostName:     "cursor",
			expectError:  false,
			expectedName: "Cursor",
		},
		{
			name:         "windsurf",
			hostName:     "windsurf",
			expectError:  false,
			expectedName: "Windsurf",
		},
		{
			name:         "antigravity",
			hostName:     "antigravity",
			expectError:  false,
			expectedName: "Antigravity",
		},
		{
			name:         "copilot",
			hostName:     "copilot",
			expectError:  false,
			expectedName: "Copilot",
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

			// Verify paths are properly set
			if tt.hostName != "copilot" {
				assert.NotEmpty(t, config.mcpGlobalConfigPath)
				assert.Contains(t, config.mcpGlobalConfigPath, homeDir)
			}
			assert.NotEmpty(t, config.localRulesPath)
		})
	}
}

func TestEnsureMcpServerInJson(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "mcp.json")

	env := EnvMap{
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
		newEnv := EnvMap{
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
			Env:     EnvMap{"KEY": "value"},
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
		newEnv := EnvMap{"SNYK_CFG_ORG": "updated-org"}
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
		newEnv := EnvMap{"SNYK_CFG_ORG": "updated-org", "SNYK_API": "https://api.snyk.io"}
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
	tempDir := t.TempDir()
	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger
	rulesContent := "# Test Rules\nRule 1\nRule 2"

	t.Run("creates local rules file", func(t *testing.T) {
		relativeRulesPath := filepath.Join(".cursor", "rules", "snyk_rules.mdc")
		err := writeLocalRules(tempDir, relativeRulesPath, rulesContent, logger)
		require.NoError(t, err)

		fullPath := filepath.Join(tempDir, relativeRulesPath)
		assert.FileExists(t, fullPath)

		content, err := os.ReadFile(fullPath)
		require.NoError(t, err)
		assert.Equal(t, rulesContent, string(content))
	})

	t.Run("skips if content unchanged", func(t *testing.T) {
		relativeRulesPath := filepath.Join(".cursor", "rules", "snyk_rules.mdc")
		err := writeLocalRules(tempDir, relativeRulesPath, rulesContent, logger)
		require.NoError(t, err)

		// Should not error - content already exists
		fullPath := filepath.Join(tempDir, relativeRulesPath)
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
		a        EnvMap
		b        EnvMap
		expected bool
	}{
		{
			name:     "equal maps",
			a:        EnvMap{"key1": "val1", "key2": "val2"},
			b:        EnvMap{"key1": "val1", "key2": "val2"},
			expected: true,
		},
		{
			name:     "different values",
			a:        EnvMap{"key1": "val1", "key2": "val2"},
			b:        EnvMap{"key1": "val1", "key2": "different"},
			expected: false,
		},
		{
			name:     "different keys",
			a:        EnvMap{"key1": "val1"},
			b:        EnvMap{"key2": "val1"},
			expected: false,
		},
		{
			name:     "both empty",
			a:        EnvMap{},
			b:        EnvMap{},
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

func TestIsExecutedViaNPMContext(t *testing.T) {
	t.Run("detects npm_execpath", func(t *testing.T) {
		os.Setenv("npm_execpath", "/usr/bin/npm")
		defer os.Unsetenv("npm_execpath")

		result := isExecutedViaNPMContext()
		assert.True(t, result)
	})

	t.Run("detects _npx in path", func(t *testing.T) {
		os.Unsetenv("npm_execpath")
		originalArgs := os.Args
		defer func() { os.Args = originalArgs }()

		os.Args = []string{"/home/user/.npm/_npx/12345/bin/snyk"}
		result := isExecutedViaNPMContext()
		assert.True(t, result)
	})

	t.Run("returns false when not in npm context", func(t *testing.T) {
		os.Unsetenv("npm_execpath")
		originalArgs := os.Args
		defer func() { os.Args = originalArgs }()

		os.Args = []string{"/usr/local/bin/snyk"}
		result := isExecutedViaNPMContext()
		assert.False(t, result)
	})
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
