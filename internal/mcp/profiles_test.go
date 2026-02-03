/*
 * © 2025 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadToolsForTest parses the embedded snyk_tools.json for testing
func loadToolsForTest() (*SnykMcpTools, error) {
	var config SnykMcpTools
	if err := json.Unmarshal([]byte(snykToolsJson), &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func TestParseProfile(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expected    Profile
		expectError bool
	}{
		{
			name:        "valid lite profile",
			input:       "lite",
			expected:    ProfileLite,
			expectError: false,
		},
		{
			name:        "valid full profile",
			input:       "full",
			expected:    ProfileFull,
			expectError: false,
		},
		{
			name:        "valid experimental profile",
			input:       "experimental",
			expected:    ProfileExperimental,
			expectError: false,
		},
		{
			name:        "uppercase LITE is valid",
			input:       "LITE",
			expected:    ProfileLite,
			expectError: false,
		},
		{
			name:        "mixed case Full is valid",
			input:       "Full",
			expected:    ProfileFull,
			expectError: false,
		},
		{
			name:        "whitespace is trimmed",
			input:       "  full  ",
			expected:    ProfileFull,
			expectError: false,
		},
		{
			name:        "invalid profile returns error",
			input:       "invalid",
			expected:    "",
			expectError: true,
		},
		{
			name:        "empty string returns error",
			input:       "",
			expected:    "",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseProfile(tc.input)

			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid profile")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestGetProfile(t *testing.T) {
	t.Run("CLI flag value takes priority over env var", func(t *testing.T) {
		t.Setenv(ProfileEnvVar, "full")

		result, err := GetProfile("lite")

		require.NoError(t, err)
		assert.Equal(t, ProfileLite, result)
	})

	t.Run("env var is used when config value is empty", func(t *testing.T) {
		t.Setenv(ProfileEnvVar, "experimental")

		result, err := GetProfile("")

		require.NoError(t, err)
		assert.Equal(t, ProfileExperimental, result)
	})

	t.Run("default profile when nothing is set", func(t *testing.T) {
		result, err := GetProfile("")

		require.NoError(t, err)
		assert.Equal(t, DefaultProfile, result)
		assert.Equal(t, ProfileFull, result)
	})

	t.Run("invalid CLI flag returns error", func(t *testing.T) {
		result, err := GetProfile("invalid")

		require.Error(t, err)
		assert.Equal(t, Profile(""), result)
	})

	t.Run("invalid env var returns error", func(t *testing.T) {
		t.Setenv(ProfileEnvVar, "invalid")

		result, err := GetProfile("")

		require.Error(t, err)
		assert.Equal(t, Profile(""), result)
	})
}

func TestIsToolInProfile(t *testing.T) {
	// This test verifies that every tool in snyk_tools.json is correctly
	// included/excluded from each profile based on its profiles configuration.
	//
	// The implementation does exact matching: a tool is included in a profile
	// only if its profiles array contains that profile name.

	// Expected profile membership for each tool based on snyk_tools.json
	toolProfileExpectations := []struct {
		toolName       string
		inLite         bool
		inFull         bool
		inExperimental bool
	}{
		// Tools in all profiles (lite, full, experimental)
		{"snyk_auth", true, true, true},
		{"snyk_sca_scan", true, true, true},
		{"snyk_code_scan", true, true, true},
		{"snyk_version", true, true, true},
		{"snyk_logout", true, true, true},
		{"snyk_trust", true, true, true},
		{"snyk_send_feedback", true, true, true},

		// Tools in full and experimental only
		{"snyk_container_scan", false, true, true},
		{"snyk_iac_scan", false, true, true},
		{"snyk_sbom_scan", false, true, true},
		{"snyk_aibom", false, true, true},

		// Tools in experimental only
		{"snyk_package_health", false, false, true},
	}

	// Load actual tools from JSON
	tools, err := loadToolsForTest()
	require.NoError(t, err, "Failed to load snyk_tools.json")

	// Create a map for quick lookup
	toolMap := make(map[string]SnykMcpToolsDefinition)
	for _, tool := range tools.Tools {
		toolMap[tool.Name] = tool
	}

	// Verify all expected tools exist in the JSON
	for _, expected := range toolProfileExpectations {
		_, exists := toolMap[expected.toolName]
		require.True(t, exists, "Tool %q defined in test expectations but not found in snyk_tools.json", expected.toolName)
	}

	// Verify no tools in JSON are missing from expectations
	expectedToolNames := make(map[string]bool)
	for _, expected := range toolProfileExpectations {
		expectedToolNames[expected.toolName] = true
	}
	for _, tool := range tools.Tools {
		require.True(t, expectedToolNames[tool.Name],
			"Tool %q exists in snyk_tools.json but is not defined in test expectations - please add it", tool.Name)
	}

	// Test each tool against each profile
	for _, expected := range toolProfileExpectations {
		tool := toolMap[expected.toolName]

		t.Run(expected.toolName, func(t *testing.T) {
			assert.Equal(t, expected.inLite, IsToolInProfile(tool, ProfileLite),
				"lite profile mismatch (profiles: %v)", tool.Profiles)
			assert.Equal(t, expected.inFull, IsToolInProfile(tool, ProfileFull),
				"full profile mismatch (profiles: %v)", tool.Profiles)
			assert.Equal(t, expected.inExperimental, IsToolInProfile(tool, ProfileExperimental),
				"experimental profile mismatch (profiles: %v)", tool.Profiles)
		})
	}
}

func TestIsToolInProfile_CaseInsensitive(t *testing.T) {
	// Verify that profile matching is case insensitive
	toolDef := SnykMcpToolsDefinition{
		Name:     "test_tool",
		Profiles: []string{"LITE", "Full", "EXPERIMENTAL"},
	}

	assert.True(t, IsToolInProfile(toolDef, ProfileLite), "Should match LITE case-insensitively")
	assert.True(t, IsToolInProfile(toolDef, ProfileFull), "Should match Full case-insensitively")
	assert.True(t, IsToolInProfile(toolDef, ProfileExperimental), "Should match EXPERIMENTAL case-insensitively")
}

func TestIsToolInProfile_EmptyProfiles(t *testing.T) {
	// A tool with no profiles should not be included in any profile
	toolDef := SnykMcpToolsDefinition{
		Name:     "test_tool",
		Profiles: []string{},
	}

	assert.False(t, IsToolInProfile(toolDef, ProfileLite), "Empty profiles should not match lite")
	assert.False(t, IsToolInProfile(toolDef, ProfileFull), "Empty profiles should not match full")
	assert.False(t, IsToolInProfile(toolDef, ProfileExperimental), "Empty profiles should not match experimental")
}

func TestIsToolInProfile_DefaultProfile(t *testing.T) {
	// When profile is empty string, it should default to DefaultProfile (full)
	toolDef := SnykMcpToolsDefinition{
		Name:     "test_tool",
		Profiles: []string{"full"},
	}

	assert.True(t, IsToolInProfile(toolDef, ""), "Empty profile should default to full")
}
