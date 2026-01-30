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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	testCases := []struct {
		name     string
		profiles []string
		profile  Profile
		expected bool
	}{
		// Lite profile tests
		{
			name:     "tool with lite profile is included in lite",
			profiles: []string{"lite"},
			profile:  ProfileLite,
			expected: true,
		},
		{
			name:     "tool with no profiles is not included in lite",
			profiles: []string{},
			profile:  ProfileLite,
			expected: false,
		},
		{
			name:     "tool with experimental profile is not included in lite",
			profiles: []string{"experimental"},
			profile:  ProfileLite,
			expected: false,
		},

		// Full profile tests
		{
			name:     "tool with lite profile is included in full",
			profiles: []string{"lite"},
			profile:  ProfileFull,
			expected: true,
		},
		{
			name:     "tool with no profiles is included in full",
			profiles: []string{},
			profile:  ProfileFull,
			expected: true,
		},
		{
			name:     "tool with only experimental profile is not included in full",
			profiles: []string{"experimental"},
			profile:  ProfileFull,
			expected: false,
		},
		{
			name:     "tool with lite and experimental profiles are not included in full",
			profiles: []string{"lite", "experimental"},
			profile:  ProfileFull,
			expected: false,
		},
		// Experimental profile tests
		{
			name:     "tool with lite profile is included in experimental",
			profiles: []string{"lite"},
			profile:  ProfileExperimental,
			expected: true,
		},
		{
			name:     "tool with no profiles is included in experimental",
			profiles: []string{},
			profile:  ProfileExperimental,
			expected: true,
		},
		{
			name:     "tool with experimental profile is included in experimental",
			profiles: []string{"experimental"},
			profile:  ProfileExperimental,
			expected: true,
		},
		// Case insensitivity tests
		{
			name:     "profile matching is case insensitive",
			profiles: []string{"LITE"},
			profile:  ProfileLite,
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			toolDef := SnykMcpToolsDefinition{
				Name:     "test_tool",
				Profiles: tc.profiles,
			}

			result := IsToolInProfile(toolDef, tc.profile)

			assert.Equal(t, tc.expected, result)
		})
	}
}
