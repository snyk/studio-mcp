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
	"fmt"
	"os"
	"strings"
)

// Profile represents an MCP tool profile that determines which tools are available
type Profile string

const (
	// ProfileLite includes only essential tools for basic scanning
	ProfileLite Profile = "lite"
	// ProfileFull includes all non-experimental tools (default)
	ProfileFull Profile = "full"
	// ProfileExperimental includes all tools including experimental ones
	ProfileExperimental Profile = "experimental"

	// ProfileEnvVar is the environment variable name for setting the profile
	ProfileEnvVar = "SNYK_MCP_PROFILE"
	// ProfileFlagName is the CLI flag name for setting the profile
	ProfileFlagName = "profile"
)

// DefaultProfile is the profile used when none is specified
var DefaultProfile = ProfileFull

// ValidProfiles contains all valid profile names
var ValidProfiles = []Profile{ProfileLite, ProfileFull, ProfileExperimental}

// ParseProfile validates and returns the profile from a string
func ParseProfile(profileStr string) (Profile, error) {
	normalized := strings.ToLower(strings.TrimSpace(profileStr))
	p := Profile(normalized)
	for _, valid := range ValidProfiles {
		if p == valid {
			return p, nil
		}
	}
	return "", fmt.Errorf("invalid profile %q: must be one of: %s", profileStr, validProfilesString())
}

// validProfilesString returns a comma-separated string of valid profile names
func validProfilesString() string {
	names := make([]string, len(ValidProfiles))
	for i, p := range ValidProfiles {
		names[i] = string(p)
	}
	return strings.Join(names, ", ")
}

// GetProfile determines the active profile from config value and environment variable.
// Priority: configValue (CLI flag) > environment variable > default
func GetProfile(configValue string) (Profile, error) {
	if configValue != "" {
		return ParseProfile(configValue)
	}
	if envValue := os.Getenv(ProfileEnvVar); envValue != "" {
		return ParseProfile(envValue)
	}
	return DefaultProfile, nil
}

// IsToolInProfile determines if a tool should be included based on the active profile.
func IsToolInProfile(toolDef SnykMcpToolsDefinition, profile Profile) bool {
	profiles := toolDef.Profiles
	if profile == "" {
		profile = DefaultProfile
	}
	for _, s := range profiles {
		if strings.EqualFold(s, string(profile)) {
			return true
		}
	}
	return false
}
