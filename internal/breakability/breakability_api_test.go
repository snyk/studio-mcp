/*
 * © 2025 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package breakability

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	breakabilityapi "github.com/snyk/studio-mcp/internal/apiclients/breakability/2024-10-15"
)

func TestBuildBreakabilityResponse(t *testing.T) {
	const (
		highInstructions   = "IMPORTANT: Breaking change detected. If Snyk reported another upgrade path that is non-breaking use it. Otherwise, inform the user of the breaking change first."
		mediumInstructions = "Check the assessment and determine if the change is breaking or not. If it is breaking, inform the user of the breaking change first. Otherwise, proceed with the upgrade."
		lowInstructions    = "Non-breaking change, proceed with the upgrade."
	)

	testCases := []struct {
		name                 string
		attrs                *breakabilityapi.BreakabilityResponseAttributes
		expectedRiskLevel    string
		expectedAssessment   string
		expectedInstructions string
	}{
		{
			name: "high risk returns breaking change instructions",
			attrs: &breakabilityapi.BreakabilityResponseAttributes{
				RiskLevel: breakabilityapi.High,
				Summary:   "API removed in this major version",
			},
			expectedRiskLevel:    "high",
			expectedAssessment:   "API removed in this major version",
			expectedInstructions: highInstructions,
		},
		{
			name: "medium risk returns ambiguous instructions",
			attrs: &breakabilityapi.BreakabilityResponseAttributes{
				RiskLevel: breakabilityapi.Medium,
				Summary:   "Some method signatures changed",
			},
			expectedRiskLevel:    "medium",
			expectedAssessment:   "Some method signatures changed",
			expectedInstructions: mediumInstructions,
		},
		{
			name: "low risk returns proceed instructions",
			attrs: &breakabilityapi.BreakabilityResponseAttributes{
				RiskLevel: breakabilityapi.Low,
				Summary:   "Patch version bump only",
			},
			expectedRiskLevel:    "low",
			expectedAssessment:   "Patch version bump only",
			expectedInstructions: lowInstructions,
		},
		{
			name: "empty summary is preserved",
			attrs: &breakabilityapi.BreakabilityResponseAttributes{
				RiskLevel: breakabilityapi.Low,
				Summary:   "",
			},
			expectedRiskLevel:    "low",
			expectedAssessment:   "",
			expectedInstructions: lowInstructions,
		},
		{
			name: "unknown risk level falls through to non-breaking instructions",
			attrs: &breakabilityapi.BreakabilityResponseAttributes{
				RiskLevel: breakabilityapi.BreakabilityResponseAttributesRiskLevel("unknown"),
				Summary:   "n/a",
			},
			expectedRiskLevel:    "unknown",
			expectedAssessment:   "n/a",
			expectedInstructions: lowInstructions,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := BuildBreakabilityResponse(tc.attrs)

			require.NotNil(t, result)
			assert.Equal(t, tc.expectedRiskLevel, result.RiskLevel)
			assert.Equal(t, tc.expectedAssessment, result.Assessment)
			assert.Equal(t, tc.expectedInstructions, result.Instructions)
			assert.Empty(t, result.PublicId, "PublicId should not be populated by BuildBreakabilityResponse")
		})
	}
}

func TestToAPIUpgrades(t *testing.T) {
	testCases := []struct {
		name     string
		input    []PackageUpgrade
		expected []breakabilityapi.Upgrade
	}{
		{
			name:     "nil input produces empty slice",
			input:    nil,
			expected: []breakabilityapi.Upgrade{},
		},
		{
			name:     "empty input produces empty slice",
			input:    []PackageUpgrade{},
			expected: []breakabilityapi.Upgrade{},
		},
		{
			name: "single upgrade is converted with all fields preserved",
			input: []PackageUpgrade{
				{Name: "lodash", FromVersion: "4.17.10", ToVersion: "4.17.21"},
			},
			expected: []breakabilityapi.Upgrade{
				{Name: "lodash", FromVersion: "4.17.10", ToVersion: "4.17.21"},
			},
		},
		{
			name: "multiple upgrades preserve order and fields",
			input: []PackageUpgrade{
				{Name: "express", FromVersion: "4.0.0", ToVersion: "5.0.0"},
				{Name: "@types/node", FromVersion: "18.0.0", ToVersion: "20.0.0"},
			},
			expected: []breakabilityapi.Upgrade{
				{Name: "express", FromVersion: "4.0.0", ToVersion: "5.0.0"},
				{Name: "@types/node", FromVersion: "18.0.0", ToVersion: "20.0.0"},
			},
		},
		{
			name: "upgrade with empty fields is preserved as-is",
			input: []PackageUpgrade{
				{Name: "", FromVersion: "", ToVersion: ""},
			},
			expected: []breakabilityapi.Upgrade{
				{Name: "", FromVersion: "", ToVersion: ""},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ToAPIUpgrades(tc.input)
			assert.Equal(t, tc.expected, result)
			assert.Equal(t, len(tc.expected), len(result))
		})
	}
}
