/*
 * © 2026 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package breakability

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	breakabilityapi "github.com/snyk/studio-mcp/internal/apiclients/breakability/2025-11-05"
)

func TestBuildBreakabilityResponse(t *testing.T) {
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
			expectedInstructions: HighRiskInstruction,
		},
		{
			name: "medium risk returns ambiguous instructions",
			attrs: &breakabilityapi.BreakabilityResponseAttributes{
				RiskLevel: breakabilityapi.Medium,
				Summary:   "Some method signatures changed",
			},
			expectedRiskLevel:    "medium",
			expectedAssessment:   "Some method signatures changed",
			expectedInstructions: MediumRiskInstruction,
		},
		{
			name: "low risk returns proceed instructions",
			attrs: &breakabilityapi.BreakabilityResponseAttributes{
				RiskLevel: breakabilityapi.Low,
				Summary:   "Patch version bump only",
			},
			expectedRiskLevel:    "low",
			expectedAssessment:   "Patch version bump only",
			expectedInstructions: LowRiskInstruction,
		},
		{
			name: "empty summary is preserved",
			attrs: &breakabilityapi.BreakabilityResponseAttributes{
				RiskLevel: breakabilityapi.Low,
				Summary:   "",
			},
			expectedRiskLevel:    "low",
			expectedAssessment:   "",
			expectedInstructions: LowRiskInstruction,
		},
		{
			name: "unknown risk level falls through to non-breaking instructions",
			attrs: &breakabilityapi.BreakabilityResponseAttributes{
				RiskLevel: breakabilityapi.BreakabilityResponseAttributesRiskLevel("unknown"),
				Summary:   "n/a",
			},
			expectedRiskLevel:    "unknown",
			expectedAssessment:   "n/a",
			expectedInstructions: "",
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

func TestSelectAssessment(t *testing.T) {
	upgrade := PackageUpgrade{Name: "lodash", FromVersion: "4.17.10", ToVersion: "4.17.21"}

	parseBody := func(jsonBody string) *breakabilityapi.BreakabilityAssessmentsResponseBody {
		var body breakabilityapi.BreakabilityAssessmentsResponseBody
		require.NoError(t, json.Unmarshal([]byte(jsonBody), &body))
		return &body
	}

	t.Run("nil body returns nil", func(t *testing.T) {
		assert.Nil(t, SelectAssessment(nil, upgrade))
	})

	t.Run("empty data returns nil", func(t *testing.T) {
		assert.Nil(t, SelectAssessment(parseBody(`{"data":[]}`), upgrade))
	})

	t.Run("matching upgrade is returned", func(t *testing.T) {
		body := parseBody(`{
			"data":[{
				"id":"33333333-3333-3333-3333-333333333333",
				"type":"breakability",
				"attributes":{
					"package_upgrade":{"name":"lodash","from_version":"4.17.10","to_version":"4.17.21"},
					"risk_level":"low",
					"summary":"Patch only"
				}
			}]
		}`)
		result := SelectAssessment(body, upgrade)
		require.NotNil(t, result)
		assert.Equal(t, "Patch only", result.Summary)
	})

	t.Run("non-matching upgrade returns nil", func(t *testing.T) {
		body := parseBody(`{
			"data":[{
				"id":"33333333-3333-3333-3333-333333333333",
				"type":"breakability",
				"attributes":{
					"package_upgrade":{"name":"express","from_version":"4.0.0","to_version":"5.0.0"},
					"risk_level":"high",
					"summary":"Breaking"
				}
			}]
		}`)
		assert.Nil(t, SelectAssessment(body, upgrade))
	})
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
