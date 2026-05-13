package oss

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/studio-mcp/internal/types"
)

func TestStripVersion(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain name with version",
			input:    "lodash@4.17.10",
			expected: "lodash",
		},
		{
			name:     "scoped npm package with version",
			input:    "@types/node@18.0.0",
			expected: "@types/node",
		},
		{
			name:     "scoped npm package without version",
			input:    "@types/node",
			expected: "@types/node",
		},
		{
			name:     "name without version",
			input:    "lodash",
			expected: "lodash",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, stripVersion(tc.input))
		})
	}
}

func TestIsTransitiveDependency(t *testing.T) {
	testCases := []struct {
		name     string
		issue    ossIssue
		expected *bool
	}{
		{
			name: "direct dependency",
			issue: ossIssue{
				PackageName: "lodash",
				From:        []string{"app@1.0.0", "lodash@4.17.10"},
			},
			expected: boolPtr(false),
		},
		{
			name: "transitive dependency",
			issue: ossIssue{
				PackageName: "lodash",
				From:        []string{"app@1.0.0", "express@4.0.0", "lodash@4.17.10"},
			},
			expected: boolPtr(true),
		},
		{
			name: "deep transitive dependency",
			issue: ossIssue{
				PackageName: "minimist",
				From:        []string{"app@1.0.0", "a@1.0.0", "b@1.0.0", "c@1.0.0", "minimist@1.2.0"},
			},
			expected: boolPtr(true),
		},
		{
			name: "scoped npm package as direct dependency",
			issue: ossIssue{
				PackageName: "@types/node",
				From:        []string{"app@1.0.0", "@types/node@18.0.0"},
			},
			expected: boolPtr(false),
		},
		{
			name: "scoped npm package as transitive",
			issue: ossIssue{
				PackageName: "@types/node",
				From:        []string{"app@1.0.0", "ts-toolbox@2.0.0", "@types/node@18.0.0"},
			},
			expected: boolPtr(true),
		},
		{
			name: "empty From",
			issue: ossIssue{
				PackageName: "lodash",
				From:        []string{},
			},
			expected: nil,
		},
		{
			name: "single-element From",
			issue: ossIssue{
				PackageName: "lodash",
				From:        []string{"app@1.0.0"},
			},
			expected: nil,
		},
		{
			name: "From[1] does not match PackageName",
			issue: ossIssue{
				PackageName: "lodash",
				From:        []string{"app@1.0.0", "express@4.0.0"},
			},
			expected: boolPtr(true),
		},
		{
			name: "From[1] without version still matches PackageName",
			issue: ossIssue{
				PackageName: "lodash",
				From:        []string{"app", "lodash"},
			},
			expected: boolPtr(false),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := isTransitiveDependency(tc.issue)
			if tc.expected == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tc.expected, *got)
		})
	}
}

func TestToIssue_SetsIsTransitiveDependency(t *testing.T) {
	testCases := []struct {
		name                      string
		issue                     ossIssue
		expected                  bool
		expectedIntroducedThrough []string
	}{
		{
			name: "direct dependency populates pointer to false",
			issue: ossIssue{
				Id:          "SNYK-JS-LODASH-1",
				Title:       "Prototype Pollution",
				Severity:    "high",
				PackageName: "lodash",
				Version:     "4.17.10",
				From:        []string{"app@1.0.0", "lodash@4.17.10"},
			},
			expected:                  false,
			expectedIntroducedThrough: nil,
		},
		{
			name: "transitive dependency populates pointer to true",
			issue: ossIssue{
				Id:          "SNYK-JS-LODASH-1",
				Title:       "Prototype Pollution",
				Severity:    "high",
				PackageName: "lodash",
				Version:     "4.17.10",
				From:        []string{"app@1.0.0", "express@4.0.0", "lodash@4.17.10"},
			},
			expected: true,
			expectedIntroducedThrough: []string{
				"express@4.0.0", "lodash@4.17.10",
			},
		},
		{
			name: "deep transitive chain in introducedThrough",
			issue: ossIssue{
				Id:          "SNYK-JS-MINIMIST-1",
				Title:       "Prototype Pollution",
				Severity:    "high",
				PackageName: "minimist",
				Version:     "1.2.0",
				From:        []string{"app@1.0.0", "a@1.0.0", "b@1.0.0", "c@1.0.0", "minimist@1.2.0"},
			},
			expected: true,
			expectedIntroducedThrough: []string{
				"a@1.0.0", "b@1.0.0", "c@1.0.0", "minimist@1.2.0",
			},
		},
		{
			name: "transitive with len(from)<3 leaves introducedThrough empty",
			issue: ossIssue{
				Id:          "SNYK-JS-LODASH-1",
				Title:       "Prototype Pollution",
				Severity:    "high",
				PackageName: "lodash",
				Version:     "4.17.10",
				From:        []string{"app@1.0.0", "express@4.0.0"},
			},
			expected:                  true,
			expectedIntroducedThrough: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := toIssue(tc.issue, "/abs/path/package.json")

			require.NotNil(t, result)
			require.NotNil(t, result.IsTransitiveDependency)
			assert.Equal(t, tc.expected, *result.IsTransitiveDependency)
			assert.Equal(t, tc.expectedIntroducedThrough, result.IntroducedThrough)
		})
	}
}

func TestIntroducedThroughChain(t *testing.T) {
	assert.Nil(t, introducedThroughChain(ossIssue{From: []string{"app@1"}}))
	assert.Nil(t, introducedThroughChain(ossIssue{From: []string{"app@1", "lodash@1"}}))
	assert.Equal(t, []string{"express@4", "lodash@1"}, introducedThroughChain(ossIssue{
		From: []string{"app@1", "express@4", "lodash@1"},
	}))
	assert.Nil(t, introducedThroughChain(ossIssue{
		PackageName: "lodash",
		From:        []string{"app@1.0.0", "express@4.0.0"},
	}))
}

func TestIntroducedThroughChain_directDependencyReturnsNil(t *testing.T) {
	issue := ossIssue{
		PackageName: "lodash",
		From:        []string{"app@1.0.0", "lodash@4.17.10"},
	}
	transitive := isTransitiveDependency(issue)
	require.NotNil(t, transitive)
	require.False(t, *transitive, "fixture should be a direct dependency")
	assert.Nil(t, introducedThroughChain(issue),
		"direct dependency must not populate introduced-through chain")
}

func boolPtr(v bool) *bool {
	return &v
}

// TestIssueData_JSONSerialization_IsTransitiveDependency locks in the
// pointer + omitempty contract: nil omits the key, false serializes as
// "isTransitiveDependency":false, true serializes as "isTransitiveDependency":true.
func TestIssueData_JSONSerialization_IsTransitiveDependency(t *testing.T) {
	trueVal := true
	falseVal := false

	testCases := []struct {
		name              string
		isTransitivePtr   *bool
		expectKeyPresent  bool
		expectKeyContents string
	}{
		{
			name:              "nil pointer omits the key",
			isTransitivePtr:   nil,
			expectKeyPresent:  false,
			expectKeyContents: "",
		},
		{
			name:              "pointer to false serializes as false",
			isTransitivePtr:   &falseVal,
			expectKeyPresent:  true,
			expectKeyContents: `"isTransitiveDependency":false`,
		},
		{
			name:              "pointer to true serializes as true",
			isTransitivePtr:   &trueVal,
			expectKeyPresent:  true,
			expectKeyContents: `"isTransitiveDependency":true`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := types.IssueData{
				ID:                     "TEST-1",
				Title:                  "Test",
				Severity:               "high",
				IsTransitiveDependency: tc.isTransitivePtr,
			}

			out, err := json.Marshal(data)
			require.NoError(t, err)

			if tc.expectKeyPresent {
				assert.Contains(t, string(out), tc.expectKeyContents)
			} else {
				assert.NotContains(t, string(out), "isTransitiveDependency")
			}
		})
	}
}

func TestIssueData_JSONSerialization_IntroducedThroughOmitempty(t *testing.T) {
	falseVal := false
	direct := types.IssueData{
		ID:                     "TEST-1",
		Title:                  "Test",
		Severity:               "high",
		IsTransitiveDependency: &falseVal,
		IntroducedThrough:      nil,
	}
	out, err := json.Marshal(direct)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "introducedThrough", "nil slice must omit key (direct / no chain)")

	trueVal := true
	transitive := types.IssueData{
		ID:                     "TEST-2",
		Title:                  "Test",
		Severity:               "high",
		IsTransitiveDependency: &trueVal,
		IntroducedThrough:      []string{"express@4", "lodash@1"},
	}
	out, err = json.Marshal(transitive)
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, "introducedThrough")
	assert.Contains(t, s, "express@4")
	assert.Contains(t, s, "lodash@1")

	var roundTrip types.IssueData
	require.NoError(t, json.Unmarshal(out, &roundTrip))
	require.NotNil(t, roundTrip.IntroducedThrough)
	assert.True(t, slices.Equal([]string{"express@4", "lodash@1"}, roundTrip.IntroducedThrough))
}
