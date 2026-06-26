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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/require"
)

// startFindingsMockServer starts an httptest server that asserts the request shape
// and responds with the supplied status/body. It records the query string it saw.
func startFindingsMockServer(t *testing.T, expectOrgID string, statusCode int, body interface{}, capturedQuery *url.Values) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/rest/orgs/"+expectOrgID+"/issues")
		require.Equal(t, prFindingsAPIVersion, r.URL.Query().Get("version"))

		if capturedQuery != nil {
			*capturedQuery = r.URL.Query()
		}

		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestSnykListPrFindingsHandler_SuccessfulResponse(t *testing.T) {
	const orgID = "22222222-2222-2222-2222-222222222222"
	const projectID = "44444444-4444-4444-4444-444444444444"

	fixture := setupTestFixture(t)
	toolDef := getToolWithName(t, fixture.tools, ToolName.ListPrFindings)
	require.NotNil(t, toolDef, "snyk_list_pr_findings tool definition not found")

	respBody := map[string]interface{}{
		"jsonapi": map[string]interface{}{"version": "1.0"},
		"data": []interface{}{
			map[string]interface{}{
				"id":   "issue-1",
				"type": "issue",
				"attributes": map[string]interface{}{
					"title":                    "SQL Injection",
					"effective_severity_level": "high",
					"type":                     "code",
					"status":                   "open",
				},
			},
			map[string]interface{}{
				"id":   "issue-2",
				"type": "issue",
				"attributes": map[string]interface{}{
					"title":                    "Prototype Pollution",
					"effective_severity_level": "medium",
					"type":                     "package_vulnerability",
					"status":                   "open",
				},
			},
		},
	}

	var capturedQuery url.Values
	apiURL := startFindingsMockServer(t, orgID, http.StatusOK, respBody, &capturedQuery)

	config := fixture.invocationContext.GetConfiguration()
	config.Set(configuration.ORGANIZATION, orgID)
	config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
	config.Set(configuration.API_URL, apiURL)

	handler := fixture.binding.snykListPrFindingsHandler(fixture.invocationContext, *toolDef)

	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]interface{}{
		"project_id": projectID,
		"severity":   "high",
		"limit":      float64(25),
	}}}

	result, err := handler(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	text, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)

	var payload prFindingsResult
	require.NoError(t, json.Unmarshal([]byte(text.Text), &payload))

	require.Equal(t, orgID, payload.OrgID)
	require.Equal(t, projectID, payload.ProjectID)
	require.Equal(t, 2, payload.Count)
	require.Len(t, payload.Findings, 2)
	require.Equal(t, "issue-1", payload.Findings[0].ID)
	require.Equal(t, "SQL Injection", payload.Findings[0].Title)
	require.Equal(t, "high", payload.Findings[0].Severity)
	require.Equal(t, "code", payload.Findings[0].Type)
	require.Equal(t, "open", payload.Findings[0].Status)

	// Verify the optional args were translated into the expected query params.
	require.Equal(t, "high", capturedQuery.Get("effective_severity_level"))
	require.Equal(t, "25", capturedQuery.Get("limit"))
	require.Equal(t, projectID, capturedQuery.Get("scan_item.id"))
	require.Equal(t, "project", capturedQuery.Get("scan_item.type"))
}

func TestSnykListPrFindingsHandler_InvalidSeverity(t *testing.T) {
	const orgID = "22222222-2222-2222-2222-222222222222"

	fixture := setupTestFixture(t)
	toolDef := getToolWithName(t, fixture.tools, ToolName.ListPrFindings)
	require.NotNil(t, toolDef)

	config := fixture.invocationContext.GetConfiguration()
	config.Set(configuration.ORGANIZATION, orgID)
	config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")

	handler := fixture.binding.snykListPrFindingsHandler(fixture.invocationContext, *toolDef)

	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]interface{}{
		"severity": "bogus",
	}}}

	result, err := handler(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	text, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)
	require.Contains(t, text.Text, "Invalid severity")
}

func TestSnykListPrFindingsHandler_OrgIDNotConfigured(t *testing.T) {
	fixture := setupTestFixture(t)
	toolDef := getToolWithName(t, fixture.tools, ToolName.ListPrFindings)
	require.NotNil(t, toolDef)

	// The fixture starts with no organization configured, so the handler should
	// short-circuit before making any API call.
	handler := fixture.binding.snykListPrFindingsHandler(fixture.invocationContext, *toolDef)

	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]interface{}{}}}

	result, err := handler(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	text, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)
	require.Contains(t, text.Text, "Organization ID not configured")
}

func TestSnykListPrFindingsHandler_APIError(t *testing.T) {
	const orgID = "22222222-2222-2222-2222-222222222222"

	fixture := setupTestFixture(t)
	toolDef := getToolWithName(t, fixture.tools, ToolName.ListPrFindings)
	require.NotNil(t, toolDef)

	apiURL := startFindingsMockServer(t, orgID, http.StatusInternalServerError, map[string]interface{}{
		"errors": []interface{}{map[string]interface{}{"detail": "boom"}},
	}, nil)

	config := fixture.invocationContext.GetConfiguration()
	config.Set(configuration.ORGANIZATION, orgID)
	config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
	config.Set(configuration.API_URL, apiURL)

	handler := fixture.binding.snykListPrFindingsHandler(fixture.invocationContext, *toolDef)

	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]interface{}{}}}

	result, err := handler(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	text, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)
	require.Contains(t, text.Text, "status 500")
}
