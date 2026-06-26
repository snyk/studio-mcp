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
	"net/url"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/require"
)

// TestSnykListPrFindings_EndToEndOverMCP drives the real MCP server message
// handling end-to-end: it registers all tools the way the production workflow
// does (addSnykTools), then exercises tools/list and tools/call over actual
// JSON-RPC. The Snyk REST API is stood in by a local httptest server, since
// this repo is a workflow library hosted by the Snyk CLI and has no live creds.
func TestSnykListPrFindings_EndToEndOverMCP(t *testing.T) {
	const orgID = "22222222-2222-2222-2222-222222222222"
	const projectID = "44444444-4444-4444-4444-444444444444"

	fixture := setupTestFixture(t)

	// Stand-in Snyk REST issues API.
	var capturedQuery url.Values
	apiURL := startFindingsMockServer(t, orgID, http.StatusOK, map[string]interface{}{
		"jsonapi": map[string]interface{}{"version": "1.0"},
		"data": []interface{}{
			map[string]interface{}{
				"id":   "issue-1",
				"type": "issue",
				"attributes": map[string]interface{}{
					"title":                    "Hardcoded secret in source",
					"effective_severity_level": "high",
					"type":                     "code",
					"status":                   "open",
				},
			},
			map[string]interface{}{
				"id":   "issue-2",
				"type": "issue",
				"attributes": map[string]interface{}{
					"title":                    "Use of vulnerable lodash version",
					"effective_severity_level": "high",
					"type":                     "package_vulnerability",
					"status":                   "open",
				},
			},
		},
	}, &capturedQuery)

	config := fixture.invocationContext.GetConfiguration()
	config.Set(configuration.ORGANIZATION, orgID)
	config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
	config.Set(configuration.API_URL, apiURL)

	// Register all tools exactly as the workflow does, then init the server.
	require.NoError(t, fixture.binding.addSnykTools(fixture.invocationContext, ProfileExperimental))
	srv := fixture.binding.mcpServer
	initializeMCPServer(t, srv)

	// 1) tools/list — confirm the tool is exposed over the wire with its schema.
	listResp := sendMCPRequest(t, srv, "tools/list", `{}`)
	t.Logf("tools/list (snyk_list_pr_findings present): %v", containsToolInList(t, listResp, "snyk_list_pr_findings"))
	require.Contains(t, listResp, "snyk_list_pr_findings", "tool must be advertised via tools/list")
	require.Contains(t, listResp, "project_id", "tool schema must advertise project_id param")

	// 2) tools/call — invoke the tool over JSON-RPC against the stand-in API.
	callResp := sendMCPRequest(t, srv, "tools/call",
		`{"name":"snyk_list_pr_findings","arguments":{"project_id":"`+projectID+`","severity":"high","limit":10}}`)
	require.NotContains(t, callResp, `"error"`, "tools/call should not error")

	// The structured payload is returned as the text content of the result.
	payload := extractToolResultPayload(t, callResp)
	t.Logf("tools/call returned %d findings: %s", payload.Count, mustJSON(t, payload))

	require.Equal(t, orgID, payload.OrgID)
	require.Equal(t, projectID, payload.ProjectID)
	require.Equal(t, 2, payload.Count)
	require.Len(t, payload.Findings, 2)
	require.Equal(t, "Hardcoded secret in source", payload.Findings[0].Title)
	require.Equal(t, "high", payload.Findings[0].Severity)

	// The agent's args were faithfully translated into REST query params.
	require.Equal(t, "high", capturedQuery.Get("effective_severity_level"))
	require.Equal(t, "10", capturedQuery.Get("limit"))
	require.Equal(t, projectID, capturedQuery.Get("scan_item.id"))
	require.Equal(t, "project", capturedQuery.Get("scan_item.type"))
}

// containsToolInList reports whether the tools/list response advertises the named tool.
func containsToolInList(t *testing.T, listResp, name string) bool {
	t.Helper()
	var resp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(listResp), &resp))
	for _, tool := range resp.Result.Tools {
		if tool.Name == name {
			return true
		}
	}
	return false
}

// extractToolResultPayload pulls the JSON text content out of a tools/call
// response and decodes it into the tool's structured result shape.
func extractToolResultPayload(t *testing.T, callResp string) prFindingsResult {
	t.Helper()
	var resp struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(callResp), &resp))
	require.NotEmpty(t, resp.Result.Content, "tool result must contain content")

	var payload prFindingsResult
	require.NoError(t, json.Unmarshal([]byte(resp.Result.Content[0].Text), &payload))
	return payload
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}
