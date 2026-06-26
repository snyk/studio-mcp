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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/studio-mcp/internal/authentication"
)

const (
	// prFindingsAPIVersion pins the Snyk REST issues API version this tool targets.
	prFindingsAPIVersion = "2024-10-15"
	// prFindingsDefaultLimit / prFindingsMaxLimit bound the page size requested from the API.
	prFindingsDefaultLimit = 50
	prFindingsMaxLimit     = 100
)

// validFindingSeverities is the set of severities accepted by the "severity" argument,
// mapped onto the issues API's effective_severity_level filter.
var validFindingSeverities = map[string]bool{
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

// prFinding is the agent-facing shape for a single finding.
type prFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Type     string `json:"type"`
	Status   string `json:"status"`
}

// prFindingsResult is the JSON payload returned to the agent.
type prFindingsResult struct {
	OrgID     string      `json:"org_id"`
	ProjectID string      `json:"project_id,omitempty"`
	Count     int         `json:"count"`
	Findings  []prFinding `json:"findings"`
}

// issuesAPIResponse is the subset of the JSON:API issues response we consume.
type issuesAPIResponse struct {
	Data []struct {
		ID         string `json:"id"`
		Attributes struct {
			Title                  string `json:"title"`
			EffectiveSeverityLevel string `json:"effective_severity_level"`
			Type                   string `json:"type"`
			Status                 string `json:"status"`
		} `json:"attributes"`
	} `json:"data"`
}

// snykListPrFindingsHandler lists open Snyk findings for the configured org, optionally
// scoped to a single project, by querying the Snyk REST issues API with the GAF-authenticated
// HTTP client. It mirrors the auth/org-resolution flow of the other REST-backed tools.
func (m *McpLLMBinding) snykListPrFindingsHandler(invocationCtx workflow.InvocationContext, toolDef SnykMcpToolsDefinition) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", "snykListPrFindingsHandler").Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")

		clientInfo := ClientInfoFromContext(ctx)
		m.updateGafConfigWithIntegrationEnvironment(invocationCtx, clientInfo.Name, clientInfo.Version)

		// Check authentication
		user, whoAmiErr := authentication.CallWhoAmI(&logger, invocationCtx.GetEngine())
		if whoAmiErr != nil || user == nil {
			return mcp.NewToolResultText("User not authenticated. Please run 'snyk_auth' first"), nil
		}

		config := invocationCtx.GetEngine().GetConfiguration()
		orgId := config.GetString(configuration.ORGANIZATION)
		if orgId == "" {
			return mcp.NewToolResultText("Error: Organization ID not configured. Please set an organization using 'snyk config set org=<org-id>'"), nil
		}

		// Extract and validate optional arguments
		args := request.GetArguments()
		projectID := getOptionalStringArg(args, "project_id")
		severity := strings.ToLower(getOptionalStringArg(args, "severity"))
		if severity != "" && !validFindingSeverities[severity] {
			return mcp.NewToolResultText(fmt.Sprintf("Error: Invalid severity '%s'. Must be one of: low, medium, high, critical", severity)), nil
		}

		limit := prFindingsDefaultLimit
		if v, ok := args["limit"].(float64); ok && v > 0 {
			limit = int(v)
			if limit > prFindingsMaxLimit {
				limit = prFindingsMaxLimit
			}
		}

		// Build the issues API query
		query := url.Values{}
		query.Set("version", prFindingsAPIVersion)
		query.Set("limit", strconv.Itoa(limit))
		if severity != "" {
			query.Set("effective_severity_level", severity)
		}
		if projectID != "" {
			query.Set("scan_item.id", projectID)
			query.Set("scan_item.type", "project")
		}

		apiRequest := &snykRestAPIRequest{
			URI:    fmt.Sprintf("/rest/orgs/%s/issues?%s", orgId, query.Encode()),
			Method: http.MethodGet,
		}

		logger.Debug().Str("uri", apiRequest.URI).Str("orgId", orgId).Str("projectId", projectID).Msg("Listing findings via API")

		reqCtx, cancel := context.WithTimeout(ctx, apiRequestTimeout)
		defer cancel()

		apiUrl := config.GetString(configuration.API_URL)
		httpClient := invocationCtx.GetNetworkAccess().GetHttpClient()
		resp, body, err := apiRequest.doRequest(reqCtx, apiUrl, httpClient)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to fetch findings")
			return mcp.NewToolResultText(fmt.Sprintf("Error: Failed to fetch findings: %s", err.Error())), nil
		}

		if resp.StatusCode != http.StatusOK {
			logger.Error().Int("statusCode", resp.StatusCode).Str("response", string(body)).Msg("Findings API returned non-200")
			return mcp.NewToolResultText(fmt.Sprintf("Error: Findings API request failed with status %d: %s", resp.StatusCode, string(body))), nil
		}

		var parsed issuesAPIResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			logger.Error().Err(err).Msg("Failed to parse findings response")
			return mcp.NewToolResultText(fmt.Sprintf("Error: Failed to parse findings response: %s", err.Error())), nil
		}

		result := prFindingsResult{
			OrgID:     orgId,
			ProjectID: projectID,
			Count:     len(parsed.Data),
			Findings:  make([]prFinding, 0, len(parsed.Data)),
		}
		for _, d := range parsed.Data {
			result.Findings = append(result.Findings, prFinding{
				ID:       d.ID,
				Title:    d.Attributes.Title,
				Severity: d.Attributes.EffectiveSeverityLevel,
				Type:     d.Attributes.Type,
				Status:   d.Attributes.Status,
			})
		}

		jsonBytes, err := json.Marshal(result)
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Error: Failed to serialize response: %s", err.Error())), nil
		}

		return mcp.NewToolResultText(string(jsonBytes)), nil
	}
}
