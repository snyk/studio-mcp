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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	apiRequestTimeout = 30 * time.Second
)

// snykRestAPIRequest represents a request to the Snyk REST API
type snykRestAPIRequest struct {
	URI    string
	Method string
	Body   io.Reader
}

// doRequest executes the API request with proper headers and error handling
func (r *snykRestAPIRequest) doRequest(ctx context.Context, baseURL string, httpClient *http.Client) (*http.Response, []byte, error) {
	baseURLParsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse API URL: %w", err)
	}

	// Parse the URI to separate path and query
	uriParsed, err := url.Parse(r.URI)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse URI: %w", err)
	}

	// Use JoinPath to construct the full URL with the REST API path
	baseURLParsed.Path = ""
	baseURLParsed.RawQuery = ""
	fullURLParsed := baseURLParsed.JoinPath(uriParsed.Path)
	fullURLParsed.RawQuery = uriParsed.RawQuery
	fullURL := fullURLParsed.String()

	method := r.Method
	if method == "" {
		method = http.MethodGet
	}

	body := r.Body
	if body == nil {
		body = http.NoBody
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	if r.Body != nil {
		req.Header.Set("Content-Type", "application/vnd.api+json")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response: %w", err)
	}

	return resp, respBody, nil
}

// enableSnykCodeForOrg attempts to enable Snyk Code (SAST) for the given organization via REST API
func (m *McpLLMBinding) enableSnykCodeForOrg(ctx context.Context, invocationCtx workflow.InvocationContext, orgId string) error {
	logger := m.logger.With().Str("method", "enableSnykCodeForOrg").Logger()

	config := invocationCtx.GetEngine().GetConfiguration()
	apiUrl := config.GetString(configuration.API_URL)

	if orgId == "" {
		return fmt.Errorf("organization ID not found")
	}

	// Get HTTP client from GAF (handles auth automatically)
	httpClient := invocationCtx.GetNetworkAccess().GetHttpClient()

	requestBody := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "sast_settings",
			"id":   orgId,
			"attributes": map[string]interface{}{
				"sast_enabled": true,
			},
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	apiRequest := &snykRestAPIRequest{
		URI:    fmt.Sprintf("/rest/orgs/%s/settings/sast?version=2024-10-15", orgId),
		Method: http.MethodPatch,
		Body:   bytes.NewBuffer(jsonBody),
	}

	logger.Debug().Str("uri", apiRequest.URI).Str("orgId", orgId).Msg("Enabling Snyk Code via API")

	ctx, cancel := context.WithTimeout(ctx, apiRequestTimeout)
	defer cancel()

	resp, body, err := apiRequest.doRequest(ctx, apiUrl, httpClient)
	if err != nil {
		return err
	}

	logger.Debug().Int("statusCode", resp.StatusCode).Str("response", string(body)).Msg("Received API response")

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	logger.Info().Msg("Successfully enabled Snyk Code for organization")
	return nil
}
