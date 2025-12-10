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
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMCPResponseFormat verifies that MCP server list responses return empty arrays
// instead of null when no items are registered. This is required by the MCP specification
// and JSON API best practices.
// See: https://modelcontextprotocol.io/docs/concepts/resources
func TestMCPResponseFormat(t *testing.T) {
	testCases := []struct {
		name                string
		serverOptions       []server.ServerOption
		setupServer         func(*server.MCPServer)
		method              string
		expectedArrayField  string
		shouldBeEmpty       bool
		expectedToolName    string
	}{
		{
			name: "empty resources list returns empty array not null",
			serverOptions: []server.ServerOption{
				server.WithResourceCapabilities(true, true),
			},
			setupServer:        nil,
			method:             "resources/list",
			expectedArrayField: "resources",
			shouldBeEmpty:      true,
		},
		{
			name:          "empty tools list returns empty array not null after removing tool",
			serverOptions: nil,
			setupServer: func(s *server.MCPServer) {
				// Add and then remove a tool to get an empty list with tool capabilities enabled
				tool := mcp.NewTool("temp_tool", mcp.WithDescription("A temporary tool"))
				s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return mcp.NewToolResultText("test"), nil
				})
				s.DeleteTools("temp_tool")
			},
			method:             "tools/list",
			expectedArrayField: "tools",
			shouldBeEmpty:      true,
		},
		{
			name: "empty prompts list returns empty array not null",
			serverOptions: []server.ServerOption{
				server.WithPromptCapabilities(true),
			},
			setupServer:        nil,
			method:             "prompts/list",
			expectedArrayField: "prompts",
			shouldBeEmpty:      true,
		},
		{
			name: "empty resource templates list returns empty array not null",
			serverOptions: []server.ServerOption{
				server.WithResourceCapabilities(true, true),
			},
			setupServer:        nil,
			method:             "resources/templates/list",
			expectedArrayField: "resourceTemplates",
			shouldBeEmpty:      true,
		},
		{
			name:          "registered tool appears in non-empty array",
			serverOptions: nil,
			setupServer: func(s *server.MCPServer) {
				tool := mcp.NewTool("test_tool", mcp.WithDescription("A test tool"))
				s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return mcp.NewToolResultText("test"), nil
				})
			},
			method:             "tools/list",
			expectedArrayField: "tools",
			shouldBeEmpty:      false,
			expectedToolName:   "test_tool",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create server with options
			mcpServer := createTestServer(t, tc.serverOptions)

			// Apply additional setup if provided
			if tc.setupServer != nil {
				tc.setupServer(mcpServer)
			}

			// Initialize the server session
			initializeServer(t, mcpServer)

			// Send the list request
			responseStr := sendListRequest(t, mcpServer, tc.method)

			// Verify the response format
			if tc.shouldBeEmpty {
				assert.Contains(t, responseStr, `"`+tc.expectedArrayField+`":[]`,
					"Response should contain empty %s array, not null. Got: %s", tc.expectedArrayField, responseStr)
				assert.NotContains(t, responseStr, `"`+tc.expectedArrayField+`":null`,
					"Response should NOT contain null %s. Got: %s", tc.expectedArrayField, responseStr)
			} else {
				assert.NotContains(t, responseStr, `"`+tc.expectedArrayField+`":null`,
					"Response should NOT contain null %s. Got: %s", tc.expectedArrayField, responseStr)
				assert.NotContains(t, responseStr, `"`+tc.expectedArrayField+`":[]`,
					"Response should NOT contain empty %s array when items are registered. Got: %s", tc.expectedArrayField, responseStr)
				if tc.expectedToolName != "" {
					assert.Contains(t, responseStr, `"`+tc.expectedToolName+`"`,
						"Response should contain the registered tool %s. Got: %s", tc.expectedToolName, responseStr)
				}
			}
		})
	}
}

// createTestServer creates an MCP server with the given options for testing.
func createTestServer(t *testing.T, options []server.ServerOption) *server.MCPServer {
	t.Helper()
	return server.NewMCPServer("test-server", "1.0.0", options...)
}

// initializeServer sends an initialize request to the MCP server.
func initializeServer(t *testing.T, mcpServer *server.MCPServer) {
	t.Helper()
	initRequest := `{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test-client","version":"1.0.0"},"capabilities":{}}}`
	initResponse := mcpServer.HandleMessage(context.Background(), []byte(initRequest))
	require.NotNil(t, initResponse, "Initialize response should not be nil")
}

// sendListRequest sends a list request for the given method and returns the JSON response string.
func sendListRequest(t *testing.T, mcpServer *server.MCPServer, method string) string {
	t.Helper()
	request := `{"jsonrpc":"2.0","method":"` + method + `","id":2,"params":{}}`
	response := mcpServer.HandleMessage(context.Background(), []byte(request))
	require.NotNil(t, response, "Response should not be nil")

	responseJSON, err := json.Marshal(response)
	require.NoError(t, err, "Failed to marshal response to JSON")

	return string(responseJSON)
}
