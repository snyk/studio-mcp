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
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MCP Specification Conformance Tests
// These tests verify compliance with the Model Context Protocol specification:
// - Version 2025-11-25: https://modelcontextprotocol.io/specification/2025-11-25/
// - Version 2025-06-18: https://modelcontextprotocol.io/specification/2025-06-18/

// =============================================================================
// Test Fixture and Helper Functions
// =============================================================================

// mcpTestFixture provides a consistent setup for MCP conformance tests.
// Following the fixture pattern from TESTING_STANDARDS_AND_DIRECTIVES.md.
type mcpTestFixture struct {
	t         *testing.T
	mcpServer *server.MCPServer
}

// setupMCPTestFixture creates a new MCP test fixture with the specified server options.
func setupMCPTestFixture(t *testing.T, opts ...server.ServerOption) *mcpTestFixture {
	t.Helper()
	mcpServer := server.NewMCPServer("test-server", "1.0.0", opts...)
	return &mcpTestFixture{
		t:         t,
		mcpServer: mcpServer,
	}
}

// initialize sends the initialize request and returns the fixture for chaining.
func (f *mcpTestFixture) initialize() *mcpTestFixture {
	f.t.Helper()
	initializeMCPServer(f.t, f.mcpServer)
	return f
}

// sendRequest sends a request to the MCP server and returns the JSON response.
func (f *mcpTestFixture) sendRequest(method, params string) string {
	f.t.Helper()
	return sendMCPRequest(f.t, f.mcpServer, method, params)
}

// sendRawRequest sends a raw JSON-RPC request and returns the response.
func (f *mcpTestFixture) sendRawRequest(request string) interface{} {
	f.t.Helper()
	return f.mcpServer.HandleMessage(f.t.Context(), []byte(request))
}

// initializeMCPServer sends an initialize request to the MCP server and verifies success.
func initializeMCPServer(t *testing.T, mcpServer *server.MCPServer) {
	t.Helper()
	initRequest := `{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}}}`
	initResponse := mcpServer.HandleMessage(t.Context(), []byte(initRequest))
	require.NotNil(t, initResponse, "Initialize response should not be nil")
}

// sendMCPRequest sends a request to the MCP server and returns the JSON response string.
func sendMCPRequest(t *testing.T, mcpServer *server.MCPServer, method, params string) string {
	t.Helper()
	request := `{"jsonrpc":"2.0","method":"` + method + `","id":2,"params":` + params + `}`
	response := mcpServer.HandleMessage(t.Context(), []byte(request))
	require.NotNil(t, response, "Response should not be nil")

	responseJSON, err := json.Marshal(response)
	require.NoError(t, err, "Failed to marshal response to JSON")

	return string(responseJSON)
}

// parseJSONResponse unmarshals a JSON response string into a map.
func parseJSONResponse(t *testing.T, responseStr string) map[string]interface{} {
	t.Helper()
	var responseMap map[string]interface{}
	err := json.Unmarshal([]byte(responseStr), &responseMap)
	require.NoError(t, err, "Failed to unmarshal response JSON")
	return responseMap
}

// =============================================================================
// Test Lifecycle & Initialization
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
// =============================================================================

// TestMCPLifecycleInitialization verifies the server correctly handles the
// initialization handshake as per MCP specification.
func TestMCPLifecycleInitialization(t *testing.T) {
	testCases := []struct {
		name              string
		serverOptions     []server.ServerOption
		request           string
		expectError       bool
		expectedErrorCode int
		validateResponse  func(t *testing.T, responseStr string)
	}{
		{
			name: "valid initialize request returns server info and capabilities",
			serverOptions: []server.ServerOption{
				server.WithResourceCapabilities(true, true),
				server.WithPromptCapabilities(true),
			},
			request: `{
				"jsonrpc": "2.0",
				"method": "initialize",
				"id": 1,
				"params": {
					"protocolVersion": "2024-11-05",
					"clientInfo": {"name": "test-client", "version": "1.0.0"},
					"capabilities": {}
				}
			}`,
			expectError: false,
			validateResponse: func(t *testing.T, responseStr string) {
				t.Helper()
				assert.Contains(t, responseStr, `"protocolVersion"`, "Response should contain protocol version")
				assert.Contains(t, responseStr, `"serverInfo"`, "Response should contain server info")
				assert.Contains(t, responseStr, `"capabilities"`, "Response should contain capabilities")
			},
		},
		{
			name:              "initialize without jsonrpc version returns error",
			serverOptions:     nil,
			request:           `{"id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "clientInfo": {"name": "test", "version": "1.0"}}}`,
			expectError:       true,
			expectedErrorCode: mcp.INVALID_REQUEST,
		},
		{
			name:              "initialize with invalid JSON returns parse error",
			serverOptions:     nil,
			request:           `{"jsonrpc": "2.0", "id": 1, "method": "initialize"`,
			expectError:       true,
			expectedErrorCode: mcp.PARSE_ERROR,
		},
		{
			name:          "request before initialize should work for initialize method",
			serverOptions: nil,
			request: `{
				"jsonrpc": "2.0",
				"method": "initialize",
				"id": 1,
				"params": {
					"protocolVersion": "2024-11-05",
					"clientInfo": {"name": "test-client", "version": "1.0.0"},
					"capabilities": {}
				}
			}`,
			expectError: false,
			validateResponse: func(t *testing.T, responseStr string) {
				t.Helper()
				assert.Contains(t, responseStr, `"result"`, "Initialize should succeed")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mcpServer := server.NewMCPServer("test-server", "1.0.0", tc.serverOptions...)
			response := mcpServer.HandleMessage(t.Context(), []byte(tc.request))
			require.NotNil(t, response, "Response should not be nil")

			responseJSON, err := json.Marshal(response)
			require.NoError(t, err, "Failed to marshal response")
			responseStr := string(responseJSON)

			if tc.expectError {
				assert.Contains(t, responseStr, `"error"`, "Response should contain error")
				if tc.expectedErrorCode != 0 {
					errorResponse, ok := response.(mcp.JSONRPCError)
					require.True(t, ok, "Response should be JSONRPCError")
					assert.Equal(t, tc.expectedErrorCode, errorResponse.Error.Code, "Error code should match")
				}
			} else {
				assert.NotContains(t, responseStr, `"error"`, "Response should not contain error")
				if tc.validateResponse != nil {
					tc.validateResponse(t, responseStr)
				}
			}
		})
	}
}

// TestMCPCapabilitiesDeclaration verifies the server correctly declares its
// capabilities during initialization.
func TestMCPCapabilitiesDeclaration(t *testing.T) {
	testCases := []struct {
		name                    string
		serverOptions           []server.ServerOption
		setupServer             func(*server.MCPServer)
		expectedCapabilities    []string
		notExpectedCapabilities []string
	}{
		{
			name: "server with resources capability declares resources",
			serverOptions: []server.ServerOption{
				server.WithResourceCapabilities(true, true),
			},
			expectedCapabilities: []string{`"resources"`},
		},
		{
			name: "server with prompts capability declares prompts",
			serverOptions: []server.ServerOption{
				server.WithPromptCapabilities(true),
			},
			expectedCapabilities: []string{`"prompts"`},
		},
		{
			name:          "server with tools declares tools capability",
			serverOptions: nil,
			setupServer: func(s *server.MCPServer) {
				tool := mcp.NewTool("test_tool", mcp.WithDescription("Test"))
				s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return mcp.NewToolResultText("ok"), nil
				})
			},
			expectedCapabilities: []string{`"tools"`},
		},
		{
			name:                    "server without capabilities does not declare them",
			serverOptions:           nil,
			notExpectedCapabilities: []string{`"resources":{"`, `"prompts":{"`, `"tools":{"`},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mcpServer := server.NewMCPServer("test-server", "1.0.0", tc.serverOptions...)
			if tc.setupServer != nil {
				tc.setupServer(mcpServer)
			}

			initRequest := `{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}}}`
			response := mcpServer.HandleMessage(t.Context(), []byte(initRequest))
			require.NotNil(t, response)

			responseJSON, err := json.Marshal(response)
			require.NoError(t, err)
			responseStr := string(responseJSON)

			for _, cap := range tc.expectedCapabilities {
				assert.Contains(t, responseStr, cap, "Should declare capability: %s", cap)
			}
			for _, cap := range tc.notExpectedCapabilities {
				assert.NotContains(t, responseStr, cap, "Should not declare capability: %s", cap)
			}
		})
	}
}

// =============================================================================
// Test JSON-RPC 2.0 Error Codes
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/basic
// =============================================================================

// TestMCPJSONRPCErrorCodes verifies the server returns correct error codes
// as defined in JSON-RPC 2.0 and the MCP specification.
func TestMCPJSONRPCErrorCodes(t *testing.T) {
	testCases := []struct {
		name              string
		serverOptions     []server.ServerOption
		initializeFirst   bool
		request           string
		expectedErrorCode int
		expectedInMessage string
	}{
		{
			name:              "invalid JSON returns parse error (-32700)",
			serverOptions:     nil,
			initializeFirst:   false,
			request:           `{"jsonrpc": "2.0", "id": 1, "method": "initialize"`,
			expectedErrorCode: mcp.PARSE_ERROR,
		},
		{
			name:              "missing jsonrpc version returns invalid request (-32600)",
			serverOptions:     nil,
			initializeFirst:   false,
			request:           `{"id": 1, "method": "initialize", "params": {}}`,
			expectedErrorCode: mcp.INVALID_REQUEST,
		},
		{
			name:              "unknown method returns method not found (-32601)",
			serverOptions:     nil,
			initializeFirst:   true,
			request:           `{"jsonrpc": "2.0", "id": 2, "method": "unknown/method", "params": {}}`,
			expectedErrorCode: mcp.METHOD_NOT_FOUND,
		},
		{
			name:              "tools/list without tools capability returns method not found",
			serverOptions:     nil,
			initializeFirst:   true,
			request:           `{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}`,
			expectedErrorCode: mcp.METHOD_NOT_FOUND,
			expectedInMessage: "tools",
		},
		{
			name:              "resources/list without resources capability returns method not found",
			serverOptions:     nil,
			initializeFirst:   true,
			request:           `{"jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {}}`,
			expectedErrorCode: mcp.METHOD_NOT_FOUND,
			expectedInMessage: "resources",
		},
		{
			name:              "prompts/list without prompts capability returns method not found",
			serverOptions:     nil,
			initializeFirst:   true,
			request:           `{"jsonrpc": "2.0", "id": 2, "method": "prompts/list", "params": {}}`,
			expectedErrorCode: mcp.METHOD_NOT_FOUND,
			expectedInMessage: "prompts",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mcpServer := server.NewMCPServer("test-server", "1.0.0", tc.serverOptions...)

			if tc.initializeFirst {
				initRequest := `{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}}}`
				initResponse := mcpServer.HandleMessage(t.Context(), []byte(initRequest))
				require.NotNil(t, initResponse)
			}

			response := mcpServer.HandleMessage(t.Context(), []byte(tc.request))
			require.NotNil(t, response, "Response should not be nil")

			errorResponse, ok := response.(mcp.JSONRPCError)
			require.True(t, ok, "Response should be a JSONRPCError, got: %T", response)
			assert.Equal(t, tc.expectedErrorCode, errorResponse.Error.Code, "Error code should match")

			if tc.expectedInMessage != "" {
				assert.Contains(t, errorResponse.Error.Message, tc.expectedInMessage, "Error message should contain expected text")
			}
		})
	}
}

// TestMCPRequestIDMatching verifies that response IDs match request IDs.
func TestMCPRequestIDMatching(t *testing.T) {
	testCases := []struct {
		name      string
		requestID interface{}
		request   string
	}{
		{
			name:      "integer ID is preserved",
			requestID: float64(42), // JSON numbers unmarshal to float64
			request:   `{"jsonrpc":"2.0","method":"initialize","id":42,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}}}`,
		},
		{
			name:      "string ID is preserved",
			requestID: "test-id-123",
			request:   `{"jsonrpc":"2.0","method":"initialize","id":"test-id-123","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}}}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mcpServer := server.NewMCPServer("test-server", "1.0.0")
			response := mcpServer.HandleMessage(t.Context(), []byte(tc.request))
			require.NotNil(t, response)

			responseJSON, err := json.Marshal(response)
			require.NoError(t, err)

			var responseMap map[string]interface{}
			err = json.Unmarshal(responseJSON, &responseMap)
			require.NoError(t, err)

			assert.Equal(t, tc.requestID, responseMap["id"], "Response ID should match request ID")
		})
	}
}

// =============================================================================
// Test Ping Mechanism
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/ping
// =============================================================================

// TestMCPPingMechanism verifies the server responds correctly to ping requests.
func TestMCPPingMechanism(t *testing.T) {
	testCases := []struct {
		name             string
		initializeFirst  bool
		request          string
		expectError      bool
		validateResponse func(t *testing.T, responseStr string)
	}{
		{
			name:            "ping returns empty result after initialization",
			initializeFirst: true,
			request:         `{"jsonrpc":"2.0","method":"ping","id":2,"params":{}}`,
			expectError:     false,
			validateResponse: func(t *testing.T, responseStr string) {
				t.Helper()
				assert.Contains(t, responseStr, `"result"`, "Ping should return result")
				assert.Contains(t, responseStr, `"id"`, "Ping should have ID")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mcpServer := server.NewMCPServer("test-server", "1.0.0")

			if tc.initializeFirst {
				initRequest := `{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}}}`
				initResponse := mcpServer.HandleMessage(t.Context(), []byte(initRequest))
				require.NotNil(t, initResponse)
			}

			response := mcpServer.HandleMessage(t.Context(), []byte(tc.request))
			require.NotNil(t, response, "Response should not be nil")

			responseJSON, err := json.Marshal(response)
			require.NoError(t, err)
			responseStr := string(responseJSON)

			if tc.expectError {
				assert.Contains(t, responseStr, `"error"`, "Response should contain error")
			} else {
				assert.NotContains(t, responseStr, `"error"`, "Response should not contain error")
				if tc.validateResponse != nil {
					tc.validateResponse(t, responseStr)
				}
			}
		})
	}
}

// =============================================================================
// Test Tool Operations
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
// =============================================================================

// TestMCPToolOperations verifies tools/list and tools/call work correctly.
func TestMCPToolOperations(t *testing.T) {
	testCases := []struct {
		name              string
		setupServer       func(*server.MCPServer)
		method            string
		params            string
		expectError       bool
		expectedErrorCode int
		validateResponse  func(t *testing.T, responseStr string)
	}{
		{
			name: "tools/list returns registered tools",
			setupServer: func(s *server.MCPServer) {
				tool := mcp.NewTool("test_tool",
					mcp.WithDescription("A test tool"),
					mcp.WithString("input", mcp.Required(), mcp.Description("Input parameter")),
				)
				s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return mcp.NewToolResultText("result"), nil
				})
			},
			method:      "tools/list",
			params:      `{}`,
			expectError: false,
			validateResponse: func(t *testing.T, responseStr string) {
				t.Helper()
				assert.Contains(t, responseStr, `"test_tool"`, "Should contain tool name")
				assert.Contains(t, responseStr, `"A test tool"`, "Should contain tool description")
			},
		},
		{
			name: "tools/call invokes tool and returns result",
			setupServer: func(s *server.MCPServer) {
				tool := mcp.NewTool("echo_tool", mcp.WithDescription("Echo tool"))
				s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return mcp.NewToolResultText("echo response"), nil
				})
			},
			method:      "tools/call",
			params:      `{"name": "echo_tool", "arguments": {}}`,
			expectError: false,
			validateResponse: func(t *testing.T, responseStr string) {
				t.Helper()
				assert.Contains(t, responseStr, `"content"`, "Should contain content array")
				assert.Contains(t, responseStr, `"echo response"`, "Should contain tool response")
			},
		},
		{
			name: "tools/call with unknown tool returns error",
			setupServer: func(s *server.MCPServer) {
				// Add a dummy tool to enable tool capabilities
				tool := mcp.NewTool("dummy", mcp.WithDescription("Dummy"))
				s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return mcp.NewToolResultText(""), nil
				})
			},
			method:      "tools/call",
			params:      `{"name": "nonexistent_tool", "arguments": {}}`,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mcpServer := server.NewMCPServer("test-server", "1.0.0")
			if tc.setupServer != nil {
				tc.setupServer(mcpServer)
			}

			initializeMCPServer(t, mcpServer)
			responseStr := sendMCPRequest(t, mcpServer, tc.method, tc.params)

			if tc.expectError {
				assert.Contains(t, responseStr, `"error"`, "Response should contain error")
			} else {
				assert.NotContains(t, responseStr, `"error"`, "Response should not contain error")
				if tc.validateResponse != nil {
					tc.validateResponse(t, responseStr)
				}
			}
		})
	}
}

// =============================================================================
// Test Resource Operations
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/resources
// =============================================================================

// TestMCPResourceOperations verifies resources/list and resources/read work correctly.
func TestMCPResourceOperations(t *testing.T) {
	testCases := []struct {
		name             string
		serverOptions    []server.ServerOption
		setupServer      func(*server.MCPServer)
		method           string
		params           string
		expectError      bool
		validateResponse func(t *testing.T, responseStr string)
	}{
		{
			name: "resources/list returns empty array when no resources",
			serverOptions: []server.ServerOption{
				server.WithResourceCapabilities(true, true),
			},
			method:      "resources/list",
			params:      `{}`,
			expectError: false,
			validateResponse: func(t *testing.T, responseStr string) {
				t.Helper()
				assert.Contains(t, responseStr, `"resources":[]`, "Should return empty resources array")
			},
		},
		{
			name: "resources/list returns registered resources",
			serverOptions: []server.ServerOption{
				server.WithResourceCapabilities(true, true),
			},
			setupServer: func(s *server.MCPServer) {
				resource := mcp.NewResource("file:///test.txt", "Test Resource", mcp.WithResourceDescription("A test resource"))
				s.AddResource(resource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
					return []mcp.ResourceContents{
						mcp.TextResourceContents{
							URI:      "file:///test.txt",
							MIMEType: "text/plain",
							Text:     "test content",
						},
					}, nil
				})
			},
			method:      "resources/list",
			params:      `{}`,
			expectError: false,
			validateResponse: func(t *testing.T, responseStr string) {
				t.Helper()
				assert.Contains(t, responseStr, `"file:///test.txt"`, "Should contain resource URI")
				assert.Contains(t, responseStr, `"Test Resource"`, "Should contain resource name")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mcpServer := server.NewMCPServer("test-server", "1.0.0", tc.serverOptions...)
			if tc.setupServer != nil {
				tc.setupServer(mcpServer)
			}

			initializeMCPServer(t, mcpServer)
			responseStr := sendMCPRequest(t, mcpServer, tc.method, tc.params)

			if tc.expectError {
				assert.Contains(t, responseStr, `"error"`, "Response should contain error")
			} else {
				assert.NotContains(t, responseStr, `"error"`, "Response should not contain error")
				if tc.validateResponse != nil {
					tc.validateResponse(t, responseStr)
				}
			}
		})
	}
}

// =============================================================================
// Test Prompts Operations
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/prompts
// =============================================================================

// TestMCPPromptsOperations verifies prompts/list works correctly.
func TestMCPPromptsOperations(t *testing.T) {
	testCases := []struct {
		name             string
		serverOptions    []server.ServerOption
		setupServer      func(*server.MCPServer)
		method           string
		params           string
		expectError      bool
		validateResponse func(t *testing.T, responseStr string)
	}{
		{
			name: "prompts/list returns empty array when no prompts",
			serverOptions: []server.ServerOption{
				server.WithPromptCapabilities(true),
			},
			method:      "prompts/list",
			params:      `{}`,
			expectError: false,
			validateResponse: func(t *testing.T, responseStr string) {
				t.Helper()
				assert.Contains(t, responseStr, `"prompts":[]`, "Should return empty prompts array")
			},
		},
		{
			name: "prompts/list returns registered prompts",
			serverOptions: []server.ServerOption{
				server.WithPromptCapabilities(true),
			},
			setupServer: func(s *server.MCPServer) {
				prompt := mcp.NewPrompt("test_prompt", mcp.WithPromptDescription("A test prompt"))
				s.AddPrompt(prompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
					return &mcp.GetPromptResult{
						Description: "Test prompt result",
						Messages: []mcp.PromptMessage{
							{
								Role: mcp.RoleUser,
								Content: mcp.TextContent{
									Type: "text",
									Text: "Test message",
								},
							},
						},
					}, nil
				})
			},
			method:      "prompts/list",
			params:      `{}`,
			expectError: false,
			validateResponse: func(t *testing.T, responseStr string) {
				t.Helper()
				assert.Contains(t, responseStr, `"test_prompt"`, "Should contain prompt name")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mcpServer := server.NewMCPServer("test-server", "1.0.0", tc.serverOptions...)
			if tc.setupServer != nil {
				tc.setupServer(mcpServer)
			}

			initializeMCPServer(t, mcpServer)
			responseStr := sendMCPRequest(t, mcpServer, tc.method, tc.params)

			if tc.expectError {
				assert.Contains(t, responseStr, `"error"`, "Response should contain error")
			} else {
				assert.NotContains(t, responseStr, `"error"`, "Response should not contain error")
				if tc.validateResponse != nil {
					tc.validateResponse(t, responseStr)
				}
			}
		})
	}
}

// =============================================================================
// Test MCP 2025-06-18 Specific Requirements
// Spec: https://modelcontextprotocol.io/specification/2025-06-18/
// =============================================================================

// TestMCPJSONRPCBatchingNotSupported verifies that JSON-RPC batching is not supported
// as per MCP 2025-06-18 specification.
func TestMCPJSONRPCBatchingNotSupported(t *testing.T) {
	t.Parallel()
	mcpServer := server.NewMCPServer("test-server", "1.0.0")

	// Send a batch request (array of requests)
	batchRequest := `[
		{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}}},
		{"jsonrpc":"2.0","method":"ping","id":2,"params":{}}
	]`

	response := mcpServer.HandleMessage(t.Context(), []byte(batchRequest))
	require.NotNil(t, response, "Response should not be nil")

	// The server should reject batch requests with an error
	responseJSON, err := json.Marshal(response)
	require.NoError(t, err)
	responseStr := string(responseJSON)

	// Batch requests should result in an error (parse error for array input)
	assert.Contains(t, responseStr, `"error"`, "Batch requests should return an error")
}

// =============================================================================
// Test Response Format Compliance
// Verifies responses conform to JSON-RPC 2.0 and MCP specifications
// =============================================================================

// TestMCPResponseFormatCompliance verifies response format requirements.
func TestMCPResponseFormatCompliance(t *testing.T) {
	testCases := []struct {
		name             string
		serverOptions    []server.ServerOption
		request          string
		validateResponse func(t *testing.T, responseStr string, responseMap map[string]interface{})
	}{
		{
			name:          "response contains jsonrpc version 2.0",
			serverOptions: nil,
			request:       `{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}}}`,
			validateResponse: func(t *testing.T, responseStr string, responseMap map[string]interface{}) {
				t.Helper()
				assert.Equal(t, "2.0", responseMap["jsonrpc"], "Response should have jsonrpc version 2.0")
			},
		},
		{
			name:          "successful response contains result field",
			serverOptions: nil,
			request:       `{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}}}`,
			validateResponse: func(t *testing.T, responseStr string, responseMap map[string]interface{}) {
				t.Helper()
				_, hasResult := responseMap["result"]
				_, hasError := responseMap["error"]
				assert.True(t, hasResult, "Successful response should have result field")
				assert.False(t, hasError, "Successful response should not have error field")
			},
		},
		{
			name:          "error response contains error field with code and message",
			serverOptions: nil,
			request:       `{"id": 1, "method": "initialize"}`, // Missing jsonrpc version
			validateResponse: func(t *testing.T, responseStr string, responseMap map[string]interface{}) {
				t.Helper()
				errorObj, hasError := responseMap["error"]
				assert.True(t, hasError, "Error response should have error field")

				if errorMap, ok := errorObj.(map[string]interface{}); ok {
					_, hasCode := errorMap["code"]
					_, hasMessage := errorMap["message"]
					assert.True(t, hasCode, "Error should have code")
					assert.True(t, hasMessage, "Error should have message")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mcpServer := server.NewMCPServer("test-server", "1.0.0", tc.serverOptions...)
			response := mcpServer.HandleMessage(t.Context(), []byte(tc.request))
			require.NotNil(t, response)

			responseJSON, err := json.Marshal(response)
			require.NoError(t, err)
			responseStr := string(responseJSON)

			var responseMap map[string]interface{}
			err = json.Unmarshal(responseJSON, &responseMap)
			require.NoError(t, err)

			tc.validateResponse(t, responseStr, responseMap)
		})
	}
}

// =============================================================================
// Test Empty Array Response Format (not null)
// MCP spec requires empty arrays [], not null, for list responses
// =============================================================================

// TestMCPEmptyArrayResponseFormat verifies that MCP server list responses return
// empty arrays instead of null when no items are registered. This is required by
// the MCP specification and JSON API best practices.
func TestMCPEmptyArrayResponseFormat(t *testing.T) {
	testCases := []struct {
		name               string
		serverOptions      []server.ServerOption
		setupServer        func(*server.MCPServer)
		method             string
		expectedArrayField string
		shouldBeEmpty      bool
		expectedItemName   string
	}{
		{
			name: "empty resources list returns empty array not null",
			serverOptions: []server.ServerOption{
				server.WithResourceCapabilities(true, true),
			},
			method:             "resources/list",
			expectedArrayField: "resources",
			shouldBeEmpty:      true,
		},
		{
			name: "empty tools list returns empty array not null after removing tool",
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
			method:             "prompts/list",
			expectedArrayField: "prompts",
			shouldBeEmpty:      true,
		},
		{
			name: "empty resource templates list returns empty array not null",
			serverOptions: []server.ServerOption{
				server.WithResourceCapabilities(true, true),
			},
			method:             "resources/templates/list",
			expectedArrayField: "resourceTemplates",
			shouldBeEmpty:      true,
		},
		{
			name: "registered tool appears in non-empty array",
			setupServer: func(s *server.MCPServer) {
				tool := mcp.NewTool("test_tool", mcp.WithDescription("A test tool"))
				s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return mcp.NewToolResultText("test"), nil
				})
			},
			method:             "tools/list",
			expectedArrayField: "tools",
			shouldBeEmpty:      false,
			expectedItemName:   "test_tool",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mcpServer := server.NewMCPServer("test-server", "1.0.0", tc.serverOptions...)
			if tc.setupServer != nil {
				tc.setupServer(mcpServer)
			}

			initializeMCPServer(t, mcpServer)
			responseStr := sendMCPRequest(t, mcpServer, tc.method, `{}`)

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
				if tc.expectedItemName != "" {
					assert.Contains(t, responseStr, `"`+tc.expectedItemName+`"`,
						"Response should contain the registered item %s. Got: %s", tc.expectedItemName, responseStr)
				}
			}
		})
	}
}

// =============================================================================
// Test Pagination Support
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination
// =============================================================================

// TestMCPPaginationSupport verifies cursor-based pagination for list operations.
func TestMCPPaginationSupport(t *testing.T) {
	testCases := []struct {
		name             string
		serverOptions    []server.ServerOption
		setupServer      func(*server.MCPServer)
		method           string
		params           string
		validateResponse func(t *testing.T, responseStr string)
	}{
		{
			name: "tools/list supports cursor parameter",
			setupServer: func(s *server.MCPServer) {
				tool := mcp.NewTool("test_tool", mcp.WithDescription("Test"))
				s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return mcp.NewToolResultText("ok"), nil
				})
			},
			method: "tools/list",
			params: `{"cursor": ""}`,
			validateResponse: func(t *testing.T, responseStr string) {
				t.Helper()
				// Should not error even with cursor parameter
				assert.NotContains(t, responseStr, `"error"`, "Should accept cursor parameter")
				assert.Contains(t, responseStr, `"tools"`, "Should return tools")
			},
		},
		{
			name: "resources/list supports cursor parameter",
			serverOptions: []server.ServerOption{
				server.WithResourceCapabilities(true, true),
			},
			method: "resources/list",
			params: `{"cursor": ""}`,
			validateResponse: func(t *testing.T, responseStr string) {
				t.Helper()
				assert.NotContains(t, responseStr, `"error"`, "Should accept cursor parameter")
				assert.Contains(t, responseStr, `"resources"`, "Should return resources")
			},
		},
		{
			name: "prompts/list supports cursor parameter",
			serverOptions: []server.ServerOption{
				server.WithPromptCapabilities(true),
			},
			method: "prompts/list",
			params: `{"cursor": ""}`,
			validateResponse: func(t *testing.T, responseStr string) {
				t.Helper()
				assert.NotContains(t, responseStr, `"error"`, "Should accept cursor parameter")
				assert.Contains(t, responseStr, `"prompts"`, "Should return prompts")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mcpServer := server.NewMCPServer("test-server", "1.0.0", tc.serverOptions...)
			if tc.setupServer != nil {
				tc.setupServer(mcpServer)
			}

			initializeMCPServer(t, mcpServer)
			responseStr := sendMCPRequest(t, mcpServer, tc.method, tc.params)

			tc.validateResponse(t, responseStr)
		})
	}
}

// =============================================================================
// Test Resource Read Operations
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/resources#read
// =============================================================================

// TestMCPResourceReadOperations verifies resources/read returns contents and errors for unknown URIs.
func TestMCPResourceReadOperations(t *testing.T) {
	testCases := []struct {
		name              string
		serverOptions     []server.ServerOption
		setupServer       func(*server.MCPServer)
		uri               string
		expectError       bool
		expectedErrorCode int
		validateResponse  func(t *testing.T, responseStr string)
	}{
		{
			name: "resources/read returns contents for registered resource",
			serverOptions: []server.ServerOption{
				server.WithResourceCapabilities(true, true),
			},
			setupServer: func(s *server.MCPServer) {
				resource := mcp.NewResource("file:///test.txt", "Test Resource", mcp.WithMIMEType("text/plain"))
				s.AddResource(resource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
					return []mcp.ResourceContents{
						mcp.TextResourceContents{
							URI:      "file:///test.txt",
							MIMEType: "text/plain",
							Text:     "hello world",
						},
					}, nil
				})
			},
			uri:         "file:///test.txt",
			expectError: false,
			validateResponse: func(t *testing.T, responseStr string) {
				t.Helper()
				assert.Contains(t, responseStr, `"contents"`, "Should include contents array")
				assert.Contains(t, responseStr, `"hello world"`, "Should include resource text content")
				assert.Contains(t, responseStr, `"mimeType":"text/plain"`, "Should include MIME type")
			},
		},
		{
			name: "resources/read returns resource not found for unknown URI",
			serverOptions: []server.ServerOption{
				server.WithResourceCapabilities(true, true),
			},
			uri:               "file:///missing.txt",
			expectError:       true,
			expectedErrorCode: mcp.RESOURCE_NOT_FOUND,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mcpServer := server.NewMCPServer("test-server", "1.0.0", tc.serverOptions...)
			if tc.setupServer != nil {
				tc.setupServer(mcpServer)
			}

			initializeMCPServer(t, mcpServer)

			params := `{"uri":"` + tc.uri + `"}`
			responseStr := sendMCPRequest(t, mcpServer, "resources/read", params)

			if tc.expectError {
				assert.Contains(t, responseStr, `"error"`, "Response should contain error")
				if tc.expectedErrorCode != 0 {
					var resp mcp.JSONRPCError
					require.NoError(t, json.Unmarshal([]byte(responseStr), &resp))
					assert.Equal(t, tc.expectedErrorCode, resp.Error.Code, "Error code should match")
				}
			} else {
				assert.NotContains(t, responseStr, `"error"`, "Response should not contain error")
				if tc.validateResponse != nil {
					tc.validateResponse(t, responseStr)
				}
			}
		})
	}
}

// =============================================================================
// Test Resource Template Operations
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/resources#templates
// =============================================================================

// TestMCPResourceTemplateOperations verifies templates are listed and can resolve reads.
func TestMCPResourceTemplateOperations(t *testing.T) {
	mcpServer := server.NewMCPServer(
		"test-server",
		"1.0.0",
		server.WithResourceCapabilities(true, true),
	)

	var capturedArgs map[string]any
	template := mcp.NewResourceTemplate("file:///logs/{name}.txt", "Log Template", mcp.WithTemplateDescription("Log files"))
	mcpServer.AddResourceTemplate(template, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		capturedArgs = req.Params.Arguments
		name := fmt.Sprint(req.Params.Arguments["name"])
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     "log for " + name,
			},
		}, nil
	})

	initializeMCPServer(t, mcpServer)

	// templates/list should include the registered template
	listResponse := sendMCPRequest(t, mcpServer, "resources/templates/list", `{}`)
	assert.NotContains(t, listResponse, `"error"`, "List templates should succeed")
	assert.Contains(t, listResponse, `"Log Template"`, "Should list template name")
	assert.Contains(t, listResponse, `"file:///logs/{name}.txt"`, "Should list template URI pattern")

	// resources/read should resolve the template and return content
	readParams := `{"uri":"file:///logs/app.txt"}`
	readResponse := sendMCPRequest(t, mcpServer, "resources/read", readParams)
	assert.NotContains(t, readResponse, `"error"`, "Template-backed read should succeed")
	assert.Contains(t, readResponse, `"log for`, "Response should include handler text")
	assert.Contains(t, readResponse, "app", "Template argument value should be present in response")

	require.NotNil(t, capturedArgs, "Template handler should receive arguments")
	assert.Contains(t, fmt.Sprint(capturedArgs["name"]), "app", "Template variables should be injected into arguments")
}

// =============================================================================
// Test Prompts Get Operations
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/prompts#get
// =============================================================================

// TestMCPPromptsGetOperations verifies prompts/get success and not-found error.
func TestMCPPromptsGetOperations(t *testing.T) {
	t.Run("prompts/get returns prompt with messages", func(t *testing.T) {
		mcpServer := server.NewMCPServer(
			"test-server",
			"1.0.0",
			server.WithPromptCapabilities(true),
		)

		prompt := mcp.NewPrompt(
			"test_prompt",
			mcp.WithPromptDescription("A test prompt"),
			mcp.WithArgument("subject", mcp.ArgumentDescription("Subject text"), mcp.RequiredArgument()),
		)
		mcpServer.AddPrompt(prompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			subject := req.Params.Arguments["subject"]
			return &mcp.GetPromptResult{
				Description: "Generated prompt",
				Messages: []mcp.PromptMessage{
					{
						Role: mcp.RoleUser,
						Content: mcp.TextContent{
							Type: "text",
							Text: "Subject: " + subject,
						},
					},
				},
			}, nil
		})

		initializeMCPServer(t, mcpServer)

		params := `{"name":"test_prompt","arguments":{"subject":"demo"}}`
		responseStr := sendMCPRequest(t, mcpServer, "prompts/get", params)

		assert.NotContains(t, responseStr, `"error"`, "prompts/get should succeed")
		assert.Contains(t, responseStr, `"Subject: demo"`, "Prompt handler should receive arguments")
		assert.Contains(t, responseStr, `"messages"`, "Response should include messages")
	})

	t.Run("prompts/get returns error for unknown prompt", func(t *testing.T) {
		mcpServer := server.NewMCPServer(
			"test-server",
			"1.0.0",
			server.WithPromptCapabilities(true),
		)

		initializeMCPServer(t, mcpServer)

		responseStr := sendMCPRequest(t, mcpServer, "prompts/get", `{"name":"missing_prompt"}`)
		assert.Contains(t, responseStr, `"error"`, "Unknown prompt should return error")

		var resp mcp.JSONRPCError
		require.NoError(t, json.Unmarshal([]byte(responseStr), &resp))
		assert.Equal(t, mcp.INVALID_PARAMS, resp.Error.Code, "Should return invalid params for missing prompt")
	})
}

// =============================================================================
// Test Tools Call Error Propagation
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/tools#call
// =============================================================================

// TestMCPToolsCallErrorPropagation verifies tool handler errors propagate as MCP errors.
func TestMCPToolsCallErrorPropagation(t *testing.T) {
	testCases := []struct {
		name              string
		toolHandler       func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
		expectedErrorCode int
	}{
		{
			name: "handler returning error surfaces as internal error",
			toolHandler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return nil, assert.AnError
			},
			expectedErrorCode: mcp.INTERNAL_ERROR,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mcpServer := server.NewMCPServer("test-server", "1.0.0")

			tool := mcp.NewTool("failing_tool", mcp.WithDescription("Fails on call"))
			mcpServer.AddTool(tool, tc.toolHandler)

			initializeMCPServer(t, mcpServer)

			responseStr := sendMCPRequest(t, mcpServer, "tools/call", `{"name":"failing_tool","arguments":{}}`)
			assert.Contains(t, responseStr, `"error"`, "Handler failure should surface as error")

			var resp mcp.JSONRPCError
			require.NoError(t, json.Unmarshal([]byte(responseStr), &resp))
			assert.Equal(t, tc.expectedErrorCode, resp.Error.Code, "Error code should match expected")
		})
	}
}

// =============================================================================
// Test Pagination Next Cursor
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination
// =============================================================================

// TestMCPPaginationNextCursor verifies nextCursor is returned when a limit is applied.
func TestMCPPaginationNextCursor(t *testing.T) {
	mcpServer := server.NewMCPServer(
		"test-server",
		"1.0.0",
		server.WithPaginationLimit(1),
	)

	toolA := mcp.NewTool("alpha", mcp.WithDescription("A"))
	toolB := mcp.NewTool("beta", mcp.WithDescription("B"))

	mcpServer.AddTool(toolA, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("alpha"), nil
	})
	mcpServer.AddTool(toolB, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("beta"), nil
	})

	initializeMCPServer(t, mcpServer)

	responseStr := sendMCPRequest(t, mcpServer, "tools/list", `{}`)
	assert.NotContains(t, responseStr, `"error"`, "List with pagination should succeed")
	assert.Contains(t, responseStr, `"nextCursor"`, "Response should include nextCursor when more pages exist")
	assert.NotContains(t, responseStr, `"nextCursor":""`, "nextCursor should not be empty when more items exist")
}

// =============================================================================
// Test Notifications Handling
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/basic#notifications
// =============================================================================

// TestMCPNotificationsAreIgnored verifies notifications do not produce responses.
func TestMCPNotificationsAreIgnored(t *testing.T) {
	t.Parallel()
	mcpServer := server.NewMCPServer("test-server", "1.0.0")

	notification := `{"jsonrpc":"2.0","method":"ping","params":{}}`
	response := mcpServer.HandleMessage(t.Context(), []byte(notification))
	assert.Nil(t, response, "Notifications should not return a response")
}

// =============================================================================
// Test Ping Before Initialization
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/ping
// =============================================================================

// TestMCPPingBeforeInitialization verifies ping works even before initialize.
func TestMCPPingBeforeInitialization(t *testing.T) {
	fixture := setupMCPTestFixture(t)

	pingRequest := `{"jsonrpc":"2.0","method":"ping","id":1,"params":{}}`
	response := fixture.sendRawRequest(pingRequest)
	require.NotNil(t, response, "Ping should return a response")

	responseJSON, err := json.Marshal(response)
	require.NoError(t, err)
	responseStr := string(responseJSON)

	assert.NotContains(t, responseStr, `"error"`, "Ping before initialization should not error")
	assert.Contains(t, responseStr, `"result"`, "Ping should return result")
}

// =============================================================================
// Test Tool Input Schema
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/tools#schema
// =============================================================================

// TestMCPToolInputSchema verifies tools/list returns proper JSON Schema for tool inputs.
func TestMCPToolInputSchema(t *testing.T) {
	testCases := []struct {
		name                   string
		toolName               string
		toolDescription        string
		toolSetup              func() mcp.Tool
		expectedInSchema       []string
		expectedSchemaType     string
		expectedRequiredParams []string
	}{
		{
			name:            "tool with string parameter includes inputSchema",
			toolName:        "string_param_tool",
			toolDescription: "Tool with string parameter",
			toolSetup: func() mcp.Tool {
				return mcp.NewTool("string_param_tool",
					mcp.WithDescription("Tool with string parameter"),
					mcp.WithString("input", mcp.Required(), mcp.Description("Input parameter")),
				)
			},
			expectedInSchema:       []string{`"input"`, `"string"`, `"Input parameter"`},
			expectedSchemaType:     "object",
			expectedRequiredParams: []string{"input"},
		},
		{
			name:            "tool with boolean parameter includes inputSchema",
			toolName:        "bool_param_tool",
			toolDescription: "Tool with boolean parameter",
			toolSetup: func() mcp.Tool {
				return mcp.NewTool("bool_param_tool",
					mcp.WithDescription("Tool with boolean parameter"),
					mcp.WithBoolean("enabled", mcp.Description("Enable flag")),
				)
			},
			expectedInSchema:   []string{`"enabled"`, `"boolean"`},
			expectedSchemaType: "object",
		},
		{
			name:            "tool with number parameter includes inputSchema",
			toolName:        "number_param_tool",
			toolDescription: "Tool with number parameter",
			toolSetup: func() mcp.Tool {
				return mcp.NewTool("number_param_tool",
					mcp.WithDescription("Tool with number parameter"),
					mcp.WithNumber("count", mcp.Required(), mcp.Description("Count value")),
				)
			},
			expectedInSchema:       []string{`"count"`, `"number"`},
			expectedSchemaType:     "object",
			expectedRequiredParams: []string{"count"},
		},
		{
			name:            "tool with multiple parameters includes all in inputSchema",
			toolName:        "multi_param_tool",
			toolDescription: "Tool with multiple parameters",
			toolSetup: func() mcp.Tool {
				return mcp.NewTool("multi_param_tool",
					mcp.WithDescription("Tool with multiple parameters"),
					mcp.WithString("path", mcp.Required(), mcp.Description("Path to scan")),
					mcp.WithBoolean("verbose", mcp.Description("Verbose output")),
					mcp.WithString("format", mcp.Description("Output format")),
				)
			},
			expectedInSchema:       []string{`"path"`, `"verbose"`, `"format"`},
			expectedSchemaType:     "object",
			expectedRequiredParams: []string{"path"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := setupMCPTestFixture(t)

			// Setup tool
			tool := tc.toolSetup()
			fixture.mcpServer.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return mcp.NewToolResultText("ok"), nil
			})

			fixture.initialize()
			responseStr := fixture.sendRequest("tools/list", `{}`)

			// Verify inputSchema is present and contains expected fields
			assert.Contains(t, responseStr, `"inputSchema"`, "Tool should have inputSchema")
			for _, expected := range tc.expectedInSchema {
				assert.Contains(t, responseStr, expected, "inputSchema should contain: %s", expected)
			}

			// Verify schema type is object (required by JSON Schema)
			if tc.expectedSchemaType != "" {
				assert.Contains(t, responseStr, `"type":"`+tc.expectedSchemaType+`"`,
					"inputSchema type should be %s", tc.expectedSchemaType)
			}

			// Verify required array contains expected parameters
			for _, req := range tc.expectedRequiredParams {
				assert.Contains(t, responseStr, `"`+req+`"`, "required array should contain: %s", req)
			}
		})
	}
}

// =============================================================================
// Test Tool Content Types
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/tools#content
// =============================================================================

// TestMCPToolContentTypes verifies tools/call returns proper content types.
func TestMCPToolContentTypes(t *testing.T) {
	testCases := []struct {
		name             string
		toolHandler      func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
		expectedType     string
		expectedInResult []string
	}{
		{
			name: "text content type",
			toolHandler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return mcp.NewToolResultText("Hello, World!"), nil
			},
			expectedType:     "text",
			expectedInResult: []string{`"type":"text"`, `"text":"Hello, World!"`},
		},
		{
			name: "text content with isError flag",
			toolHandler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				result := mcp.NewToolResultText("Error occurred")
				result.IsError = true
				return result, nil
			},
			expectedType:     "text",
			expectedInResult: []string{`"type":"text"`, `"isError":true`},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := setupMCPTestFixture(t)

			tool := mcp.NewTool("content_test_tool", mcp.WithDescription("Content test"))
			fixture.mcpServer.AddTool(tool, tc.toolHandler)

			fixture.initialize()
			responseStr := fixture.sendRequest("tools/call", `{"name":"content_test_tool","arguments":{}}`)

			assert.NotContains(t, responseStr, `"error"`, "Tool call should succeed")
			for _, expected := range tc.expectedInResult {
				assert.Contains(t, responseStr, expected, "Result should contain: %s", expected)
			}
		})
	}
}

// =============================================================================
// Test Resource MIME Types
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/resources#content
// =============================================================================

// TestMCPResourceMIMETypes verifies resources/read returns proper MIME types.
func TestMCPResourceMIMETypes(t *testing.T) {
	testCases := []struct {
		name         string
		resourceURI  string
		mimeType     string
		content      string
		expectedMIME string
	}{
		{
			name:         "text/plain MIME type",
			resourceURI:  "file:///test.txt",
			mimeType:     "text/plain",
			content:      "plain text content",
			expectedMIME: "text/plain",
		},
		{
			name:         "application/json MIME type",
			resourceURI:  "file:///data.json",
			mimeType:     "application/json",
			content:      `{"key": "value"}`,
			expectedMIME: "application/json",
		},
		{
			name:         "text/html MIME type",
			resourceURI:  "file:///page.html",
			mimeType:     "text/html",
			content:      "<html><body>Test</body></html>",
			expectedMIME: "text/html",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := setupMCPTestFixture(t, server.WithResourceCapabilities(true, true))

			resource := mcp.NewResource(tc.resourceURI, "Test Resource", mcp.WithMIMEType(tc.mimeType))
			fixture.mcpServer.AddResource(resource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				return []mcp.ResourceContents{
					mcp.TextResourceContents{
						URI:      tc.resourceURI,
						MIMEType: tc.mimeType,
						Text:     tc.content,
					},
				}, nil
			})

			fixture.initialize()
			responseStr := fixture.sendRequest("resources/read", `{"uri":"`+tc.resourceURI+`"}`)

			assert.NotContains(t, responseStr, `"error"`, "Resource read should succeed")
			assert.Contains(t, responseStr, `"mimeType":"`+tc.expectedMIME+`"`,
				"Response should contain correct MIME type")
			assert.Contains(t, responseStr, `"contents"`, "Response should contain contents array")
		})
	}
}

// =============================================================================
// Test Prompt Message Format
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/server/prompts#messages
// =============================================================================

// TestMCPPromptMessageFormat verifies prompts/get returns properly formatted messages.
func TestMCPPromptMessageFormat(t *testing.T) {
	testCases := []struct {
		name             string
		promptName       string
		messageRole      mcp.Role
		messageText      string
		expectedInResult []string
	}{
		{
			name:        "user role message",
			promptName:  "user_prompt",
			messageRole: mcp.RoleUser,
			messageText: "User message content",
			expectedInResult: []string{
				`"role":"user"`,
				`"type":"text"`,
				`"User message content"`,
			},
		},
		{
			name:        "assistant role message",
			promptName:  "assistant_prompt",
			messageRole: mcp.RoleAssistant,
			messageText: "Assistant message content",
			expectedInResult: []string{
				`"role":"assistant"`,
				`"type":"text"`,
				`"Assistant message content"`,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := setupMCPTestFixture(t, server.WithPromptCapabilities(true))

			prompt := mcp.NewPrompt(tc.promptName, mcp.WithPromptDescription("Test prompt"))
			fixture.mcpServer.AddPrompt(prompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
				return &mcp.GetPromptResult{
					Description: "Test prompt result",
					Messages: []mcp.PromptMessage{
						{
							Role: tc.messageRole,
							Content: mcp.TextContent{
								Type: "text",
								Text: tc.messageText,
							},
						},
					},
				}, nil
			})

			fixture.initialize()
			responseStr := fixture.sendRequest("prompts/get", `{"name":"`+tc.promptName+`"}`)

			assert.NotContains(t, responseStr, `"error"`, "Prompt get should succeed")
			assert.Contains(t, responseStr, `"messages"`, "Response should contain messages array")
			for _, expected := range tc.expectedInResult {
				assert.Contains(t, responseStr, expected, "Response should contain: %s", expected)
			}
		})
	}
}

// =============================================================================
// Test JSON-RPC Error Data Field
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/basic
// =============================================================================

// TestMCPJSONRPCErrorStructure verifies error responses follow JSON-RPC 2.0 spec.
func TestMCPJSONRPCErrorStructure(t *testing.T) {
	testCases := []struct {
		name           string
		request        string
		expectedCode   int
		validateFields func(t *testing.T, errorObj map[string]interface{})
	}{
		{
			name:         "error response has required code field",
			request:      `{"id": 1, "method": "initialize"}`, // Missing jsonrpc
			expectedCode: mcp.INVALID_REQUEST,
			validateFields: func(t *testing.T, errorObj map[string]interface{}) {
				t.Helper()
				_, hasCode := errorObj["code"]
				assert.True(t, hasCode, "Error must have code field")

				code, ok := errorObj["code"].(float64) // JSON numbers are float64
				assert.True(t, ok, "Code should be a number")
				assert.Equal(t, float64(mcp.INVALID_REQUEST), code, "Error code should match")
			},
		},
		{
			name:         "error response has required message field",
			request:      `{"jsonrpc":"2.0","id":1,"method":"unknown/method","params":{}}`,
			expectedCode: mcp.METHOD_NOT_FOUND,
			validateFields: func(t *testing.T, errorObj map[string]interface{}) {
				t.Helper()
				_, hasMessage := errorObj["message"]
				assert.True(t, hasMessage, "Error must have message field")

				message, ok := errorObj["message"].(string)
				assert.True(t, ok, "Message should be a string")
				assert.NotEmpty(t, message, "Message should not be empty")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := setupMCPTestFixture(t)
			fixture.initialize()

			response := fixture.sendRawRequest(tc.request)
			require.NotNil(t, response)

			responseJSON, err := json.Marshal(response)
			require.NoError(t, err)

			responseMap := parseJSONResponse(t, string(responseJSON))

			errorObj, hasError := responseMap["error"].(map[string]interface{})
			require.True(t, hasError, "Response should have error field")

			tc.validateFields(t, errorObj)
		})
	}
}

// =============================================================================
// Test Server Info in Initialize Response
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle#initialize
// =============================================================================

// TestMCPServerInfoInInitialize verifies initialize response contains proper server info.
func TestMCPServerInfoInInitialize(t *testing.T) {
	testCases := []struct {
		name            string
		serverName      string
		serverVersion   string
		expectedName    string
		expectedVersion string
	}{
		{
			name:            "server info contains name and version",
			serverName:      "Snyk MCP Server",
			serverVersion:   "2.1.0",
			expectedName:    "Snyk MCP Server",
			expectedVersion: "2.1.0",
		},
		{
			name:            "server info with different version format",
			serverName:      "Test Server",
			serverVersion:   "1.0.0-beta",
			expectedName:    "Test Server",
			expectedVersion: "1.0.0-beta",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mcpServer := server.NewMCPServer(tc.serverName, tc.serverVersion)

			initRequest := `{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}}}`
			response := mcpServer.HandleMessage(t.Context(), []byte(initRequest))
			require.NotNil(t, response)

			responseJSON, err := json.Marshal(response)
			require.NoError(t, err)
			responseStr := string(responseJSON)

			assert.Contains(t, responseStr, `"serverInfo"`, "Response should contain serverInfo")
			assert.Contains(t, responseStr, `"`+tc.expectedName+`"`, "serverInfo should contain name")
			assert.Contains(t, responseStr, `"`+tc.expectedVersion+`"`, "serverInfo should contain version")
		})
	}
}

// =============================================================================
// Test Capability Options
// Spec: https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle#capabilities
// =============================================================================

// TestMCPCapabilityOptions verifies specific capability options are declared correctly.
// Note: server.WithResourceCapabilities(subscribe, listChanged) parameter order
func TestMCPCapabilityOptions(t *testing.T) {
	testCases := []struct {
		name               string
		serverOptions      []server.ServerOption
		expectedContains   []string
		expectedNotContain []string
	}{
		{
			name: "resources capability with subscribe",
			serverOptions: []server.ServerOption{
				// Parameters: (subscribe, listChanged)
				server.WithResourceCapabilities(true, false),
			},
			expectedContains: []string{`"resources"`, `"subscribe":true`},
		},
		{
			name: "resources capability with listChanged",
			serverOptions: []server.ServerOption{
				// Parameters: (subscribe, listChanged)
				server.WithResourceCapabilities(false, true),
			},
			expectedContains: []string{`"resources"`, `"listChanged":true`},
		},
		{
			name: "prompts capability with listChanged",
			serverOptions: []server.ServerOption{
				server.WithPromptCapabilities(true),
			},
			expectedContains: []string{`"prompts"`, `"listChanged":true`},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mcpServer := server.NewMCPServer("test-server", "1.0.0", tc.serverOptions...)

			initRequest := `{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}}}`
			response := mcpServer.HandleMessage(t.Context(), []byte(initRequest))
			require.NotNil(t, response)

			responseJSON, err := json.Marshal(response)
			require.NoError(t, err)
			responseStr := string(responseJSON)

			for _, expected := range tc.expectedContains {
				assert.Contains(t, responseStr, expected, "Response should contain: %s", expected)
			}
			for _, notExpected := range tc.expectedNotContain {
				assert.NotContains(t, responseStr, notExpected, "Response should not contain: %s", notExpected)
			}
		})
	}
}

// =============================================================================
// Test Context Cancellation
// Spec: Proper context handling for MCP operations
// =============================================================================

// TestMCPContextCancellation verifies the server handles context cancellation gracefully.
func TestMCPContextCancellation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		request string
	}{
		{
			name:    "cancelled context during initialize",
			request: `{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}}}`,
		},
		{
			name:    "cancelled context during ping",
			request: `{"jsonrpc":"2.0","method":"ping","id":1,"params":{}}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mcpServer := server.NewMCPServer("test-server", "1.0.0")

			ctx, cancel := context.WithCancel(context.Background())
			cancel() // Cancel immediately

			// Server should handle cancelled context gracefully (not panic)
			response := mcpServer.HandleMessage(ctx, []byte(tc.request))
			t.Logf("Response with cancelled context: %v", response)
			// The response may be nil or an error, but should not panic
		})
	}
}

// =============================================================================
// Fuzz Testing for JSON-RPC Message Parsing
// Ensures parser handles malformed input without panicking
// =============================================================================

// FuzzMCPMessageParsing tests that the MCP server handles arbitrary input without panicking.
func FuzzMCPMessageParsing(f *testing.F) {
	// Add seed corpus with known valid and invalid inputs
	f.Add(`{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}}}`)
	f.Add(`{"jsonrpc":"2.0","method":"ping","id":1,"params":{}}`)
	f.Add(`{"jsonrpc":"2.0","method":"tools/list","id":1,"params":{}}`)
	f.Add(`{"invalid json`)
	f.Add(`[]`)
	f.Add(`null`)
	f.Add(`""`)
	f.Add(`{}`)
	f.Add(`{"jsonrpc":"2.0"}`)
	f.Add(`{"id":1}`)
	f.Add(`{"method":"test"}`)
	f.Add(`[{"jsonrpc":"2.0","method":"ping","id":1}]`) // Batch request
	f.Add(`{"jsonrpc":"2.0","method":"initialize","id":null,"params":{}}`)
	f.Add(`{"jsonrpc":"2.0","method":"initialize","id":"string-id","params":{}}`)

	f.Fuzz(func(t *testing.T, input string) {
		mcpServer := server.NewMCPServer("test-server", "1.0.0")

		// The server should not panic on any input
		// We don't care about the response, just that it handles input gracefully
		_ = mcpServer.HandleMessage(context.Background(), []byte(input))
	})
}
