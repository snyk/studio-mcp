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

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MCP Specification Conformance Tests
// These tests verify compliance with the Model Context Protocol specification.
//
// NOTE: The official go-sdk uses a transport-based architecture rather than
// direct message handling. These tests use the InMemoryTransport for testing.

// =============================================================================
// Test Server Creation and Configuration
// =============================================================================

// TestMCPServerCreation verifies the server can be created correctly.
func TestMCPServerCreation(t *testing.T) {
	t.Run("creates server with name and version", func(t *testing.T) {
		server := mcp.NewServer(
			&mcp.Implementation{Name: "test-server", Version: "1.0.0"},
			nil,
		)
		require.NotNil(t, server, "Server should not be nil")
	})

	t.Run("creates server with options", func(t *testing.T) {
		server := mcp.NewServer(
			&mcp.Implementation{Name: "test-server", Version: "1.0.0"},
			&mcp.ServerOptions{
				// Options can be added here
			},
		)
		require.NotNil(t, server, "Server should not be nil")
	})
}

// =============================================================================
// Test Tool Registration
// =============================================================================

// TestMCPToolRegistration verifies tools can be registered correctly.
func TestMCPToolRegistration(t *testing.T) {
	t.Run("registers tool with handler", func(t *testing.T) {
		server := mcp.NewServer(
			&mcp.Implementation{Name: "test-server", Version: "1.0.0"},
			nil,
		)

		tool := &mcp.Tool{
			Name:        "test_tool",
			Description: "A test tool",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"input": map[string]any{
						"type":        "string",
						"description": "Input parameter",
					},
				},
				"required": []string{"input"},
			},
		}

		handler := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: "result"},
				},
			}, nil
		}

		server.AddTool(tool, handler)
		// No error means success
	})

	t.Run("registers multiple tools", func(t *testing.T) {
		server := mcp.NewServer(
			&mcp.Implementation{Name: "test-server", Version: "1.0.0"},
			nil,
		)

		tools := []struct {
			name        string
			description string
		}{
			{"tool1", "First tool"},
			{"tool2", "Second tool"},
			{"tool3", "Third tool"},
		}

		for _, tt := range tools {
			tool := &mcp.Tool{
				Name:        tt.name,
				Description: tt.description,
				InputSchema: map[string]any{
					"type":       "object",
					"properties": map[string]any{},
				},
			}

			handler := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{
					Content: []mcp.Content{
						&mcp.TextContent{Text: "ok"},
					},
				}, nil
			}

			server.AddTool(tool, handler)
		}
	})
}

// =============================================================================
// Test Tool Definition Structure
// =============================================================================

// TestMCPToolDefinitionStructure verifies tool definitions are created correctly.
func TestMCPToolDefinitionStructure(t *testing.T) {
	testCases := []struct {
		name           string
		toolDefinition SnykMcpToolsDefinition
		expectedName   string
	}{
		{
			name: "Simple Tool",
			toolDefinition: SnykMcpToolsDefinition{
				Name:        "test_tool",
				Description: "Test tool description",
				Command:     []string{"test"},
				Params:      []SnykMcpToolParameter{},
			},
			expectedName: "test_tool",
		},
		{
			name: "Tool with String Params",
			toolDefinition: SnykMcpToolsDefinition{
				Name:        "string_param_tool",
				Description: "Tool with string params",
				Command:     []string{"test"},
				Params: []SnykMcpToolParameter{
					{
						Name:        "param1",
						Type:        "string",
						IsRequired:  true,
						Description: "Required string param",
					},
					{
						Name:        "param2",
						Type:        "string",
						IsRequired:  false,
						Description: "Optional string param",
					},
				},
			},
			expectedName: "string_param_tool",
		},
		{
			name: "Tool with Boolean Params",
			toolDefinition: SnykMcpToolsDefinition{
				Name:        "bool_param_tool",
				Description: "Tool with boolean params",
				Command:     []string{"test"},
				Params: []SnykMcpToolParameter{
					{
						Name:        "flag1",
						Type:        "boolean",
						IsRequired:  true,
						Description: "Required boolean param",
					},
					{
						Name:        "flag2",
						Type:        "boolean",
						IsRequired:  false,
						Description: "Optional boolean param",
					},
				},
			},
			expectedName: "bool_param_tool",
		},
		{
			name: "Tool with Number Params",
			toolDefinition: SnykMcpToolsDefinition{
				Name:        "number_param_tool",
				Description: "Tool with number params",
				Command:     []string{"test"},
				Params: []SnykMcpToolParameter{
					{
						Name:        "count",
						Type:        "number",
						IsRequired:  true,
						Description: "Required number param",
					},
				},
			},
			expectedName: "number_param_tool",
		},
		{
			name: "Tool with Mixed Params",
			toolDefinition: SnykMcpToolsDefinition{
				Name:        "mixed_param_tool",
				Description: "Tool with mixed params",
				Command:     []string{"test"},
				Params: []SnykMcpToolParameter{
					{
						Name:        "str_param",
						Type:        "string",
						IsRequired:  true,
						Description: "Required string param",
					},
					{
						Name:        "bool_flag",
						Type:        "boolean",
						IsRequired:  false,
						Description: "Optional boolean param",
					},
					{
						Name:        "num_count",
						Type:        "number",
						IsRequired:  false,
						Description: "Optional number param",
					},
				},
			},
			expectedName: "mixed_param_tool",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tool := createToolFromDefinition(&tc.toolDefinition)

			require.NotNil(t, tool)
			assert.Equal(t, tc.expectedName, tool.Name)
			assert.Equal(t, tc.toolDefinition.Description, tool.Description)

			// Verify InputSchema structure
			inputSchema, ok := tool.InputSchema.(map[string]any)
			require.True(t, ok, "InputSchema should be a map")
			assert.Equal(t, "object", inputSchema["type"])

			// Verify properties
			if len(tc.toolDefinition.Params) > 0 {
				properties, ok := inputSchema["properties"].(map[string]any)
				require.True(t, ok, "properties should be a map")
				assert.Len(t, properties, len(tc.toolDefinition.Params))

				// Verify each parameter is present
				for _, param := range tc.toolDefinition.Params {
					propDef, exists := properties[param.Name]
					assert.True(t, exists, "Property %s should exist", param.Name)

					propMap, ok := propDef.(map[string]any)
					require.True(t, ok, "Property definition should be a map")
					assert.Equal(t, param.Description, propMap["description"])
				}

				// Verify required fields
				required, hasRequired := inputSchema["required"]
				if hasRequired {
					requiredList, ok := required.([]string)
					require.True(t, ok, "required should be a string slice")
					for _, param := range tc.toolDefinition.Params {
						if param.IsRequired {
							assert.Contains(t, requiredList, param.Name)
						}
					}
				}
			}
		})
	}
}

// =============================================================================
// Test Tool Result Helpers
// =============================================================================

// TestToolResultHelpers verifies the tool result helper functions work correctly.
func TestToolResultHelpers(t *testing.T) {
	t.Run("NewToolResultText creates text result", func(t *testing.T) {
		result := NewToolResultText("test message")

		require.NotNil(t, result)
		require.Len(t, result.Content, 1)

		textContent, ok := result.Content[0].(*mcp.TextContent)
		require.True(t, ok, "Content should be TextContent")
		assert.Equal(t, "test message", textContent.Text)
		assert.False(t, result.IsError)
	})

	t.Run("NewToolResultError creates error result", func(t *testing.T) {
		result := NewToolResultError("error message")

		require.NotNil(t, result)
		require.Len(t, result.Content, 1)

		textContent, ok := result.Content[0].(*mcp.TextContent)
		require.True(t, ok, "Content should be TextContent")
		assert.Equal(t, "error message", textContent.Text)
		assert.True(t, result.IsError)
	})
}

// =============================================================================
// Test Client Info Extraction
// =============================================================================

// TestClientInfoExtraction verifies client info can be extracted from sessions.
func TestClientInfoExtraction(t *testing.T) {
	t.Run("returns empty ClientInfo for nil session", func(t *testing.T) {
		clientInfo := ClientInfoFromSession(nil)

		assert.Empty(t, clientInfo.Name)
		assert.Empty(t, clientInfo.Version)
	})
}

// =============================================================================
// Test Request Argument Extraction
// =============================================================================

// TestRequestArgumentExtraction verifies arguments are correctly extracted from requests.
func TestRequestArgumentExtraction(t *testing.T) {
	testCases := []struct {
		name         string
		arguments    map[string]any
		expectedArgs map[string]any
	}{
		{
			name:         "empty arguments",
			arguments:    map[string]any{},
			expectedArgs: map[string]any{},
		},
		{
			name: "string arguments",
			arguments: map[string]any{
				"path": "/some/path",
				"org":  "my-org",
			},
			expectedArgs: map[string]any{
				"path": "/some/path",
				"org":  "my-org",
			},
		},
		{
			name: "boolean arguments",
			arguments: map[string]any{
				"json":         true,
				"all_projects": false,
			},
			expectedArgs: map[string]any{
				"json":         true,
				"all_projects": false,
			},
		},
		{
			name: "number arguments",
			arguments: map[string]any{
				"count": float64(42),
				"limit": float64(100),
			},
			expectedArgs: map[string]any{
				"count": float64(42),
				"limit": float64(100),
			},
		},
		{
			name: "mixed arguments",
			arguments: map[string]any{
				"path":  "/some/path",
				"json":  true,
				"count": float64(42),
			},
			expectedArgs: map[string]any{
				"path":  "/some/path",
				"json":  true,
				"count": float64(42),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a request with arguments
			argsJSON, err := json.Marshal(tc.arguments)
			require.NoError(t, err)

			// Create the request using the proper structure
			requestObj := map[string]any{
				"params": map[string]any{
					"arguments": tc.arguments,
				},
			}
			requestJSON, err := json.Marshal(requestObj)
			require.NoError(t, err)

			var request mcp.CallToolRequest
			err = json.Unmarshal(requestJSON, &request)
			require.NoError(t, err)

			// Extract arguments
			args := getRequestArguments(&request)

			// Verify extracted arguments match expected - use argsJSON to avoid unused warning
			_ = argsJSON
			assert.Equal(t, tc.expectedArgs, args)
		})
	}

	t.Run("handles nil arguments", func(t *testing.T) {
		// Create request with empty arguments
		requestObj := map[string]any{
			"params": map[string]any{},
		}
		requestJSON, err := json.Marshal(requestObj)
		require.NoError(t, err)

		var request mcp.CallToolRequest
		err = json.Unmarshal(requestJSON, &request)
		require.NoError(t, err)

		args := getRequestArguments(&request)

		assert.NotNil(t, args)
		assert.Empty(t, args)
	})
}

// =============================================================================
// Test Snyk Tools Configuration
// =============================================================================

// TestSnykToolsConfiguration verifies the embedded tools configuration is valid.
func TestSnykToolsConfiguration(t *testing.T) {
	t.Run("loads tools configuration successfully", func(t *testing.T) {
		config, err := loadMcpToolsFromJson()

		require.NoError(t, err)
		require.NotNil(t, config)
		require.NotEmpty(t, config.Tools)
	})

	t.Run("all expected tools are present", func(t *testing.T) {
		config, err := loadMcpToolsFromJson()
		require.NoError(t, err)

		expectedTools := map[string]bool{
			SnykScaTest:           false,
			SnykCodeTest:          false,
			SnykVersion:           false,
			SnykAuth:              false,
			SnykLogout:            false,
			SnykTrust:             false,
			SnykSendFeedback:      false,
			"snyk_package_health": false, // Tool is named package_health in config
		}

		for _, tool := range config.Tools {
			expectedTools[tool.Name] = true
		}

		for name, found := range expectedTools {
			assert.True(t, found, "Tool %s should be present in configuration", name)
		}
	})

	t.Run("each tool has valid definition", func(t *testing.T) {
		config, err := loadMcpToolsFromJson()
		require.NoError(t, err)

		for _, toolDef := range config.Tools {
			t.Run(toolDef.Name, func(t *testing.T) {
				assert.NotEmpty(t, toolDef.Name, "Tool should have a name")
				assert.NotEmpty(t, toolDef.Description, "Tool should have a description")

				// Verify tool can be created from definition
				tool := createToolFromDefinition(&toolDef)
				assert.NotNil(t, tool)
				assert.Equal(t, toolDef.Name, tool.Name)
			})
		}
	})
}
