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
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/snyk/studio-mcp/internal/authentication"
	"github.com/snyk/studio-mcp/internal/trust"
	"github.com/snyk/studio-mcp/shared"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type testFixture struct {
	t                 *testing.T
	mockEngine        *mocks.MockEngine
	binding           *McpLLMBinding
	snykCliPath       string
	invocationContext *mocks.MockInvocationContext
	tools             *SnykMcpTools
}

func SetupEngineMock(t *testing.T) (*mocks.MockEngine, configuration.Configuration) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockEngine := mocks.NewMockEngine(ctrl)
	engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	return mockEngine, engineConfig
}

func setupTestFixture(t *testing.T) *testFixture {
	t.Helper()
	engine, engineConfig := SetupEngineMock(t)
	logger := zerolog.New(io.Discard)

	mockctl := gomock.NewController(t)
	storage := mocks.NewMockStorage(mockctl)
	engineConfig.SetStorage(storage)

	invocationCtx := mocks.NewMockInvocationContext(mockctl)
	invocationCtx.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationCtx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New(runtimeinfo.WithName("hurz"), runtimeinfo.WithVersion("1000.8.3"))).AnyTimes()
	invocationCtx.EXPECT().GetEngine().Return(engine).AnyTimes()

	// Mock network access for updateGafConfigWithIntegrationEnvironment (GetNetworkAccess, RemoveHeaderField, AddHeaderField)
	mockNetworkAccess := mocks.NewMockNetworkAccess(mockctl)
	mockNetworkAccess.EXPECT().RemoveHeaderField("User-Agent").AnyTimes()
	mockNetworkAccess.EXPECT().AddHeaderField("User-Agent", gomock.Any()).AnyTimes()
	mockNetworkAccess.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()
	invocationCtx.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()
	engine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()

	engine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	_, expectedUserData := whoamiWorkflowResponse(t)
	engine.EXPECT().InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, gomock.Any()).Return(expectedUserData, nil).AnyTimes()
	// Snyk CLI mock
	tempDir := t.TempDir()
	snykCliPath := filepath.Join(tempDir, "snyk")
	if runtime.GOOS == "windows" {
		snykCliPath += ".bat"
	}

	// Create a default mock CLI that just echoes the command
	defaultMockResponse := "{\"ok\": true}"
	createMockSnykCli(t, snykCliPath, defaultMockResponse)

	engineConfig.Set(trust.DisableTrustFlag, true)

	// Create the binding
	binding := NewMcpLLMBinding(WithCliPath(snykCliPath), WithLogger(invocationCtx.GetEnhancedLogger()))
	binding.folderTrust = trust.NewFolderTrust(&logger, invocationCtx.GetConfiguration())
	binding.mcpServer = server.NewMCPServer("Snyk", "1.1.1")

	tools, err := loadMcpToolsFromJson()
	require.NoError(t, err)
	return &testFixture{
		t:                 t,
		mockEngine:        engine,
		binding:           binding,
		snykCliPath:       snykCliPath,
		invocationContext: invocationCtx,
		tools:             tools,
	}
}

func (f *testFixture) mockCliOutput(output string) {
	createMockSnykCli(f.t, f.snykCliPath, output)
}

func getToolWithName(t *testing.T, tools *SnykMcpTools, toolName string) *SnykMcpToolsDefinition {
	t.Helper()
	for _, tool := range tools.Tools {
		if tool.Name == toolName {
			return &tool
		}
	}
	return nil
}

func TestMcpSnykToolRegistration(t *testing.T) {
	fixture := setupTestFixture(t)
	err := fixture.binding.addSnykTools(fixture.invocationContext, ProfileFull)
	require.NoError(t, err)
}

func TestSnykTestHandler(t *testing.T) {
	// Setup
	fixture := setupTestFixture(t)

	// Configure mock CLI to return a specific JSON response
	mockOutput := `[{"ok": false,"vulnerabilities": [{"id": "SNYK-JS-ACORN-559469","title": "Regular Expression Denial of Service (ReDoS)","severity":"high","packageName": "acorn","version": "5.5.3","identifiers": {"CVE": ["CVE-2020-7598"],"CWE": ["CWE-400"]},"fixedIn": ["5.7.4", "6.4.1", "7.1.1"],"isUpgradable": true,"isPatchable": false,"upgradePath": ["my-app@1.0.0", "acorn@7.1.1"],"from": ["my-app@1.0.0", "acorn@5.5.3"],"packageManager": "npm"},{"id": "SNYK-JS-TUNNELAGENT-1572284","title": "Uninitialized Memory Exposure","severity": "medium","packageName": "tunnel-agent","version": "0.6.0","identifiers": {"CVE": [],"CWE": ["CWE-201"]},"fixedIn": [],"isUpgradable": false,"isPatchable": false,"upgradePath": [],"from": ["my-app@1.0.0", "tunnel-agent@0.6.0"],"packageManager": "npm"}],"dependencyCount": 42,"packageManager": "npm"}]`
	fixture.mockCliOutput(mockOutput)
	tool := getToolWithName(t, fixture.tools, ToolName.ScaTest)
	require.NotNil(t, tool)
	// Create the handler
	handler := fixture.binding.defaultHandler(fixture.invocationContext, *tool)

	tmpDir := t.TempDir()
	// Define test cases
	testCases := []struct {
		name string
		args map[string]any
	}{
		{
			name: "Basic SCA Test",
			args: map[string]any{
				"path":         tmpDir,
				"all_projects": true,
				"json":         true,
			},
		},
		{
			name: "Test with PreferredOrg",
			args: map[string]any{
				"path":         tmpDir,
				"all_projects": true,
				"json":         true,
				"org":          "my-snyk-org",
			},
		},
		{
			name: "Test with Severity Threshold",
			args: map[string]any{
				"path":               tmpDir,
				"all_projects":       false,
				"json":               true,
				"severity_threshold": "high",
			},
		},
		{
			name: "Test with Multiple Options",
			args: map[string]any{
				"path":                           tmpDir,
				"all_projects":                   true,
				"json":                           true,
				"severity_threshold":             "medium",
				"dev":                            true,
				"skip_unresolved":                true,
				"prune_repeated_subdependencies": true,
				"fail_on":                        "upgradable",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestObj := map[string]any{
				"params": map[string]any{
					"arguments": tc.args,
				},
			}
			requestJSON, err := json.Marshal(requestObj)
			require.NoError(t, err, "Failed to marshal request to JSON")

			// Parse the JSON string to CallToolRequest
			var request mcp.CallToolRequest
			err = json.Unmarshal(requestJSON, &request)
			require.NoError(t, err, "Failed to unmarshal JSON to CallToolRequest")

			result, err := handler(t.Context(), request)

			require.NoError(t, err)
			require.NotNil(t, result)

			textContent, ok := result.Content[0].(mcp.TextContent)
			require.True(t, ok)
			content := strings.TrimSpace(textContent.Text)

			// Parse the enhanced JSON response
			var enhanced EnhancedScanResult
			err = json.Unmarshal([]byte(content), &enhanced)
			require.NoError(t, err, "Failed to parse enhanced scan result")

			// Debug output
			t.Logf("Enhanced result: %+v", enhanced)
			if len(enhanced.Issues) > 0 {
				t.Logf("First issue: %+v", enhanced.Issues[0])
			}

			// Check that we have both original output and issue data
			require.True(t, enhanced.Success)
			require.Equal(t, 2, enhanced.IssueCount)
			require.Len(t, enhanced.Issues, 2)

			// Verify we extracted the issues successfully
			// The actual issue verification is done in the dedicated test
		})
	}
}

func TestSnykCodeTestHandler(t *testing.T) {
	// Setup
	fixture := setupTestFixture(t)

	// Configure mock CLI with SARIF response
	mockJsonResponse := `{"runs":[{"tool":{"driver":{"rules":[{"id":"javascript/DangerousEval","shortDescription":{"text":"Code Injection"},"properties":{"cwe":["CWE-94","CWE-95"],"categories":["Security"]}}]}},"results":[{"ruleId":"javascript/DangerousEval","level":"warning","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/app.js"},"region":{"startLine":10,"startColumn":5}}}]}]}]}`
	fixture.mockCliOutput(mockJsonResponse)

	// Get the tool definition
	toolDef := getToolWithName(t, fixture.tools, ToolName.CodeTest)

	// Create the handler
	handler := fixture.binding.defaultHandler(fixture.invocationContext, *toolDef)
	tmpDir := t.TempDir()
	// Test cases with various combinations of convertedToolParams
	testCases := []struct {
		name         string
		args         map[string]any
		requireTrust bool
	}{
		{
			name: "Basic Test",
			args: map[string]any{
				"path": tmpDir,
			},
		},
		{
			name: "Test with Custom File",
			args: map[string]any{
				"path": tmpDir,
				"file": "specific_file.js",
			},
		},
		{
			name: "Test with Severity Threshold",
			args: map[string]any{
				"path":               tmpDir,
				"severity_threshold": "high",
			},
		},
		{
			name: "Test with PreferredOrg",
			args: map[string]any{
				"path": tmpDir,
				"org":  "my-snyk-org",
			},
		},
		{
			name: "Test with All Options",
			args: map[string]any{
				"path":               tmpDir,
				"file":               "specific_file.js",
				"severity_threshold": "high",
				"org":                "my-snyk-org",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestObj := map[string]any{
				"params": map[string]any{
					"arguments": tc.args,
				},
			}
			fixture.invocationContext.GetConfiguration().Set(trust.DisableTrustFlag, !tc.requireTrust)
			requestJSON, err := json.Marshal(requestObj)
			require.NoError(t, err, "Failed to marshal request to JSON")

			var request mcp.CallToolRequest
			err = json.Unmarshal(requestJSON, &request)
			require.NoError(t, err, "Failed to unmarshal JSON to CallToolRequest")

			result, err := handler(t.Context(), request)
			require.NoError(t, err)
			require.NotNil(t, result)
			textContent, ok := result.Content[0].(mcp.TextContent)
			require.True(t, ok)
			content := strings.TrimSpace(textContent.Text)

			// Parse the enhanced JSON response
			var enhanced EnhancedScanResult
			err = json.Unmarshal([]byte(content), &enhanced)
			require.NoError(t, err, "Failed to parse enhanced scan result")

			// Check that we have both original output and issue data
			require.True(t, enhanced.Success)
			require.Equal(t, 1, enhanced.IssueCount)
			require.Len(t, enhanced.Issues, 1)

			// Verify we extracted the issues successfully
			// The actual issue verification is done in the dedicated test
		})
	}
}

func TestSnykCodeAutoEnablement(t *testing.T) {
	// Test the two-phase Snyk Code enablement feature:
	// Phase 1: First call returns a prompt asking user for confirmation
	// Phase 2: Second call (after user confirms) enables Snyk Code and retries scan
	fixture := setupTestFixture(t)
	tmpDir := t.TempDir()

	// Get the tool definition
	toolDef := getToolWithName(t, fixture.tools, ToolName.CodeTest)
	require.NotNil(t, toolDef, "snyk_code_scan tool definition not found")

	t.Run("First call prompts user for confirmation", func(t *testing.T) {
		// Clear any previous state
		delete(snykCodeEnablementPrompted, "test-org-prompt")

		createMockSnykCliWithScript(t, fixture.snykCliPath, mockCliScriptAlwaysError("Error: snyk-code-0005: Snyk Code is not enabled"))

		config := fixture.invocationContext.GetConfiguration()
		config.Set(configuration.ORGANIZATION, "test-org-prompt")
		config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
		config.Set(configuration.WEB_APP_URL, "https://app.snyk.io")

		handler := fixture.binding.defaultHandler(fixture.invocationContext, *toolDef)

		requestObj := map[string]any{
			"params": map[string]any{
				"arguments": map[string]any{
					"path": tmpDir,
				},
			},
		}
		requestJSON, err := json.Marshal(requestObj)
		require.NoError(t, err)

		var request mcp.CallToolRequest
		err = json.Unmarshal(requestJSON, &request)
		require.NoError(t, err)

		result, err := handler(context.Background(), request)
		require.NoError(t, err)

		var resultText string
		if result != nil && len(result.Content) > 0 {
			textContent, ok := result.Content[0].(mcp.TextContent)
			require.True(t, ok)
			resultText = textContent.Text
		}

		// Should return a prompt asking for confirmation
		require.Contains(t, resultText, "IMPORTANT: Ask the user")
		require.Contains(t, resultText, "Would you like me to enable it")
		require.Contains(t, resultText, "If the user says YES")
		require.Contains(t, resultText, "If the user says NO")
		require.Contains(t, resultText, "disable the snyk_code_scan tool")
		// Should NOT attempt enablement yet
		require.NotContains(t, resultText, "Attempting to enable Snyk Code for organization")
	})

	t.Run("Second call enables Snyk Code and retries scan", func(t *testing.T) {
		// Simulate that we already prompted for this org (user said yes and called again)
		snykCodeEnablementPrompted["test-org-enable"] = true

		createMockSnykCliWithScript(t, fixture.snykCliPath, mockCliScriptErrorThenSuccess())

		apiURL := createMockAPIServer(t, 201, map[string]interface{}{
			"data": map[string]interface{}{
				"type": "sast_settings",
				"id":   "test-org-enable",
				"attributes": map[string]interface{}{
					"sast_enabled": true,
				},
			},
		})

		config := fixture.invocationContext.GetConfiguration()
		config.Set(configuration.ORGANIZATION, "test-org-enable")
		config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
		config.Set(configuration.WEB_APP_URL, "https://app.snyk.io")
		config.Set(configuration.API_URL, apiURL)

		handler := fixture.binding.defaultHandler(fixture.invocationContext, *toolDef)

		requestObj := map[string]any{
			"params": map[string]any{
				"arguments": map[string]any{
					"path": tmpDir,
				},
			},
		}
		requestJSON, err := json.Marshal(requestObj)
		require.NoError(t, err)

		var request mcp.CallToolRequest
		err = json.Unmarshal(requestJSON, &request)
		require.NoError(t, err)

		result, err := handler(context.Background(), request)
		require.NoError(t, err)

		var resultText string
		if result != nil && len(result.Content) > 0 {
			textContent, ok := result.Content[0].(mcp.TextContent)
			require.True(t, ok)
			resultText = textContent.Text
		}

		// Should attempt enablement and retry
		require.Contains(t, resultText, "Attempting to enable Snyk Code for organization")
		require.Contains(t, resultText, "Snyk Code has been successfully enabled")
		require.Contains(t, resultText, "Running scan")
	})

	t.Run("Enable fails with 403 - provides manual instructions", func(t *testing.T) {
		// Simulate that we already prompted (user said yes and called again)
		snykCodeEnablementPrompted["test-org-403"] = true

		createMockSnykCliWithScript(t, fixture.snykCliPath, mockCliScriptAlwaysError("Error: snyk-code-0005: Snyk Code is disabled"))

		apiURL := createMockAPIServer(t, 403, map[string]interface{}{
			"errors": []interface{}{
				map[string]interface{}{
					"status": "403",
					"detail": "Forbidden",
				},
			},
		})

		config := fixture.invocationContext.GetConfiguration()
		config.Set(configuration.ORGANIZATION, "test-org-403")
		config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
		config.Set(configuration.WEB_APP_URL, "https://app.snyk.io")
		config.Set(configuration.API_URL, apiURL)

		handler := fixture.binding.defaultHandler(fixture.invocationContext, *toolDef)

		requestObj := map[string]any{
			"params": map[string]any{
				"arguments": map[string]any{
					"path": tmpDir,
				},
			},
		}
		requestJSON, err := json.Marshal(requestObj)
		require.NoError(t, err)

		var request mcp.CallToolRequest
		err = json.Unmarshal(requestJSON, &request)
		require.NoError(t, err)

		result, err := handler(context.Background(), request)
		require.NoError(t, err)

		var resultText string
		if result != nil && len(result.Content) > 0 {
			textContent, ok := result.Content[0].(mcp.TextContent)
			require.True(t, ok)
			resultText = textContent.Text
		}

		require.Contains(t, resultText, "snyk-code-0005")
		require.Contains(t, resultText, "Attempting to enable Snyk Code for organization")
		require.Contains(t, resultText, "Failed to enable Snyk Code")
		require.Contains(t, resultText, "API request failed with status 403")
		require.Contains(t, resultText, "To activate Snyk Code manually")
	})

	t.Run("Enable succeeds but retry also fails", func(t *testing.T) {
		// Simulate that we already prompted (user said yes and called again)
		snykCodeEnablementPrompted["test-org-retry-fail"] = true

		createMockSnykCliWithScript(t, fixture.snykCliPath, mockCliScriptAlwaysError("Error: snyk-code-0005: Snyk Code is not enabled"))

		apiURL := createMockAPIServer(t, 201, map[string]interface{}{
			"data": map[string]interface{}{
				"type": "sast_settings",
				"id":   "test-org-retry-fail",
				"attributes": map[string]interface{}{
					"sast_enabled": true,
				},
			},
		})

		config := fixture.invocationContext.GetConfiguration()
		config.Set(configuration.ORGANIZATION, "test-org-retry-fail")
		config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
		config.Set(configuration.WEB_APP_URL, "https://app.snyk.io")
		config.Set(configuration.API_URL, apiURL)

		handler := fixture.binding.defaultHandler(fixture.invocationContext, *toolDef)

		requestObj := map[string]any{
			"params": map[string]any{
				"arguments": map[string]any{
					"path": tmpDir,
				},
			},
		}
		requestJSON, err := json.Marshal(requestObj)
		require.NoError(t, err)

		var request mcp.CallToolRequest
		err = json.Unmarshal(requestJSON, &request)
		require.NoError(t, err)

		result, err := handler(context.Background(), request)
		require.NoError(t, err)

		var resultText string
		if result != nil && len(result.Content) > 0 {
			textContent, ok := result.Content[0].(mcp.TextContent)
			require.True(t, ok)
			resultText = textContent.Text
		}

		require.Contains(t, resultText, "Attempting to enable Snyk Code for organization")
		require.Contains(t, resultText, "Snyk Code has been successfully enabled")
		require.Contains(t, resultText, "Running scan")
		require.Contains(t, resultText, "Scan failed")
	})

	t.Run("Missing org ID - provides manual instructions without prompting", func(t *testing.T) {
		createMockSnykCliWithScript(t, fixture.snykCliPath, mockCliScriptAlwaysError("Error: snyk-code-0005: Snyk Code is not enabled"))

		config := fixture.invocationContext.GetConfiguration()
		config.Set(configuration.ORGANIZATION, "")
		config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
		config.Set(configuration.WEB_APP_URL, "https://app.snyk.io")

		handler := fixture.binding.defaultHandler(fixture.invocationContext, *toolDef)

		requestObj := map[string]any{
			"params": map[string]any{
				"arguments": map[string]any{
					"path": tmpDir,
				},
			},
		}
		requestJSON, err := json.Marshal(requestObj)
		require.NoError(t, err)

		var request mcp.CallToolRequest
		err = json.Unmarshal(requestJSON, &request)
		require.NoError(t, err)

		result, err := handler(context.Background(), request)
		require.NoError(t, err)

		var resultText string
		if result != nil && len(result.Content) > 0 {
			textContent, ok := result.Content[0].(mcp.TextContent)
			require.True(t, ok)
			resultText = textContent.Text
		}

		require.Contains(t, resultText, "snyk-code-0005")
		require.Contains(t, resultText, "To activate Snyk Code")
		// Should NOT attempt enablement or ask for confirmation when no org ID
		require.NotContains(t, resultText, "IMPORTANT: Ask the user")
		require.NotContains(t, resultText, "Attempting to enable Snyk Code for organization")
	})
}

func TestBasicSnykCommands(t *testing.T) {
	// Setup
	fixture := setupTestFixture(t)

	testCases := []struct {
		name         string
		handlerFunc  func(invocationCtx workflow.InvocationContext, toolDefinition SnykMcpToolsDefinition) func(ctx context.Context, arguments mcp.CallToolRequest) (*mcp.CallToolResult, error)
		mockResponse string
		expectedCmd  string
		command      []string
	}{
		{
			name:         "Version Command",
			handlerFunc:  fixture.binding.defaultHandler,
			command:      []string{"--version"},
			mockResponse: `{"client":{"version":"1.1192.0"}}`,
			expectedCmd:  "version",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Configure mock CLI
			fixture.mockCliOutput(tc.mockResponse)

			// Create the handler
			handler := tc.handlerFunc(fixture.invocationContext, SnykMcpToolsDefinition{Command: tc.command})

			// Create an empty request object as JSON string
			requestObj := map[string]any{
				"params": map[string]any{
					"arguments": map[string]any{},
				},
			}
			requestJSON, err := json.Marshal(requestObj)
			require.NoError(t, err, "Failed to marshal request to JSON")

			// Parse the JSON string to CallToolRequest
			var request mcp.CallToolRequest
			err = json.Unmarshal(requestJSON, &request)
			require.NoError(t, err, "Failed to unmarshal JSON to CallToolRequest")

			// Call the handler
			result, err := handler(t.Context(), request)

			// Assertions
			require.NoError(t, err)
			require.NotNil(t, result)
			textContent, ok := result.Content[0].(mcp.TextContent)
			require.True(t, ok)
			require.Equal(t, tc.mockResponse, strings.TrimSpace(textContent.Text))
		})
	}
}

func TestAuthHandler(t *testing.T) {
	// Setup
	fixture := setupTestFixture(t)

	// Configure mock CLI
	mockAuthResponse := "Authenticated Successfully"
	fixture.mockCliOutput(mockAuthResponse)

	// Create the handler
	handler := fixture.binding.defaultHandler(fixture.invocationContext, SnykMcpToolsDefinition{Command: []string{"auth"}})

	requestObj := map[string]any{
		"params": map[string]any{
			"arguments": map[string]any{},
		},
	}
	requestJSON, err := json.Marshal(requestObj)
	require.NoError(t, err, "Failed to marshal request to JSON")

	var request mcp.CallToolRequest
	err = json.Unmarshal(requestJSON, &request)
	require.NoError(t, err, "Failed to unmarshal JSON to CallToolRequest")

	result, err := handler(t.Context(), request)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	textContent, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)
	require.Equal(t, mockAuthResponse, strings.TrimSpace(textContent.Text))
}

func TestGetSnykToolsConfig(t *testing.T) {
	config, err := loadMcpToolsFromJson()

	require.NoError(t, err)
	require.NotNil(t, config)
	require.NotEmpty(t, config.Tools)

	toolNames := map[string]bool{
		ToolName.ScaTest:  false,
		ToolName.CodeTest: false,
		ToolName.Version:  false,
		ToolName.Auth:     false,
		ToolName.Logout:   false,
	}

	for _, tool := range config.Tools {
		toolNames[tool.Name] = true
	}

	for name, found := range toolNames {
		require.True(t, found, "Tool %s not found in configuration", name)
	}
}

// TestSnykToolsJSONToolAnnotations ensures snyk_tools.json advertises
// mimimum recommended MCP tool annotations.
func TestSnykToolsJSONToolAnnotations(t *testing.T) {
	var root struct {
		Tools []json.RawMessage `json:"tools"`
	}
	err := json.Unmarshal([]byte(snykToolsJson), &root)
	require.NoError(t, err, "embedded snyk_tools.json must be valid JSON")

	requiredKeys := []string{
		"readOnlyHint",
		"destructiveHint",
		"openWorldHint",
		"idempotentHint",
	}

	for i, rawTool := range root.Tools {
		var tool struct {
			Name        string          `json:"name"`
			Annotations json.RawMessage `json:"annotations"`
		}
		err = json.Unmarshal(rawTool, &tool)
		require.NoError(t, err, "tool index %d", i)
		require.NotEmpty(t, tool.Name, "tool index %d must have name", i)
		require.NotEmpty(t, tool.Annotations, "tool %q must have a non-empty annotations object", tool.Name)

		var ann map[string]json.RawMessage
		err = json.Unmarshal(tool.Annotations, &ann)
		require.NoError(t, err, "tool %q annotations must be a JSON object", tool.Name)

		for _, key := range requiredKeys {
			rawVal, ok := ann[key]
			require.True(t, ok, "tool %q must include annotation %q", tool.Name, key)
			var b bool
			err = json.Unmarshal(rawVal, &b)
			require.NoError(t, err, "tool %q annotation %q must be a JSON boolean", tool.Name, key)
		}
	}
}

func TestCreateToolFromDefinition(t *testing.T) {
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
				Description: "Tool with string convertedToolParams",
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
				Description: "Tool with boolean convertedToolParams",
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
			name: "Tool with Mixed Params",
			toolDefinition: SnykMcpToolsDefinition{
				Name:        "mixed_param_tool",
				Description: "Tool with mixed convertedToolParams",
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
				},
			},
			expectedName: "mixed_param_tool",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tool := createToolFromDefinition(&tc.toolDefinition)

			require.NotNil(t, tool)
			require.Equal(t, tc.expectedName, tool.Name)
		})
	}
}

func TestExtractParamsFromRequest(t *testing.T) {
	dir := t.TempDir()
	testCases := []struct {
		name               string
		toolDef            SnykMcpToolsDefinition
		requestArgs        map[string]any
		expectedParamCount int
		expectedWorkingDir string
		expectedParams     map[string]any
	}{
		{
			name: "Empty Request",
			toolDef: SnykMcpToolsDefinition{
				Name:   "test_tool",
				Params: []SnykMcpToolParameter{},
			},
			requestArgs:        map[string]any{},
			expectedParamCount: 0,
			expectedWorkingDir: "",
			expectedParams:     map[string]any{},
		},
		{
			name: "String Parameters",
			toolDef: SnykMcpToolsDefinition{
				Name: "string_tool",
				Params: []SnykMcpToolParameter{
					{
						Name: "org",
						Type: "string",
					},
					{
						Name: "path",
						Type: "string",
					},
				},
			},
			requestArgs: map[string]any{
				"org":  "my-org",
				"path": dir,
			},
			expectedParamCount: 2,
			expectedWorkingDir: dir,
			expectedParams: map[string]any{
				"org":  "my-org",
				"path": dir,
			},
		},
		{
			name: "Boolean Parameters",
			toolDef: SnykMcpToolsDefinition{
				Name: "bool_tool",
				Params: []SnykMcpToolParameter{
					{
						Name: "json",
						Type: "boolean",
					},
					{
						Name: "all_projects",
						Type: "boolean",
					},
				},
			},
			requestArgs: map[string]any{
				"json":         true,
				"all_projects": true,
			},
			expectedParamCount: 2,
			expectedWorkingDir: "",
			expectedParams: map[string]any{
				"json":         true,
				"all-projects": true,
			},
		},
		{
			name: "Mixed Parameters",
			toolDef: SnykMcpToolsDefinition{
				Name: "mixed_tool",
				Params: []SnykMcpToolParameter{
					{
						Name: "path",
						Type: "string",
					},
					{
						Name: "json",
						Type: "boolean",
					},
					{
						Name: "severity_threshold",
						Type: "string",
					},
				},
			},
			requestArgs: map[string]any{
				"path":               dir,
				"json":               true,
				"severity_threshold": "high",
			},
			expectedParamCount: 3,
			expectedWorkingDir: dir,
			expectedParams: map[string]any{
				"path":               dir,
				"json":               true,
				"severity-threshold": "high",
			},
		},
		{
			name: "Empty String Parameters",
			toolDef: SnykMcpToolsDefinition{
				Name: "empty_string_tool",
				Params: []SnykMcpToolParameter{
					{
						Name: "org",
						Type: "string",
					},
				},
			},
			requestArgs: map[string]any{
				"org": "",
			},
			expectedParamCount: 0,
			expectedWorkingDir: "",
			expectedParams:     map[string]any{},
		},
		{
			name: "False Boolean Parameters",
			toolDef: SnykMcpToolsDefinition{
				Name: "false_bool_tool",
				Params: []SnykMcpToolParameter{
					{
						Name: "all_projects",
						Type: "boolean",
					},
				},
			},
			requestArgs: map[string]any{
				"all-projects": false,
			},
			expectedParamCount: 0,
			expectedWorkingDir: "",
			expectedParams:     map[string]any{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, workingDir, err := normalizeParamsAndDetermineWorkingDir(tc.toolDef, tc.requestArgs)
			require.NoError(t, err)
			require.Equal(t, tc.expectedWorkingDir, workingDir)

			// assert only empty string parameters are there if we don't expect any - they'll be filtered in buildArgs
			if tc.expectedParamCount == 0 {
				for _, parameter := range params {
					if strings.ToLower(parameter.Type) == "string" {
						require.Equalf(t, "", parameter.value, "Parameter %s should not be set", parameter.Name)
					} else {
						require.Failf(t, "Parameter %s should not be set", parameter.Name)
					}
				}
			}

			// assert each of the expected parameters is set
			for key, value := range tc.expectedParams {
				positional := false
				for _, param := range tc.toolDef.Params {
					if param.Name == key && param.IsPositional {
						positional = true
						break
					}
				}

				if positional {
					continue
				}

				expectedKey := strings.ReplaceAll(key, "_", "-")
				actualValue, ok := params[expectedKey]
				require.True(t, ok, "Parameter %s not found", expectedKey)
				require.Equal(t, value, actualValue.value)
			}
		})
	}
}

func TestBuildCommand(t *testing.T) {
	testCases := []struct {
		name                string
		cliPath             string
		command             []string
		convertedToolParams map[string]convertedToolParameter
		expected            []string
	}{
		{
			name:                "No Parameters",
			cliPath:             "snyk",
			command:             []string{"test"},
			convertedToolParams: map[string]convertedToolParameter{},
			expected:            []string{"snyk", "test"},
		},
		{
			name:    "String Parameters",
			cliPath: "snyk",
			command: []string{"test"},
			convertedToolParams: map[string]convertedToolParameter{
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "my-org",
				},
				"file": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "file",
						Type: "string",
					},
					value: "package.json",
				},
			},
			expected: []string{"snyk", "test", "--org=my-org", "--file=package.json"},
		},
		{
			name:    "Boolean Parameters",
			cliPath: "snyk",
			command: []string{"test"},
			convertedToolParams: map[string]convertedToolParameter{
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: true,
				},
			},
			expected: []string{"snyk", "test", "--all-projects"},
		},
		{
			name:    "Mixed Parameters",
			cliPath: "snyk",
			command: []string{"test"},
			convertedToolParams: map[string]convertedToolParameter{
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "my-org",
				},
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: true,
				},
			},
			expected: []string{"snyk", "test", "--org=my-org", "--all-projects"},
		},
		{
			name:    "Empty String Parameters",
			cliPath: "snyk",
			command: []string{"test"},
			convertedToolParams: map[string]convertedToolParameter{
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "",
				},
			},
			expected: []string{"snyk", "test"},
		},
		{
			name:    "False Boolean Parameters",
			cliPath: "snyk",
			command: []string{"test"},
			convertedToolParams: map[string]convertedToolParameter{
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: false,
				},
			},
			expected: []string{"snyk", "test"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := buildCommand(tc.cliPath, tc.command, tc.convertedToolParams)
			for _, arg := range tc.expected {
				require.Contains(t, args, arg)
			}
			require.Len(t, tc.expected, len(args))
		})
	}
}

func TestRunSnyk(t *testing.T) {
	fixture := setupTestFixture(t)

	ctx := t.Context()

	testCases := []struct {
		name        string
		mockOutput  string
		command     []string
		workingDir  string
		expectError bool
	}{
		{
			name:        "Successful Command",
			mockOutput:  "Command executed successfully",
			command:     []string{fixture.snykCliPath, "test"},
			workingDir:  "",
			expectError: false,
		},
		{
			name:        "Command with Working Directory",
			mockOutput:  "Command executed successfully",
			command:     []string{fixture.snykCliPath, "test"},
			workingDir:  t.TempDir(),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture.mockCliOutput(tc.mockOutput)

			output, err := fixture.binding.runSnyk(ctx, fixture.invocationContext, tc.workingDir, tc.command)

			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.mockOutput, strings.TrimSpace(output))
			}
		})
	}
}

func createMockSnykCli(t *testing.T, path, output string) {
	t.Helper()

	var script string

	if runtime.GOOS == "windows" {
		script = fmt.Sprintf(`@echo off
echo %s
exit /b 0
`, output)
	} else {
		script = fmt.Sprintf(`#!/bin/sh
echo '%s'
exit 0
`, output)
	}

	err := os.WriteFile(path, []byte(script), 0755)
	require.NoError(t, err)
}

// createMockAPIServer creates a mock HTTP server that simulates the Snyk REST API
func createMockAPIServer(t *testing.T, statusCode int, response map[string]interface{}) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(statusCode)
		if response != nil {
			_ = json.NewEncoder(w).Encode(response)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// createMockSnykCliWithScript creates a mock Snyk CLI with custom script logic
func createMockSnykCliWithScript(t *testing.T, path, scriptContent string) {
	t.Helper()

	var script string

	if runtime.GOOS == "windows" {
		// Convert bash script to batch script for Windows
		script = `@echo off
echo Error: snyk-code-0005: Snyk Code is not enabled
exit /b 2
`
	} else {
		script = scriptContent
	}

	err := os.WriteFile(path, []byte(script), 0755)
	require.NoError(t, err)
}

// mockCliScriptErrorThenSuccess returns a bash script that errors on first call, succeeds on retry
func mockCliScriptErrorThenSuccess() string {
	return `#!/bin/bash
# Use a unique temp file for this test run
FLAG_FILE="/tmp/snyk_test_retry_$$"

# First invocation returns error with exit code 2
if [ ! -f "$FLAG_FILE" ]; then
  touch "$FLAG_FILE"
  # Output to stderr to match real CLI behavior
  echo "Error: snyk-code-0005: Snyk Code is not enabled for organization" >&2
  exit 2
fi

# Second invocation (retry) returns success
rm -f "$FLAG_FILE"
echo '{"runs":[{"tool":{"driver":{"rules":[]}},"results":[]}]}'
exit 0
`
}

// mockCliScriptAlwaysError returns a bash script that always errors
func mockCliScriptAlwaysError(errorMsg string) string {
	// Output to stderr to match real CLI behavior
	return fmt.Sprintf(`#!/bin/bash
echo "%s" >&2
exit 2
`, errorMsg)
}

// PathSafeTestName returns a file-system-safe version of the test name.
// Replaces characters that could cause issues with file system paths.
func PathSafeTestName(t *testing.T) string {
	t.Helper()
	replacer := strings.NewReplacer(
		"/", "__",
		"\\", "__",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)
	return replacer.Replace(t.Name())
}

func TestPrepareCmdArgsForTool(t *testing.T) {
	dir := t.TempDir()
	tempFile, err := os.CreateTemp(dir, PathSafeTestName(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tempFile.Close()
	})

	nopLogger := zerolog.Nop()

	testCases := []struct {
		name           string
		toolDef        SnykMcpToolsDefinition
		requestArgs    map[string]any
		expectedParams map[string]convertedToolParameter
		expectedWd     string
	}{
		{
			name: "Basic string & bool convertedToolParams, path extraction",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "path", Type: "string", IsPositional: true},
					{Name: "all_projects", Type: "boolean"},
					{Name: "org", Type: "string"},
				},
			},
			requestArgs: map[string]any{
				"path":         dir,
				"all_projects": true,
				"org":          "my-org-name",
				"unused_param": "",
			},
			expectedParams: map[string]convertedToolParameter{
				"path": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:         "path",
						Type:         "string",
						IsPositional: true,
					},
					value: dir,
				},
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: true,
				},
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "my-org-name",
				},
			},
			expectedWd: dir,
		},
		{
			name: "path with file given",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "all-projects", Type: "boolean"},
					{Name: "org", Type: "string"},
					{Name: "path", Type: "string", IsPositional: true},
				},
			},
			requestArgs: map[string]any{
				"all-projects": true,
				"org":          "my-org-name",
				"path":         tempFile.Name(),
			},
			expectedParams: map[string]convertedToolParameter{
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: true,
				},
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "my-org-name",
				},
				"path": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:         "path",
						Type:         "string",
						IsPositional: true,
					},
					value: tempFile.Name(),
				},
			},
			expectedWd: dir,
		},
		{
			name: "no path given",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "all_projects", Type: "boolean"},
					{Name: "org", Type: "string"},
				},
			},
			requestArgs: map[string]any{
				"all_projects": true,
				"org":          "my-org-name",
			},
			expectedParams: map[string]convertedToolParameter{
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: true,
				},
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "my-org-name",
				},
			},
			expectedWd: "",
		},
		{
			name: "Standard convertedToolParams addition",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "file", Type: "string"},
				},
				StandardParams: []string{"json", "debug_mode"},
			},
			requestArgs: map[string]any{
				"file": "package.json",
			},
			expectedParams: map[string]convertedToolParameter{
				"file": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "file",
						Type: "string",
					},
					value: "package.json",
				},
				"json": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "json",
						Type: "boolean",
					},
					value: true,
				},
				"debug-mode": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "debug-mode",
						Type: "boolean",
					},
					value: true,
				},
			},
			expectedWd: "",
		},
		{
			name: "Supersedence: 'file' supersedes 'all_projects' (both in request)",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "file", Type: "string", SupersedesParams: []string{"all_projects"}},
					{Name: "all_projects", Type: "boolean"},
					{Name: "json", Type: "boolean"},
				},
			},
			requestArgs: map[string]any{
				"file":        "pom.xml",
				"allprojects": true,
				"json":        true,
			},
			expectedParams: map[string]convertedToolParameter{
				"file": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:             "file",
						Type:             "string",
						SupersedesParams: []string{"all_projects"},
					},
					value: "pom.xml",
				},
				"json": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "json",
						Type: "boolean",
					},
					value: true,
				},
			},
			expectedWd: "",
		},
		{
			name: "Supersedence: 'file' (in request) supersedes 'all_projects' (from standard_params)",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "file", Type: "string", SupersedesParams: []string{"all_projects"}},
					{Name: "json", Type: "boolean"},
				},
				StandardParams: []string{"all_projects", "debug"}, // all_projects will be added as standard
			},
			requestArgs: map[string]any{
				"file": "pom.xml",
				"json": true,
			},
			expectedParams: map[string]convertedToolParameter{
				"file": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:             "file",
						Type:             "string",
						SupersedesParams: []string{"all_projects"},
					},
					value: "pom.xml",
				},
				"json": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "json",
						Type: "boolean",
					},
					value: true,
				},
				"debug": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "debug",
						Type: "boolean",
					},
					value: true,
				},
			},
			expectedWd: "",
		},
		{
			name: "No request args, only standard convertedToolParams",
			toolDef: SnykMcpToolsDefinition{
				StandardParams: []string{"json", "all_projects"},
			},
			requestArgs: map[string]any{},
			expectedParams: map[string]convertedToolParameter{
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: true,
				},
				"json": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "json",
						Type: "boolean",
					},
					value: true,
				},
			},
			expectedWd: "",
		},
		{
			name: "Path is provided but not a string",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "path", Type: "string", IsPositional: true},
				},
			},
			requestArgs: map[string]any{
				"path": 123,
			},
			expectedParams: map[string]convertedToolParameter{
				"path": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:         "path",
						Type:         "string",
						IsPositional: true,
					},
					value: 123,
				}},
			expectedWd: "", // Path extraction fails if not string
		},
		{
			name: "Boolean param in request is false",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "all_projects", Type: "boolean"},
				},
			},
			requestArgs: map[string]any{
				"all-projects": false,
			},
			expectedParams: map[string]convertedToolParameter{}, // False booleans are not added
			expectedWd:     "",
		},
		{
			name: "String param in request is empty string",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "org", Type: "string"},
				},
			},
			requestArgs: map[string]any{
				"org": "",
			},
			expectedParams: map[string]convertedToolParameter{
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "",
				}},
			expectedWd: "",
		},
		{
			name: "Supersedence: multiple convertedToolParams superseded",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "package_manager", Type: "string", SupersedesParams: []string{"all_projects", "file"}},
					{Name: "all_projects", Type: "boolean"},
					{Name: "file", Type: "string"},
					{Name: "json", Type: "boolean"},
				},
			},
			requestArgs: map[string]any{
				"package_manager": "npm",
				"all_projects":    true,
				"file":            "package-lock.json",
				"json":            true,
			},
			expectedParams: map[string]convertedToolParameter{
				"package-manager": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:             "package-manager",
						Type:             "string",
						SupersedesParams: []string{"all_projects", "file"},
					},
					value: "npm",
				},
				"json": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "json",
						Type: "boolean",
					},
					value: true,
				},
			},
			expectedWd: "",
		},
		{
			name: "Supersedence: superseded param not in request, but in standard convertedToolParams",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "org", Type: "string", SupersedesParams: []string{"dev"}},
				},
				StandardParams: []string{"dev", "json"},
			},
			requestArgs: map[string]any{
				"org": "my-org",
			},
			expectedParams: map[string]convertedToolParameter{
				//"org":  "my-org",
				//"json": true, // dev is removed
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:             "org",
						Type:             "string",
						SupersedesParams: []string{"dev"},
					},
					value: "my-org",
				},
				"json": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "json",
						Type: "boolean",
					},
					value: true,
				},
			},
			expectedWd: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualParams, actualWd, err := prepareCmdArgsForTool(&nopLogger, tc.toolDef, tc.requestArgs)
			require.NoError(t, err)
			require.EqualValues(t, tc.expectedParams, actualParams, "Parameter map mismatch")
			require.Equal(t, tc.expectedWd, actualWd, "Working directory mismatch")
		})
	}
}

func TestSnykTrustHandler(t *testing.T) {
	fixture := setupTestFixture(t)
	toolDef := getToolWithName(t, fixture.tools, ToolName.Trust)
	require.NotNil(t, toolDef, "snyk_trust tool definition not found")
	fixture.invocationContext.GetConfiguration().Set(trust.DisableTrustFlag, false)

	handler := fixture.binding.snykTrustHandler(fixture.invocationContext, *toolDef)

	t.Run("PathMissing", func(t *testing.T) {
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]interface{}{},
			},
		}

		result, err := handler(t.Context(), request)

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "argument 'path' is missing for tool snyk_trust")
	})

	t.Run("PathEmpty", func(t *testing.T) {
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]interface{}{"path": ""},
			},
		}

		result, err := handler(t.Context(), request)

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "empty path given to tool snyk_trust")
	})
}

func TestSnykSendFeedbackHandler_Validation(t *testing.T) {
	fixture := setupTestFixture(t)
	toolDef := getToolWithName(t, fixture.tools, ToolName.SendFeedback)
	require.NotNil(t, toolDef, "snyk_send_feedback tool definition not found")

	handler := fixture.binding.snykSendFeedback(fixture.invocationContext, *toolDef)

	t.Run("MissingPreventedIssuesCount", func(t *testing.T) {
		req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]interface{}{
			"fixedExistingIssuesCount": float64(0),
			"path":                     "/tmp",
		}}}
		result, err := handler(t.Context(), req)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "preventedIssuesCount")
	})

	t.Run("MissingFixedExistingIssuesCount", func(t *testing.T) {
		req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]interface{}{
			"preventedIssuesCount": float64(1),
			"path":                 "/tmp",
		}}}
		result, err := handler(t.Context(), req)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "fixedExistingIssuesCount")
	})

	t.Run("MissingPath", func(t *testing.T) {
		req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]interface{}{
			"preventedIssuesCount":     float64(1),
			"fixedExistingIssuesCount": float64(0),
		}}}
		result, err := handler(t.Context(), req)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "'path' is missing")
	})

	t.Run("EmptyPath", func(t *testing.T) {
		req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]interface{}{
			"preventedIssuesCount":     float64(1),
			"fixedExistingIssuesCount": float64(0),
			"path":                     "",
		}}}
		result, err := handler(t.Context(), req)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "empty path")
	})

	t.Run("BothCountsZeroReturnsEarly", func(t *testing.T) {
		// Both counts zero short-circuits before any analytics dispatch, so this
		// is the success path safe to exercise without mocking the analytics workflow.
		req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]interface{}{
			"preventedIssuesCount":     float64(0),
			"fixedExistingIssuesCount": float64(0),
			"path":                     "/tmp",
			"preventedIssueIds":        []any{"sast:ignored"},
		}}}
		result, err := handler(t.Context(), req)
		require.NoError(t, err)
		require.NotNil(t, result)
	})
}

func TestCoerceStringSlice(t *testing.T) {
	t.Run("NilInput", func(t *testing.T) {
		require.Nil(t, coerceStringSlice(nil))
	})

	t.Run("NonSliceInput", func(t *testing.T) {
		require.Nil(t, coerceStringSlice("not a slice"))
		require.Nil(t, coerceStringSlice(42))
	})

	t.Run("EmptySlice", func(t *testing.T) {
		got := coerceStringSlice([]any{})
		require.NotNil(t, got)
		require.Len(t, got, 0)
	})

	t.Run("AllStrings", func(t *testing.T) {
		got := coerceStringSlice([]any{"a", "b", "c"})
		require.Equal(t, []string{"a", "b", "c"}, got)
	})

	t.Run("MixedTypesDropsNonStrings", func(t *testing.T) {
		got := coerceStringSlice([]any{"a", 1, "b", true, "c"})
		require.Equal(t, []string{"a", "b", "c"}, got)
	})
}

func TestBuildSendFeedbackExtension(t *testing.T) {
	t.Run("CountsOnlyNoIDs", func(t *testing.T) {
		ext := buildSendFeedbackExtension(nil, 2, 1, nil)
		require.Equal(t, 2, ext["mcp::preventedIssuesCount"])
		require.Equal(t, 1, ext["mcp::remediatedIssuesCount"])
		_, hasIDs := ext["mcp::preventedIssueIds"]
		require.False(t, hasIDs, "preventedIssueIds key must be omitted when no IDs provided")
	})

	t.Run("WithMatchingIDs", func(t *testing.T) {
		ids := []string{"sast:javascript/SqlInjection", "sca:SNYK-JS-LODASH-1234567"}
		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		ext := buildSendFeedbackExtension(&logger, 2, 0, ids)
		require.Equal(t, ids, ext["mcp::preventedIssueIds"])
		require.Empty(t, buf.String(), "no warning expected when length matches count")
	})

	t.Run("CountMismatchLogsWarningButIncludesIDs", func(t *testing.T) {
		ids := []string{"sast:a", "sast:b"}
		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		ext := buildSendFeedbackExtension(&logger, 3, 0, ids)
		require.Equal(t, ids, ext["mcp::preventedIssueIds"])
		require.Contains(t, buf.String(), "does not match")
	})

	t.Run("EmptyIDsSliceOmittedFromExtension", func(t *testing.T) {
		ext := buildSendFeedbackExtension(nil, 0, 0, []string{})
		_, hasIDs := ext["mcp::preventedIssueIds"]
		require.False(t, hasIDs)
	})
}

func TestHandleFileOutput(t *testing.T) {
	logger := zerolog.New(io.Discard)
	testOutput := `{"test": "output", "issues": [{"id": "1", "severity": "high"}]}`

	toolDef := SnykMcpToolsDefinition{
		Name:        "snyk_code_scan",
		Description: "Test tool",
	}

	t.Run("WriteToTempDirectory", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invocationCtx := mocks.NewMockInvocationContext(ctrl)
		config := configuration.New()
		config.Set(shared.OutputDirParam, OsTempDir)
		invocationCtx.EXPECT().GetConfiguration().Return(config).AnyTimes()

		workingDir := t.TempDir()
		filePath, err := handleFileOutput(logger, invocationCtx, workingDir, toolDef, testOutput)

		require.NoError(t, err)
		require.NotEmpty(t, filePath)
		require.Contains(t, filePath, os.TempDir())
		require.Contains(t, filePath, "scan_output_")
		require.Contains(t, filePath, "snyk_code_scan.json")

		// Verify file was created and contains correct content
		content, err := os.ReadFile(filePath)
		require.NoError(t, err)
		require.Equal(t, testOutput, string(content))
	})

	t.Run("WriteToAbsolutePath", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invocationCtx := mocks.NewMockInvocationContext(ctrl)
		config := configuration.New()

		outputDir := t.TempDir()
		config.Set(shared.OutputDirParam, outputDir)
		invocationCtx.EXPECT().GetConfiguration().Return(config).AnyTimes()

		workingDir := t.TempDir()
		filePath, err := handleFileOutput(logger, invocationCtx, workingDir, toolDef, testOutput)

		require.NoError(t, err)
		require.NotEmpty(t, filePath)
		require.Contains(t, filePath, outputDir)
		require.Contains(t, filePath, "scan_output_")
		require.Contains(t, filePath, "snyk_code_scan.json")

		// Verify file was created and contains correct content
		content, err := os.ReadFile(filePath)
		require.NoError(t, err)
		require.Equal(t, testOutput, string(content))
	})

	t.Run("WriteToRelativePath", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invocationCtx := mocks.NewMockInvocationContext(ctrl)
		config := configuration.New()

		relativeDir := "output"
		config.Set(shared.OutputDirParam, relativeDir)
		invocationCtx.EXPECT().GetConfiguration().Return(config).AnyTimes()

		workingDir := t.TempDir()
		// Create the output directory since handleFileOutput doesn't create it
		err := os.Mkdir(filepath.Join(workingDir, relativeDir), 0755)
		require.NoError(t, err)

		filePath, err := handleFileOutput(logger, invocationCtx, workingDir, toolDef, testOutput)

		require.NoError(t, err)
		require.NotEmpty(t, filePath)
		require.Contains(t, filePath, workingDir)
		require.Contains(t, filePath, relativeDir)
		require.Contains(t, filePath, "scan_output_")
		require.Contains(t, filePath, "snyk_code_scan.json")

		// Verify file was created and contains correct content
		content, err := os.ReadFile(filePath)
		require.NoError(t, err)
		require.Equal(t, testOutput, string(content))
	})

	t.Run("FileNameIncludesWorkingDirBasename", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invocationCtx := mocks.NewMockInvocationContext(ctrl)
		config := configuration.New()
		config.Set(shared.OutputDirParam, OsTempDir)
		invocationCtx.EXPECT().GetConfiguration().Return(config).AnyTimes()

		// Create a temp dir with a specific name
		tempBase := t.TempDir()
		workingDir := filepath.Join(tempBase, "my-project")
		err := os.Mkdir(workingDir, 0755)
		require.NoError(t, err)

		filePath, err := handleFileOutput(logger, invocationCtx, workingDir, toolDef, testOutput)

		require.NoError(t, err)
		require.Contains(t, filePath, "my-project")
	})

	t.Run("DifferentToolNames", func(t *testing.T) {
		testCases := []struct {
			toolName     string
			expectedName string
		}{
			{"snyk_code_scan", "snyk_code_scan.json"},
			{"snyk_sca_scan", "snyk_sca_scan.json"},
			{"snyk_iac_scan", "snyk_iac_scan.json"},
		}

		for _, tc := range testCases {
			t.Run(tc.toolName, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				invocationCtx := mocks.NewMockInvocationContext(ctrl)
				config := configuration.New()
				config.Set(shared.OutputDirParam, OsTempDir)
				invocationCtx.EXPECT().GetConfiguration().Return(config).AnyTimes()

				workingDir := t.TempDir()
				toolDefLocal := SnykMcpToolsDefinition{Name: tc.toolName}

				filePath, err := handleFileOutput(logger, invocationCtx, workingDir, toolDefLocal, testOutput)

				require.NoError(t, err)
				require.Contains(t, filePath, tc.expectedName)
			})
		}
	})

	t.Run("ErrorWhenWriteFails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invocationCtx := mocks.NewMockInvocationContext(ctrl)
		config := configuration.New()

		// Use an invalid path that will cause write to fail
		invalidPath := "/invalid/readonly/path/that/does/not/exist"
		config.Set(shared.OutputDirParam, invalidPath)
		invocationCtx.EXPECT().GetConfiguration().Return(config).AnyTimes()

		workingDir := t.TempDir()
		filePath, err := handleFileOutput(logger, invocationCtx, workingDir, toolDef, testOutput)

		require.Error(t, err)
		require.Empty(t, filePath)
	})

	t.Run("CaseInsensitiveTempCheck", func(t *testing.T) {
		tempVariants := []string{OsTempDir, OsTempDir, OsTempDir, OsTempDir}

		for _, tempVariant := range tempVariants {
			t.Run(tempVariant, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				invocationCtx := mocks.NewMockInvocationContext(ctrl)
				config := configuration.New()
				config.Set(shared.OutputDirParam, tempVariant)
				invocationCtx.EXPECT().GetConfiguration().Return(config).AnyTimes()

				workingDir := t.TempDir()
				filePath, err := handleFileOutput(logger, invocationCtx, workingDir, toolDef, testOutput)

				require.NoError(t, err)
				require.Contains(t, filePath, os.TempDir())
			})
		}
	})
}

func whoamiWorkflowResponse(t *testing.T) (*authentication.ActiveUser, []workflow.Data) {
	t.Helper()
	expectedUser := authentication.ActiveUser{
		Id:       "id",
		UserName: "username",
	}
	expectedUserJSON, err := json.Marshal(expectedUser)
	require.NoError(t, err)

	expectedUserData := []workflow.Data{
		workflow.NewData(
			workflow.NewTypeIdentifier(localworkflows.WORKFLOWID_WHOAMI, "payload"),
			"application/json",
			expectedUserJSON),
	}
	return &expectedUser, expectedUserData
}

func TestAddSnykToolsWithProfile(t *testing.T) {
	testCases := []struct {
		name            string
		profile         Profile
		expectedTools   []string
		unexpectedTools []string
	}{
		{
			name:    "lite profile registers only lite tools",
			profile: ProfileLite,
			expectedTools: []string{
				"snyk_auth",
				"snyk_sca_scan",
				"snyk_code_scan",
				"snyk_version",
				"snyk_logout",
				"snyk_trust",
				"snyk_send_feedback",
			},
			unexpectedTools: []string{
				"snyk_container_scan",
				"snyk_iac_scan",
				"snyk_sbom_scan",
				"snyk_aibom",
				"snyk_package_health_check",
				"snyk_secret_scan",
				"snyk_breakability_check",
			},
		},
		{
			name:    "full profile excludes experimental tools",
			profile: ProfileFull,
			expectedTools: []string{
				"snyk_auth",
				"snyk_sca_scan",
				"snyk_code_scan",
				"snyk_version",
				"snyk_logout",
				"snyk_trust",
				"snyk_send_feedback",
				"snyk_container_scan",
				"snyk_iac_scan",
				"snyk_sbom_scan",
				"snyk_aibom",
				"snyk_package_health_check",
				"snyk_breakability_check",
			},
			unexpectedTools: []string{
				"snyk_secret_scan",
			},
		},
		{
			name:    "experimental profile includes all tools",
			profile: ProfileExperimental,
			expectedTools: []string{
				"snyk_auth",
				"snyk_sca_scan",
				"snyk_code_scan",
				"snyk_version",
				"snyk_logout",
				"snyk_trust",
				"snyk_send_feedback",
				"snyk_container_scan",
				"snyk_iac_scan",
				"snyk_sbom_scan",
				"snyk_aibom",
				"snyk_package_health_check",
				"snyk_secret_scan",
				"snyk_breakability_check",
			},
			unexpectedTools: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Load tools from JSON and filter by profile
			config, err := loadMcpToolsFromJson()
			require.NoError(t, err)

			// Build map of tools that would be registered for this profile
			registeredToolNames := make(map[string]bool)
			for _, toolDef := range config.Tools {
				if IsToolInProfile(toolDef, tc.profile) {
					registeredToolNames[toolDef.Name] = true
				}
			}

			// Verify expected tools would be registered
			for _, expectedTool := range tc.expectedTools {
				require.True(t, registeredToolNames[expectedTool],
					"Expected tool %s to be registered for profile %s", expectedTool, tc.profile)
			}

			// Verify unexpected tools would NOT be registered
			for _, unexpectedTool := range tc.unexpectedTools {
				require.False(t, registeredToolNames[unexpectedTool],
					"Expected tool %s to NOT be registered for profile %s", unexpectedTool, tc.profile)
			}
		})
	}
}

func TestToolNamesMustExistInJson(t *testing.T) {
	// This test ensures that all tool names in the ToolName struct
	// have a corresponding tool definition in snyk_tools.json.
	// Uses reflection to automatically validate all fields.

	config, err := loadMcpToolsFromJson()
	require.NoError(t, err)
	require.NotNil(t, config)

	// Build a set of all tool names from JSON
	jsonToolNames := make(map[string]bool)
	for _, tool := range config.Tools {
		jsonToolNames[tool.Name] = true
	}

	// Use reflection to iterate over all ToolName struct fields
	v := reflect.ValueOf(ToolName)
	toolNameType := v.Type()

	for i := 0; i < v.NumField(); i++ {
		fieldName := toolNameType.Field(i).Name
		toolName := v.Field(i).String()

		require.True(t, jsonToolNames[toolName],
			"ToolName.%s has value %q but no tool with that name exists in snyk_tools.json. "+
				"Ensure the value matches the 'name' field in the JSON definition.",
			fieldName, toolName)
	}
}

func TestToolProfileAssignmentsInJson(t *testing.T) {
	config, err := loadMcpToolsFromJson()
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify all tools have profiles field parsed correctly
	for _, tool := range config.Tools {
		t.Run(tool.Name, func(t *testing.T) {
			// Profiles field should exist (even if empty)
			require.NotNil(t, tool.Profiles, "Tool %s should have Profiles field", tool.Name)

			// Verify profile-based filtering works for each tool
			switch tool.Name {
			case "snyk_auth", "snyk_sca_scan", "snyk_code_scan", "snyk_version", "snyk_logout", "snyk_trust", "snyk_send_feedback":
				// These should be in lite profile
				require.True(t, IsToolInProfile(tool, ProfileLite),
					"Tool %s should be in lite profile", tool.Name)
				require.True(t, IsToolInProfile(tool, ProfileFull),
					"Tool %s should be in full profile", tool.Name)
				require.True(t, IsToolInProfile(tool, ProfileExperimental),
					"Tool %s should be in experimental profile", tool.Name)

			case "snyk_container_scan", "snyk_iac_scan", "snyk_sbom_scan", "snyk_aibom", "snyk_package_health_check", "snyk_breakability_check":
				// These should be in full but not lite
				require.False(t, IsToolInProfile(tool, ProfileLite),
					"Tool %s should NOT be in lite profile", tool.Name)
				require.True(t, IsToolInProfile(tool, ProfileFull),
					"Tool %s should be in full profile", tool.Name)
				require.True(t, IsToolInProfile(tool, ProfileExperimental),
					"Tool %s should be in experimental profile", tool.Name)

			case "snyk_secret_scan":
				// These should be experimental only
				require.False(t, IsToolInProfile(tool, ProfileLite),
					"Tool %s should NOT be in lite profile", tool.Name)
				require.False(t, IsToolInProfile(tool, ProfileFull),
					"Tool %s should NOT be in full profile", tool.Name)
				require.True(t, IsToolInProfile(tool, ProfileExperimental),
					"Tool %s should be in experimental profile", tool.Name)
			}
		})
	}
}

// breakabilityErrMsg mirrors the message returned by snykBreakabilityHandler
// when the API call fails or returns an unexpected payload.
const breakabilityErrMsg = "no additional breakability context available"

// configureBreakabilityFixture wires the org id and API URL on the fixture so
// the breakability handler can build a real HTTP request against the mock
// server. testOrgID is a valid UUID accepted by uuid.Parse.
func configureBreakabilityFixture(t *testing.T, fixture *testFixture, apiURL, orgID string) {
	t.Helper()
	config := fixture.invocationContext.GetConfiguration()
	config.Set(configuration.ORGANIZATION, orgID)
	config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
	config.Set(configuration.API_URL, apiURL)
}

// startBreakabilityMockServer starts an httptest server that asserts the
// request shape and responds with the supplied status/body.
func startBreakabilityMockServer(t *testing.T, expectOrgID string, statusCode int, body interface{}, capturedBody *map[string]interface{}) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/hidden/orgs/"+expectOrgID+"/breakability")
		require.Equal(t, "2024-10-15", r.URL.Query().Get("version"))
		require.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))

		if capturedBody != nil {
			require.NoError(t, json.NewDecoder(r.Body).Decode(capturedBody))
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

func TestSnykBreakabilityHandler_ArgumentValidation(t *testing.T) {
	fixture := setupTestFixture(t)
	toolDef := getToolWithName(t, fixture.tools, ToolName.Breakability)
	require.NotNil(t, toolDef, "snyk_breakability_check tool definition not found")
	handler := fixture.binding.snykBreakabilityHandler(fixture.invocationContext, *toolDef)

	testCases := []struct {
		name        string
		args        map[string]interface{}
		expectedErr string
	}{
		{
			name:        "missing package_name",
			args:        map[string]interface{}{"package_version_from": "1.0.0", "package_version_to": "2.0.0"},
			expectedErr: "argument 'package_name' is required",
		},
		{
			name:        "empty package_name",
			args:        map[string]interface{}{"package_name": "", "package_version_from": "1.0.0", "package_version_to": "2.0.0"},
			expectedErr: "argument 'package_name' must be a non-empty string",
		},
		{
			name:        "missing package_version_from",
			args:        map[string]interface{}{"package_name": "lodash", "package_version_to": "2.0.0"},
			expectedErr: "argument 'package_version_from' is required",
		},
		{
			name:        "missing package_version_to",
			args:        map[string]interface{}{"package_name": "lodash", "package_version_from": "1.0.0"},
			expectedErr: "argument 'package_version_to' is required",
		},
		{
			name:        "wrong type package_name",
			args:        map[string]interface{}{"package_name": 42, "package_version_from": "1.0.0", "package_version_to": "2.0.0"},
			expectedErr: "argument 'package_name' must be a non-empty string",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := mcp.CallToolRequest{
				Params: mcp.CallToolParams{Arguments: tc.args},
			}

			result, err := handler(t.Context(), req)

			require.Error(t, err)
			require.Nil(t, result)
			require.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

func TestSnykBreakabilityHandler_OrgIDValidation(t *testing.T) {
	const validUUID = "11111111-1111-1111-1111-111111111111"

	args := map[string]interface{}{
		"package_name":         "lodash",
		"package_version_from": "1.0.0",
		"package_version_to":   "2.0.0",
	}

	t.Run("missing organization returns user-facing error", func(t *testing.T) {
		fixture := setupTestFixture(t)
		toolDef := getToolWithName(t, fixture.tools, ToolName.Breakability)
		require.NotNil(t, toolDef)
		fixture.invocationContext.GetConfiguration().Set(configuration.ORGANIZATION, "")
		handler := fixture.binding.snykBreakabilityHandler(fixture.invocationContext, *toolDef)

		result, err := handler(t.Context(), mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: args}})

		require.NoError(t, err)
		require.NotNil(t, result)
		text, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		require.Contains(t, text.Text, "Organization ID not configured")
	})

	t.Run("non-UUID organization returns user-facing error", func(t *testing.T) {
		fixture := setupTestFixture(t)
		toolDef := getToolWithName(t, fixture.tools, ToolName.Breakability)
		require.NotNil(t, toolDef)
		fixture.invocationContext.GetConfiguration().Set(configuration.ORGANIZATION, "not-a-uuid")
		handler := fixture.binding.snykBreakabilityHandler(fixture.invocationContext, *toolDef)

		result, err := handler(t.Context(), mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: args}})

		require.NoError(t, err)
		require.NotNil(t, result)
		text, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		require.Contains(t, text.Text, "Invalid organization ID format")
	})

	t.Run("valid UUID is accepted (though API call fails gracefully)", func(t *testing.T) {
		fixture := setupTestFixture(t)
		toolDef := getToolWithName(t, fixture.tools, ToolName.Breakability)
		require.NotNil(t, toolDef)
		// API_URL points to an unreachable host so the API call fails.
		configureBreakabilityFixture(t, fixture, "http://127.0.0.1:1", validUUID)
		handler := fixture.binding.snykBreakabilityHandler(fixture.invocationContext, *toolDef)

		result, err := handler(t.Context(), mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: args}})

		require.NoError(t, err)
		require.NotNil(t, result)
		text, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		require.Equal(t, breakabilityErrMsg, text.Text)
	})
}

func TestSnykBreakabilityHandler_SuccessfulResponse(t *testing.T) {
	const orgID = "22222222-2222-2222-2222-222222222222"

	testCases := []struct {
		name                 string
		riskLevel            string
		summary              string
		expectedRiskLevel    string
		expectedInstructions string
	}{
		{
			name:                 "high risk surfaces breaking change instructions",
			riskLevel:            "high",
			summary:              "Removed deprecated API",
			expectedRiskLevel:    "high",
			expectedInstructions: "IMPORTANT: Breaking change detected.",
		},
		{
			name:                 "medium risk surfaces ambiguous instructions",
			riskLevel:            "medium",
			summary:              "Signature changed",
			expectedRiskLevel:    "medium",
			expectedInstructions: "Check the assessment",
		},
		{
			name:                 "low risk surfaces non-breaking instructions",
			riskLevel:            "low",
			summary:              "Patch only",
			expectedRiskLevel:    "low",
			expectedInstructions: "Non-breaking change",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := setupTestFixture(t)
			toolDef := getToolWithName(t, fixture.tools, ToolName.Breakability)
			require.NotNil(t, toolDef)

			capturedBody := map[string]interface{}{}
			respBody := map[string]interface{}{
				"jsonapi": map[string]interface{}{"version": "1.0"},
				"data": map[string]interface{}{
					"id":   "33333333-3333-3333-3333-333333333333",
					"type": "breakability",
					"attributes": map[string]interface{}{
						"risk_level": tc.riskLevel,
						"summary":    tc.summary,
					},
				},
			}
			apiURL := startBreakabilityMockServer(t, orgID, http.StatusOK, respBody, &capturedBody)
			configureBreakabilityFixture(t, fixture, apiURL, orgID)

			handler := fixture.binding.snykBreakabilityHandler(fixture.invocationContext, *toolDef)

			req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]interface{}{
				"package_name":         "express",
				"package_version_from": "4.18.0",
				"package_version_to":   "5.0.0",
			}}}

			result, err := handler(t.Context(), req)

			require.NoError(t, err)
			require.NotNil(t, result)
			text, ok := result.Content[0].(mcp.TextContent)
			require.True(t, ok)

			var payload map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(text.Text), &payload))
			require.Equal(t, tc.expectedRiskLevel, payload["risk_level"])
			require.Equal(t, tc.summary, payload["assessment"])
			require.Contains(t, payload["instructions"], tc.expectedInstructions)

			// Verify the request body includes the upgrade exactly once.
			data, _ := capturedBody["data"].(map[string]interface{})
			require.NotNil(t, data, "expected data field in request body")
			require.Equal(t, "breakability", data["type"])
			attrs, _ := data["attributes"].(map[string]interface{})
			require.NotNil(t, attrs)
			upgrades, _ := attrs["package_upgrades"].([]interface{})
			require.Len(t, upgrades, 1)
			upgrade, _ := upgrades[0].(map[string]interface{})
			require.Equal(t, "express", upgrade["name"])
			require.Equal(t, "4.18.0", upgrade["from_version"])
			require.Equal(t, "5.0.0", upgrade["to_version"])
		})
	}
}

func TestSnykBreakabilityHandler_GracefulFailure(t *testing.T) {
	const orgID = "44444444-4444-4444-4444-444444444444"

	args := map[string]interface{}{
		"package_name":         "lodash",
		"package_version_from": "4.17.10",
		"package_version_to":   "4.17.21",
	}

	t.Run("API returns 200 but data is missing", func(t *testing.T) {
		fixture := setupTestFixture(t)
		toolDef := getToolWithName(t, fixture.tools, ToolName.Breakability)
		require.NotNil(t, toolDef)

		respBody := map[string]interface{}{
			"jsonapi": map[string]interface{}{"version": "1.0"},
		}
		apiURL := startBreakabilityMockServer(t, orgID, http.StatusOK, respBody, nil)
		configureBreakabilityFixture(t, fixture, apiURL, orgID)

		handler := fixture.binding.snykBreakabilityHandler(fixture.invocationContext, *toolDef)

		result, err := handler(t.Context(), mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: args}})

		require.NoError(t, err)
		require.NotNil(t, result)
		text, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		require.Equal(t, breakabilityErrMsg, text.Text)
	})

	t.Run("API returns 500 server error", func(t *testing.T) {
		fixture := setupTestFixture(t)
		toolDef := getToolWithName(t, fixture.tools, ToolName.Breakability)
		require.NotNil(t, toolDef)

		respBody := map[string]interface{}{
			"jsonapi": map[string]interface{}{"version": "1.0"},
			"errors":  []interface{}{map[string]interface{}{"status": "500", "detail": "boom"}},
		}
		apiURL := startBreakabilityMockServer(t, orgID, http.StatusInternalServerError, respBody, nil)
		configureBreakabilityFixture(t, fixture, apiURL, orgID)

		handler := fixture.binding.snykBreakabilityHandler(fixture.invocationContext, *toolDef)

		result, err := handler(t.Context(), mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: args}})

		require.NoError(t, err)
		require.NotNil(t, result)
		text, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		require.Equal(t, breakabilityErrMsg, text.Text)
	})
}

func TestSnykBreakabilityHandler_Unauthenticated(t *testing.T) {
	// When WhoAmI fails, the handler should bail out with a friendly auth message.
	engine, engineConfig := SetupEngineMock(t)
	logger := zerolog.New(io.Discard)
	mockctl := gomock.NewController(t)

	storage := mocks.NewMockStorage(mockctl)
	engineConfig.SetStorage(storage)

	invocationCtx := mocks.NewMockInvocationContext(mockctl)
	invocationCtx.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationCtx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New(runtimeinfo.WithName("hurz"), runtimeinfo.WithVersion("1000.8.3"))).AnyTimes()
	invocationCtx.EXPECT().GetEngine().Return(engine).AnyTimes()

	mockNetworkAccess := mocks.NewMockNetworkAccess(mockctl)
	mockNetworkAccess.EXPECT().RemoveHeaderField("User-Agent").AnyTimes()
	mockNetworkAccess.EXPECT().AddHeaderField("User-Agent", gomock.Any()).AnyTimes()
	mockNetworkAccess.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()
	invocationCtx.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()
	engine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()

	// Force WhoAmI to return an error.
	engine.EXPECT().InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, gomock.Any()).Return(nil, fmt.Errorf("unauthorized")).AnyTimes()

	binding := NewMcpLLMBinding(WithCliPath("/no/such/path"), WithLogger(&logger))
	binding.folderTrust = trust.NewFolderTrust(&logger, engineConfig)
	binding.mcpServer = server.NewMCPServer("Snyk", "1.1.1")

	tools, err := loadMcpToolsFromJson()
	require.NoError(t, err)
	toolDef := getToolWithName(t, tools, ToolName.Breakability)
	require.NotNil(t, toolDef)

	handler := binding.snykBreakabilityHandler(invocationCtx, *toolDef)

	result, err := handler(t.Context(), mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]interface{}{
		"package_name":         "lodash",
		"package_version_from": "1.0.0",
		"package_version_to":   "2.0.0",
	}}})

	require.NoError(t, err)
	require.NotNil(t, result)
	text, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)
	require.Contains(t, text.Text, "User not authenticated")
}
