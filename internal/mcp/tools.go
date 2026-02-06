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
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/studio-mcp/internal/analytics"
	packageapi "github.com/snyk/studio-mcp/internal/apiclients/package/2024-10-15"
	"github.com/snyk/studio-mcp/internal/authentication"
	"github.com/snyk/studio-mcp/internal/package_health"
	"github.com/snyk/studio-mcp/internal/trust"
	"github.com/snyk/studio-mcp/internal/types"
	"github.com/snyk/studio-mcp/shared"
)

const (
	OsTempDir = "ostemp"
)

const (
	CodeAutoEnablementError = "snyk-code-0005"
)

// ToolName defines all custom tool names.
// Values must match the "name" field in snyk_tools.json.
var ToolName = struct {
	ScaTest       string
	CodeTest      string
	Version       string
	Auth          string
	Logout        string
	Trust         string
	SendFeedback  string
	PackageHealth string
}{
	ScaTest:       "snyk_sca_scan",
	CodeTest:      "snyk_code_scan",
	Version:       "snyk_version",
	Auth:          "snyk_auth",
	Logout:        "snyk_logout",
	Trust:         "snyk_trust",
	SendFeedback:  "snyk_send_feedback",
	PackageHealth: "snyk_package_health",
}

type SnykMcpToolsDefinition struct {
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Command        []string               `json:"command"`
	StandardParams []string               `json:"standardParams"`
	Profiles       []string               `json:"profiles"`
	IgnoreTrust    bool                   `json:"ignoreTrust"`
	IgnoreAuth     bool                   `json:"ignoreAuth"`
	OutputMapper   string                 `json:"outputMapper"`
	Params         []SnykMcpToolParameter `json:"params"`
}

type SnykMcpToolParameter struct {
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	IsRequired       bool     `json:"isRequired"`
	Description      string   `json:"description"`
	SupersedesParams []string `json:"supersedesParams"`
	IsPositional     bool     `json:"isPositional"`
	Position         int      `json:"position"`
}

//go:embed snyk_tools.json
var snykToolsJson string

var (
	outputMapperMap = map[string]func(logger *zerolog.Logger, result *EnhancedScanResult, workDir string, includeIgnores bool){
		ScaOutputMapper:  extractSCAIssues,
		CodeOutputMapper: extractSASTIssues,
	}
)

type SnykMcpTools struct {
	Tools []SnykMcpToolsDefinition `json:"tools"`
}

func loadMcpToolsFromJson() (*SnykMcpTools, error) {
	var config SnykMcpTools
	if err := json.Unmarshal([]byte(snykToolsJson), &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

func (m *McpLLMBinding) addSnykTools(invocationCtx workflow.InvocationContext, profile Profile) error {
	config, err := loadMcpToolsFromJson()

	if err != nil || config == nil {
		m.logger.Err(err).Msg("Failed to load Snyk tools configuration")
		return err
	}

	m.logger.Info().Str("profile", string(profile)).Msg("Loading tools for profile")
	registeredCount := 0

	for _, toolDef := range config.Tools {
		if !IsToolInProfile(toolDef, profile) {
			m.logger.Debug().Str("tool", toolDef.Name).Str("profile", string(profile)).Msg("Skipping tool not in profile")
			continue
		}

		tool := createToolFromDefinition(&toolDef)
		switch toolDef.Name {
		case ToolName.Logout:
			m.mcpServer.AddTool(tool, m.snykLogoutHandler(invocationCtx, toolDef))
		case ToolName.Trust:
			m.mcpServer.AddTool(tool, m.snykTrustHandler(invocationCtx, toolDef))
		case ToolName.SendFeedback:
			m.mcpServer.AddTool(tool, m.snykSendFeedback(invocationCtx, toolDef))
		case ToolName.Auth:
			m.mcpServer.AddTool(tool, m.snykAuthHandler(invocationCtx, toolDef))
		case ToolName.PackageHealth:
			m.mcpServer.AddTool(tool, m.snykPackageInfoHandler(invocationCtx, toolDef))
		default:
			m.mcpServer.AddTool(tool, m.defaultHandler(invocationCtx, toolDef))
		}
		registeredCount++
	}

	m.logger.Info().Int("count", registeredCount).Str("profile", string(profile)).Msg("Registered tools for profile")
	return nil
}

// runSnyk runs a Snyk command and returns the result
func (m *McpLLMBinding) runSnyk(ctx context.Context, invocationCtx workflow.InvocationContext, workingDir string, cmd []string) (string, error) {
	logger := m.logger.With().Str("method", "runSnyk").Logger()
	clientInfo := ClientInfoFromContext(ctx)
	logger.Debug().Str("clientName", clientInfo.Name).Str("clientVersion", clientInfo.Version).Msg("Found client info")

	command := exec.CommandContext(ctx, cmd[0], cmd[1:]...)

	if workingDir != "" {
		command.Dir = workingDir
	}

	m.updateGafConfigWithIntegrationEnvironment(invocationCtx, clientInfo.Name, clientInfo.Version)

	integrationVersion := "unknown"
	runtimeInfo := invocationCtx.GetRuntimeInfo()
	if runtimeInfo != nil {
		integrationVersion = runtimeInfo.GetVersion()
	}

	command.Env = m.expandedEnv(invocationCtx, integrationVersion, clientInfo.Name, clientInfo.Version)

	logger.Debug().Strs("args", command.Args).Str("workingDir", command.Dir).Msg("Running Command with")
	logger.Trace().Strs("env", command.Env).Msg("Environment")

	command.Stderr = logger
	res, err := command.Output()
	resAsString := string(res)

	logger.Debug().Str("result", resAsString).Msg("Command run result")

	if err != nil {
		var errorType *exec.ExitError
		if errors.As(err, &errorType) {
			if errorType.ExitCode() > 1 {
				// Exit code > 1 means CLI run didn't work
				logger.Err(err).Msg("Received CLI error running command")
				return resAsString, err
			}
		} else {
			logger.Err(err).Msg("Received error running command")
			return resAsString, err
		}
	}
	return resAsString, nil
}

// nolint: gocyclo, nolintlint // func is used for all scanners, will be refactored to use GAF WFs
// defaultHandler executes a command and enhances output for scan tools
func (m *McpLLMBinding) defaultHandler(invocationCtx workflow.InvocationContext, toolDef SnykMcpToolsDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", "defaultHandler").Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")
		if len(toolDef.Command) == 0 {
			return nil, fmt.Errorf("empty command in tool definition for %s", toolDef.Name)
		}

		requestArgs := request.GetArguments()
		params, workingDir, err := prepareCmdArgsForTool(m.logger, toolDef, requestArgs)
		if err != nil {
			return nil, err
		}
		includeIgnores := false
		if param, exists := params["include-ignores"]; exists && toolDef.Name == ToolName.CodeTest {
			if value, parsable := param.value.(bool); value && parsable {
				includeIgnores = true
				// deleting the key to not include in the CLI run
				delete(params, "include-ignores")
			}
		}

		trustDisabled := invocationCtx.GetConfiguration().GetBool(trust.DisableTrustFlag) || toolDef.IgnoreTrust
		if !trustDisabled && !m.folderTrust.IsFolderTrusted(workingDir) {
			trustErr := fmt.Sprintf("Error: folder '%s' is not trusted. Please run 'snyk_trust' first", workingDir)
			logger.Error().Msg(trustErr)
			return mcp.NewToolResultText(trustErr), nil
		}

		if !toolDef.IgnoreAuth {
			user, whoAmiErr := authentication.CallWhoAmI(&logger, invocationCtx.GetEngine())
			if whoAmiErr != nil || user == nil {
				return mcp.NewToolResultText("User not authenticated. Please run 'snyk_auth' first"), nil
			}
		}

		if cmd, ok := params["command"]; ok && !verifyCommandArgument(cmd.value) {
			return mcp.NewToolResultText("Error: The provided binary name is invalid. Only use the `command` argument for python scanning and provide absolute path of python binary path."), nil
		}

		args := buildCommand(m.cliPath, toolDef.Command, params)

		// Add a working directory if specified
		if workingDir == "" {
			logger.Debug().Msg("Received empty workingDir")
		}

		// Run the command
		output, err := m.runSnyk(ctx, invocationCtx, workingDir, args)
		success := (err == nil)

		if err != nil {
			// No output from CLI, return Err
			if output == "" {
				return mcp.NewToolResultText(fmt.Sprintf("Error: %s", err.Error())), nil
			}

			// Try Snyk Code auto-enable for snyk-code-0005 error
			if strings.Contains(strings.ToLower(output), CodeAutoEnablementError) && toolDef.Name == ToolName.CodeTest {
				output, success = m.tryAutoEnableSnykCodeAndRetry(ctx, invocationCtx, &logger, workingDir, args, output, toolDef, includeIgnores)
			}

			// Return error if not recovered (either non-code-0005 error or failed auto-enable/retry)
			if !success {
				return mcp.NewToolResultText(fmt.Sprintf("Error: %s", output)), nil
			}
		}

		// Success path: enhance output and handle file output
		output = m.enhanceOutput(&logger, toolDef, output, success, workingDir, includeIgnores)
		return m.handleSuccessOutput(invocationCtx, logger, workingDir, toolDef, output)
	}
}

func handleFileOutput(logger zerolog.Logger, invocationCtx workflow.InvocationContext, workingDir string, toolDef SnykMcpToolsDefinition, toolOutput string) (string, error) {
	outputDir := invocationCtx.GetConfiguration().GetString(shared.OutputDirParam)
	baseDirName := filepath.Base(workingDir)
	fileName := fmt.Sprintf("scan_output_%s_%s.json", baseDirName, toolDef.Name)
	var path string
	if strings.ToLower(outputDir) == OsTempDir {
		path = filepath.Join(os.TempDir(), fileName)
	} else if filepath.IsAbs(outputDir) {
		path = filepath.Join(outputDir, fileName)
	} else {
		path = filepath.Join(workingDir, outputDir, fileName)
	}
	err := os.WriteFile(path, []byte(toolOutput), 0644)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to write output to file")
		return "", err
	}
	return path, nil
}

// enhanceOutput enhances the scan output with structured issue data
func (m *McpLLMBinding) enhanceOutput(logger *zerolog.Logger, toolDef SnykMcpToolsDefinition, output string, success bool, workDir string, includeIgnores bool) string {
	return mapScanResponse(logger, toolDef, output, success, workDir, includeIgnores)
}

// tryAutoEnableSnykCodeAndRetry attempts to enable Snyk Code for an organization and retry the scan
func (m *McpLLMBinding) tryAutoEnableSnykCodeAndRetry(ctx context.Context, invocationCtx workflow.InvocationContext, logger *zerolog.Logger, workingDir string, args []string, output string, toolDef SnykMcpToolsDefinition, includeIgnores bool) (string, bool) {
	config := invocationCtx.GetEngine().GetConfiguration()
	orgId := config.GetString(configuration.ORGANIZATION)
	appUrl := config.GetString(configuration.WEB_APP_URL)

	// No organization ID - provide manual enablement instructions
	if orgId == "" {
		output += fmt.Sprintf("\nTo activate Snyk Code, visit %s/manage/snyk-code?from=mcp or ask your administrator.", appUrl)
		return output, false
	}

	// Try to enable Snyk Code for the organization
	logger.Info().Str("orgId", orgId).Msg("Attempting to enable Snyk Code automatically")
	output += "\n\nAttempting to enable Snyk Code automatically for organization: " + orgId

	enableErr := m.enableSnykCodeForOrg(ctx, invocationCtx, orgId)
	if enableErr != nil {
		logger.Warn().Err(enableErr).Msg("Failed to enable Snyk Code automatically")
		output += fmt.Sprintf("\n\nFailed to enable Snyk Code automatically: %s", enableErr.Error())
		output += fmt.Sprintf("\nTo activate Snyk Code, visit %s/manage/snyk-code?from=mcp or ask your administrator.", appUrl)
		return output, false
	}

	// Retry the scan
	logger.Info().Msg("Snyk Code enabled successfully, automatically retrying scan")
	output += "\n\nSnyk Code has been successfully enabled for your organization. Retrying scan automatically...\n\n"

	retryOutput, retryErr := m.runSnyk(ctx, invocationCtx, workingDir, args)
	if retryErr != nil {
		output += fmt.Sprintf("Retry failed: %s\n%s", retryErr.Error(), retryOutput)
		return output, false
	}

	output += retryOutput
	return output, true
}

// handleSuccessOutput handles file output or returns direct output
func (m *McpLLMBinding) handleSuccessOutput(invocationCtx workflow.InvocationContext, logger zerolog.Logger, workingDir string, toolDef SnykMcpToolsDefinition, output string) (*mcp.CallToolResult, error) {
	if invocationCtx.GetConfiguration().IsSet(shared.OutputDirParam) {
		filePath, fileErr := handleFileOutput(logger, invocationCtx, workingDir, toolDef, output)
		if fileErr != nil {
			return nil, fileErr
		}
		return mcp.NewToolResultText(fmt.Sprintf("Scan results written locally, Read them from: %s", filePath)), nil
	}

	return mcp.NewToolResultText(output), nil
}

func (m *McpLLMBinding) snykAuthHandler(invocationCtx workflow.InvocationContext, toolDef SnykMcpToolsDefinition) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", "snykAuthHandler").Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")

		engine := invocationCtx.GetEngine()
		globalConfig := engine.GetConfiguration()
		apiUrl := globalConfig.GetString(configuration.API_URL)

		user, err := authentication.CallWhoAmI(&logger, engine)
		if err == nil && user != nil {
			msg := getAuthMsg(globalConfig, user)
			return mcp.NewToolResultText(msg), nil
		}

		if err != nil && os.Getenv("SNYK_TOKEN") != "" {
			logger.Error().Msg("Auth tool can't be called if SNYK_TOKEN env var is set")
			return mcp.NewToolResultText("Authentication aborted. Auth tool can't be called if SNYK_TOKEN env var is set"), nil
		}

		logger.Info().Msgf("Starting authentication process. API Endpoint: %s", apiUrl)

		conf := invocationCtx.GetConfiguration()
		conf.Set(localworkflows.AuthTypeParameter, auth.AUTH_TYPE_OAUTH)

		_, err = engine.InvokeWithConfig(localworkflows.WORKFLOWID_AUTH, conf)

		if err != nil {
			return mcp.NewToolResultText("Authentication failed"), nil
		}

		return mcp.NewToolResultText("Successfully logged in"), nil
	}
}

func (m *McpLLMBinding) snykLogoutHandler(invocationCtx workflow.InvocationContext, toolDef SnykMcpToolsDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", "snykLogoutHandler").Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")
		configs := []configuration.Configuration{invocationCtx.GetConfiguration(), invocationCtx.GetEngine().GetConfiguration()}
		for _, config := range configs {
			config.ClearCache()
			config.Unset(configuration.AUTHENTICATION_TOKEN)
			config.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)
		}

		return mcp.NewToolResultText("Successfully logged out"), nil
	}
}

func (m *McpLLMBinding) snykSendFeedback(invocationCtx workflow.InvocationContext, toolDef SnykMcpToolsDefinition) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", toolDef.Name).Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")

		preventedCountStr := request.GetArguments()["preventedIssuesCount"]
		remediatedCountStr := request.GetArguments()["fixedExistingIssuesCount"]

		preventedCount, ok := preventedCountStr.(float64)
		if !ok {
			return nil, fmt.Errorf("invalid argument preventedIssuesCount")
		}
		remediatedCount, ok := remediatedCountStr.(float64)
		if !ok {
			return nil, fmt.Errorf("invalid argument fixedExistingIssuesCount")
		}
		pathArg := request.GetArguments()["path"]
		if pathArg == nil {
			return nil, fmt.Errorf("argument 'path' is missing for tool %s", toolDef.Name)
		}
		path, ok := pathArg.(string)
		if !ok {
			return nil, fmt.Errorf("argument 'path' is not a string for tool %s", toolDef.Name)
		}
		if path == "" {
			return nil, fmt.Errorf("empty path given to tool %s", toolDef.Name)
		}

		if preventedCount == 0 && remediatedCount == 0 {
			return mcp.NewToolResultText("No issues to send feedback for"), nil
		}

		clientInfo := ClientInfoFromContext(ctx)

		m.updateGafConfigWithIntegrationEnvironment(invocationCtx, clientInfo.Name, clientInfo.Version)
		event := analytics.NewAnalyticsEventParam("Send feedback", nil, types.FilePath(path))

		event.Extension = map[string]any{
			"mcp::preventedIssuesCount":  int(preventedCount),
			"mcp::remediatedIssuesCount": int(remediatedCount),
		}
		go analytics.SendAnalytics(invocationCtx.GetEngine(), "", event, nil)

		return mcp.NewToolResultText("Successfully sent feedback"), nil
	}
}

func (m *McpLLMBinding) snykTrustHandler(invocationCtx workflow.InvocationContext, toolDef SnykMcpToolsDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", toolDef.Name).Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")

		if invocationCtx.GetConfiguration().GetBool(trust.DisableTrustFlag) {
			logger.Info().Msg("Folder trust is disabled. Trust mechanism is ignored")
			return mcp.NewToolResultText("Trust mechanism is disabled. Considering Folder to be trusted."), nil
		}

		pathArg := request.GetArguments()["path"]
		if pathArg == nil {
			return nil, fmt.Errorf("argument 'path' is missing for tool %s", toolDef.Name)
		}
		folderPath, ok := pathArg.(string)
		if !ok {
			return nil, fmt.Errorf("argument 'path' is not a string for tool %s", toolDef.Name)
		}
		if folderPath == "" {
			return nil, fmt.Errorf("empty path given to tool %s", toolDef.Name)
		}

		if m.folderTrust.IsFolderTrusted(folderPath) {
			msg := fmt.Sprintf("Folder '%s' is already trusted", folderPath)
			logger.Info().Msg(msg)
			return mcp.NewToolResultText(msg), nil
		}

		return m.folderTrust.HandleTrust(ctx, folderPath, logger)
	}
}

func getAuthMsg(config configuration.Configuration, activeUser *authentication.ActiveUser) string {
	user := activeUser.UserName
	if activeUser.Name != "" {
		user = activeUser.Name
	}

	apiUrl := config.GetString(configuration.API_URL)
	org := config.GetString(configuration.ORGANIZATION)
	return fmt.Sprintf("Already Authenticated. User: %s Using API Endpoint: %s and Org: %s", user, apiUrl, org)
}

func (m *McpLLMBinding) snykPackageInfoHandler(invocationCtx workflow.InvocationContext, toolDef SnykMcpToolsDefinition) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", "snykPackageInfoHandler").Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")

		// Check authentication
		user, whoAmiErr := authentication.CallWhoAmI(&logger, invocationCtx.GetEngine())
		if whoAmiErr != nil || user == nil {
			return mcp.NewToolResultText("User not authenticated. Please run 'snyk_auth' first"), nil
		}

		// Extract and validate arguments
		args := request.GetArguments()

		packageName, err := getRequiredStringArg(args, "package_name")
		if err != nil {
			return nil, err
		}

		ecosystem, err := getRequiredStringArg(args, "ecosystem")
		if err != nil {
			return nil, err
		}

		// Validate ecosystem
		ecosystem = strings.ToLower(ecosystem)
		if !package_health.ValidEcosystems[ecosystem] {
			return mcp.NewToolResultText(fmt.Sprintf("Error: Invalid ecosystem '%s'. Must be one of: npm, pypi, maven, nuget, golang", ecosystem)), nil
		}

		// Optional package version
		packageVersion := getOptionalStringArg(args, "package_version")

		// Get org ID from configuration
		config := invocationCtx.GetEngine().GetConfiguration()
		orgIdStr := config.GetString(configuration.ORGANIZATION)
		if orgIdStr == "" {
			return mcp.NewToolResultText("Error: Organization ID not configured. Please set an organization using 'snyk config set org=<org-id>'"), nil
		}

		orgId, err := uuid.Parse(orgIdStr)
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Error: Invalid organization ID format: %s", orgIdStr)), nil
		}

		endpoint, err := url.JoinPath(config.GetString(configuration.API_URL), "rest")
		httpClient := invocationCtx.GetNetworkAccess().GetHttpClient()
		if err != nil {
			return nil, err
		}
		// Create the package API client
		apiClient, err := packageapi.NewClientWithResponses(endpoint, packageapi.WithHTTPClient(httpClient))
		if err != nil {
			logger.Error().Err(err).Msg("Failed to create package API client")
			return mcp.NewToolResultText(fmt.Sprintf("Error: Failed to create API client: %s", err.Error())), nil
		}

		logger.Debug().Str("package", packageName).Str("version", packageVersion).Str("ecosystem", ecosystem).Msg("Fetching package info")

		const packageApiVersion = "2024-10-15"
		const insufficientPackageInfoMsg = "Warning: Snyk doesn't have sufficient information about this package. Proceed with caution and ask the user for input."

		var response *package_health.PackageInfoResponse
		if packageVersion != "" {
			resp, err := apiClient.GetPackageVersionWithResponse(ctx, orgId, ecosystem, packageName, packageVersion, &packageapi.GetPackageVersionParams{Version: packageApiVersion})
			if err != nil {
				var snykErr snyk_errors.Error
				if errors.As(err, &snykErr) && snykErr.StatusCode == http.StatusNotFound {
					return mcp.NewToolResultText(insufficientPackageInfoMsg), nil
				}
				logger.Error().Err(err).Msg("Failed to fetch package version info")
				return mcp.NewToolResultText(fmt.Sprintf("Error: Failed to fetch package info: %s", err.Error())), nil
			}
			if resp.ApplicationvndApiJSON200 == nil || resp.ApplicationvndApiJSON200.Data == nil || resp.ApplicationvndApiJSON200.Data.Attributes == nil {
				return mcp.NewToolResultText("Error: Unexpected response format from API"), nil
			}
			response = package_health.BuildPackageInfoResponse(resp.ApplicationvndApiJSON200.Data.Attributes)
		} else {
			resp, err := apiClient.GetPackageWithResponse(ctx, orgId, ecosystem, packageName, &packageapi.GetPackageParams{Version: packageApiVersion})
			if err != nil {
				var snykErr snyk_errors.Error
				if errors.As(err, &snykErr) && snykErr.StatusCode == http.StatusNotFound {
					return mcp.NewToolResultText(insufficientPackageInfoMsg), nil
				}
				logger.Error().Err(err).Msg("Failed to fetch package info")
				return mcp.NewToolResultText(fmt.Sprintf("Error: Failed to fetch package info: %s", err.Error())), nil
			}
			if resp.ApplicationvndApiJSON200 == nil || resp.ApplicationvndApiJSON200.Data == nil || resp.ApplicationvndApiJSON200.Data.Attributes == nil {
				return mcp.NewToolResultText("Error: Unexpected response format from API"), nil
			}
			response = package_health.BuildPackageInfoResponseFromPackage(resp.ApplicationvndApiJSON200.Data.Attributes)
		}

		jsonBytes, err := json.Marshal(response)
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Error: Failed to serialize response: %s", err.Error())), nil
		}

		return mcp.NewToolResultText(string(jsonBytes)), nil
	}
}

func getRequiredStringArg(args map[string]interface{}, name string) (string, error) {
	arg := args[name]
	if arg == nil {
		return "", fmt.Errorf("argument '%s' is required", name)
	}
	val, ok := arg.(string)
	if !ok || val == "" {
		return "", fmt.Errorf("argument '%s' must be a non-empty string", name)
	}
	return val, nil
}

func getOptionalStringArg(args map[string]interface{}, name string) string {
	if arg := args[name]; arg != nil {
		if val, ok := arg.(string); ok {
			return val
		}
	}
	return ""
}
