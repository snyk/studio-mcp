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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"
)

type convertedToolParameter struct {
	SnykMcpToolParameter
	value any // value is the requested parameter value that is provided from the LLM
}

// buildCommand builds command-line convertedToolParams for Snyk CLI based on parameters
func buildCommand(cliPath string, command []string, params map[string]convertedToolParameter) []string {
	cmd := []string{cliPath}
	cmd = append(cmd, command...)

	cmd = append(cmd, buildArgs(params)...)
	return cmd
}

func buildArgs(params map[string]convertedToolParameter) []string {
	args := []string{}
	// Add convertedToolParams as command-line flags
	for key, param := range params {
		arg := buildArg(key, param)
		if arg != "" {
			args = append(args, arg)
		}
	}
	return args
}

func buildArg(key string, param convertedToolParameter) string {
	switch param.value.(type) {
	case string:
		if param.value == "" {
			return ""
		}
	case bool:
		if param.value == false {
			return ""
		}
	default:
		return ""
	}
	valueString, _ := param.value.(string)

	if param.IsPositional {
		return valueString
	}
	switch strings.ToLower(param.Type) {
	case "boolean":
		return "--" + key
	case "string":
		return "--" + key + "=" + valueString
	default:
		return ""
	}
}

// createToolFromDefinition creates an MCP tool from a Snyk tool definition
// Returns a Tool pointer with InputSchema as required by the official go-sdk
func createToolFromDefinition(toolDef *SnykMcpToolsDefinition) *mcp.Tool {
	// Build JSON schema properties
	properties := make(map[string]any)
	required := []string{}

	for _, param := range toolDef.Params {
		propSchema := map[string]any{
			"description": param.Description,
		}

		switch param.Type {
		case "string":
			propSchema["type"] = "string"
		case "boolean":
			propSchema["type"] = "boolean"
		case "number":
			propSchema["type"] = "number"
		}

		properties[param.Name] = propSchema

		if param.IsRequired {
			required = append(required, param.Name)
		}
	}

	inputSchema := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		inputSchema["required"] = required
	}

	return &mcp.Tool{
		Name:        toolDef.Name,
		Description: toolDef.Description,
		InputSchema: inputSchema,
	}
}

func prepareCmdArgsForTool(logger *zerolog.Logger, toolDef SnykMcpToolsDefinition, requestArgs map[string]any) (map[string]convertedToolParameter, string, error) {
	params, workingDir, err := normalizeParamsAndDetermineWorkingDir(toolDef, requestArgs)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract parameters from request: %w", err)
	}

	// Add standard parameters
	for _, paramName := range toolDef.StandardParams {
		cliParamName := convertToCliParam(paramName)
		params[cliParamName] = convertedToolParameter{
			SnykMcpToolParameter: SnykMcpToolParameter{
				Name: cliParamName,
				Type: "boolean",
			},
			value: true,
		}
	}

	// Handle supersedence: if an explicitly provided argument supersedes others, remove the superseded ones.
	for _, paramDef := range toolDef.Params {
		if _, argExistsInRequest := requestArgs[paramDef.Name]; !argExistsInRequest || len(paramDef.SupersedesParams) == 0 {
			continue
		}
		for _, supersededParamName := range paramDef.SupersedesParams {
			cliSupersededName := convertToCliParam(supersededParamName)
			if _, ok := params[cliSupersededName]; ok {
				logger.Debug().Str("supersedingArg", paramDef.Name).Str("supersededParam", supersededParamName).Msg("Deleting superseded parameter.")
				delete(params, cliSupersededName)
			}
		}
	}
	return params, workingDir, nil
}

// normalizeParamsAndDetermineWorkingDir extracts parameters from the convertedToolParams based on the tool definition
func normalizeParamsAndDetermineWorkingDir(toolDef SnykMcpToolsDefinition, requestArgs map[string]any) (map[string]convertedToolParameter, string, error) {
	params := make(map[string]convertedToolParameter)
	var workingDir string

	for _, paramDef := range toolDef.Params {
		val, ok := requestArgs[paramDef.Name]
		if !ok {
			continue
		}

		// Store path separately to use as working directory
		if paramDef.Name == "path" {
			if pathStr, ok := val.(string); ok {
				fileInfo, err := os.Stat(pathStr)
				if err != nil {
					return nil, "", fmt.Errorf("file does not exist, path: %s, err: %w", paramDef.Name, err)
				}
				if fileInfo.IsDir() {
					workingDir = pathStr
				} else {
					workingDir = filepath.Dir(pathStr)
				}
			}
		}

		// Convert parameter name from snake_case to kebab-case for CLI convertedToolParams
		cliParamName := strings.ReplaceAll(paramDef.Name, "_", "-")
		paramDef.Name = cliParamName
		params[cliParamName] = convertedToolParameter{
			SnykMcpToolParameter: paramDef,
			value:                val,
		}
	}

	return params, workingDir, nil
}

// convertToCliParam Convert parameter name from snake_case to kebab-case for CLI convertedToolParams
func convertToCliParam(cliParam string) string {
	return strings.ReplaceAll(cliParam, "_", "-")
}

// ClientInfo holds client implementation info extracted from session
type ClientInfo struct {
	Name    string
	Version string
}

// ClientInfoFromSession extracts client info from a server session
func ClientInfoFromSession(session *mcp.ServerSession) ClientInfo {
	if session == nil {
		return ClientInfo{}
	}
	initParams := session.InitializeParams()
	if initParams == nil || initParams.ClientInfo == nil {
		return ClientInfo{}
	}
	return ClientInfo{
		Name:    initParams.ClientInfo.Name,
		Version: initParams.ClientInfo.Version,
	}
}

var re = regexp.MustCompile(`^python(\d+(\.\d+)?(\.\d+)?)?(\.exe)?$`)

// verifyCommandArgument verifies if provided command from the LLM used for python matches python binary name
func verifyCommandArgument(command any) bool {
	if command == nil {
		return true
	}

	cmdStr, ok := command.(string)
	if !ok {
		return true
	}

	binaryName := filepath.Base(cmdStr)
	isMatch := re.MatchString(binaryName)
	return isMatch
}

func IsJSON(s string) bool {
	var js interface{}
	err := json.Unmarshal([]byte(s), &js)
	return err == nil
}

// NewToolResultText creates a CallToolResult with a text content
func NewToolResultText(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
}

// NewToolResultError creates a CallToolResult with an error
func NewToolResultError(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
		IsError: true,
	}
}

// getRequestArguments extracts arguments from a CallToolRequest
func getRequestArguments(req *mcp.CallToolRequest) map[string]any {
	if req.Params.Arguments == nil {
		return make(map[string]any)
	}
	var args map[string]any
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		return make(map[string]any)
	}
	return args
}
