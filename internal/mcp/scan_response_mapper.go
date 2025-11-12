/*
 * © 2024 Snyk Limited
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

	"github.com/rs/zerolog"
	"github.com/snyk/studio-mcp/internal/code"
	"github.com/snyk/studio-mcp/internal/oss"
	"github.com/snyk/studio-mcp/internal/types"
)

const (
	CodeOutputMapper = "CodeOutputMapper"
	ScaOutputMapper  = "ScaOutputMapper"
)

// EnhancedScanResult contains the original scan output and extracted issues
type EnhancedScanResult struct {
	OriginalOutput string            `json:"-"`
	Success        bool              `json:"success"`
	IssueCount     int               `json:"issueCount"`
	Issues         []types.IssueData `json:"issues"`
}

// mapScanResponse maps the scan output to an enhanced format for LLMs
func mapScanResponse(logger *zerolog.Logger, toolDef SnykMcpToolsDefinition, output string, success bool, workDir string, includeIgnores bool) string {
	mapperFunc, ok := outputMapperMap[toolDef.OutputMapper]
	if !ok || !IsJSON(output) {
		return output
	}

	result := EnhancedScanResult{
		OriginalOutput: output,
		Success:        success,
		Issues:         []types.IssueData{},
	}

	mapperFunc(logger, &result, workDir, includeIgnores)

	enhancedJSON, err := json.Marshal(result)
	if err != nil {
		return output
	}

	return string(enhancedJSON)
}

// extractSCAIssues extracts structured issue data from SCA JSON output
func extractSCAIssues(logger *zerolog.Logger, result *EnhancedScanResult, workDir string, includeIgnores bool) {
	issues, err := oss.ConvertOssJsonToIssues(workDir, []byte(result.OriginalOutput), includeIgnores)
	if err != nil {
		logger.Err(err).Msg("Failed to unmarshal SCA JSON output")
		return
	}
	result.Issues = issues
	result.IssueCount = len(issues)
}

// extractSASTIssues extracts issues from SAST scan output
func extractSASTIssues(logger *zerolog.Logger, result *EnhancedScanResult, workDir string, includeIgnores bool) {
	issues, err := code.ConvertSARIFJSONToIssues(logger, []byte(result.OriginalOutput), workDir, includeIgnores)
	if err != nil {
		return
	}
	result.Issues = issues
	result.IssueCount = len(result.Issues)
}
