package code

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	codeClientSarif "github.com/snyk/code-client-go/sarif"
	sarifutils "github.com/snyk/go-application-framework/pkg/utils/sarif"

	"github.com/rs/zerolog"
	"github.com/snyk/studio-mcp/internal/types"
)

type IgnoreDetails struct {
	Category   string                           `json:"category"`
	Reason     string                           `json:"reason"`
	Expiration string                           `json:"expiration"`
	IgnoredOn  time.Time                        `json:"ignoredOn"`
	IgnoredBy  string                           `json:"ignoredBy"`
	Status     codeClientSarif.SuppresionStatus `json:"status"`
}

// ConvertSARIFJSONToIssues converts SARIF JSON output to Issues without requiring a full scanner instance
// This is a simplified version for use by MCP and other tools that need conversion without full scanner
// basePath is the absolute path where the scan was run (optional - if empty, paths remain relative)
func ConvertSARIFJSONToIssues(logger *zerolog.Logger, sarifJSON []byte, basePath string, includeIgnores bool) ([]types.IssueData, error) {
	var sarifResponse codeClientSarif.SarifResponse

	err := json.Unmarshal(sarifJSON, &sarifResponse.Sarif)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SARIF JSON: %w", err)
	}

	converter := SarifConverter{sarif: sarifResponse, logger: logger}

	// Convert with provided base path (or empty for relative paths)
	issues, err := converter.toIssues(types.FilePath(basePath), includeIgnores)
	if err != nil {
		return nil, fmt.Errorf("failed to convert SARIF to issues: %w", err)
	}

	return issues, nil
}

type SarifConverter struct {
	sarif  codeClientSarif.SarifResponse
	logger *zerolog.Logger
}

func (s *SarifConverter) isSecurityIssue(r codeClientSarif.Rule) bool {
	isSecurity := slices.ContainsFunc(r.Properties.Categories, func(category string) bool {
		return strings.ToLower(category) == "security"
	})

	return isSecurity
}

func (s *SarifConverter) cwe(r codeClientSarif.Rule) string {
	count := len(r.Properties.Cwe)
	if count == 0 {
		return ""
	}
	builder := strings.Builder{}
	builder.Grow(100)
	ending := "y"
	if count > 1 {
		ending = "ies"
	}
	builder.WriteString(fmt.Sprintf("Vulnerabilit%s: ", ending))
	for i, cwe := range r.Properties.Cwe {
		if i > 0 {
			builder.WriteString(" | ")
		}
		builder.WriteString(fmt.Sprintf(
			"[%s](%s)",
			cwe,
			fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.Split(cwe, "-")[1])))
	}
	builder.WriteString("\n\n\n")
	return builder.String()
}

func (s *SarifConverter) getCodeFlow(r codeClientSarif.Result, baseDir types.FilePath) (dataflow []types.DataflowElement) {
	flows := r.CodeFlows
	dedupMap := map[string]bool{}
	for _, cFlow := range flows {
		threadFlows := cFlow.ThreadFlows
		for _, tFlow := range threadFlows {
			for _, tFlowLocation := range tFlow.Locations {
				physicalLoc := tFlowLocation.Location.PhysicalLocation
				path, err := DecodePath(ToAbsolutePath(baseDir, types.FilePath(physicalLoc.ArtifactLocation.URI)))
				if err != nil {
					s.logger.Error().
						Err(err).
						Msg("failed to convert URI to absolute path: base directory: " +
							string(baseDir) +
							", URI: " +
							physicalLoc.ArtifactLocation.URI)
					continue
				}
				region := physicalLoc.Region
				myRange :=
					types.Range{
						Start: types.Position{
							Line:      region.StartLine - 1,
							Character: region.StartColumn - 1,
						},
						End: types.Position{
							Line:      region.EndLine - 1,
							Character: region.EndColumn,
						}}

				key := fmt.Sprintf("%sL%4d", path, region.StartLine)
				if !dedupMap[key] {
					d := types.DataflowElement{
						Position:  len(dataflow),
						FilePath:  types.FilePath(path),
						FlowRange: myRange,
					}
					dataflow = append(dataflow, d)
					dedupMap[key] = true
				}
			}
		}
	}
	return dataflow
}

func (s *SarifConverter) getMessage(r codeClientSarif.Result, rule codeClientSarif.Rule) string {
	text := r.Message.Text
	if rule.ShortDescription.Text != "" {
		text = fmt.Sprintf("%s: %s", rule.ShortDescription.Text, text)
	}
	const maxLength = 100
	if len(text) > maxLength {
		text = text[:maxLength] + "..."
	}
	return text
}

func (s *SarifConverter) getRule(r codeClientSarif.Run, id string) codeClientSarif.Rule {
	for _, r := range r.Tool.Driver.Rules {
		if r.ID == id {
			return r
		}
	}
	return codeClientSarif.Rule{}
}

func (s *SarifConverter) toIssues(baseDir types.FilePath, includeIgnores bool) (issues []types.IssueData, err error) {
	runs := s.sarif.Sarif.Runs
	if len(runs) == 0 {
		return issues, nil
	}

	r := runs[0]
	var errs error
	for _, result := range r.Results {
		for _, loc := range result.Locations {
			// Response contains encoded relative paths that should be decoded and converted to absolute.
			absPath, err := DecodePath(ToAbsolutePath(baseDir, types.FilePath(loc.PhysicalLocation.ArtifactLocation.URI)))
			if err != nil {
				s.logger.Error().
					Err(err).
					Msg("failed to convert URI to absolute path: base directory: " +
						string(baseDir) +
						", URI: " +
						loc.PhysicalLocation.ArtifactLocation.URI)
				errs = errors.Join(errs, err)
				continue
			}

			position := loc.PhysicalLocation.Region
			// NOTE: sarif uses 1-based location numbering, see
			// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html#_Ref493492556
			startLine := position.StartLine - 1
			endLine := math.Max(float64(position.EndLine-1), float64(startLine))
			startCol := position.StartColumn - 1
			endCol := math.Max(float64(position.EndColumn-1), 0)
			myRange := types.Range{
				Start: types.Position{
					Line:      startLine,
					Character: startCol,
				},
				End: types.Position{
					Line:      int(endLine),
					Character: int(endCol),
				},
			}

			testRule := s.getRule(r, result.RuleID)

			// only process security issues
			isSecurityType := s.isSecurityIssue(testRule)
			if !isSecurityType {
				continue
			}

			message := s.getMessage(result, testRule)
			errs = errors.Join(errs, err)

			title := testRule.ShortDescription.Text
			if title == "" {
				title = testRule.ID
			}

			d := types.IssueData{
				ID:          result.RuleID,
				Title:       title,
				Severity:    issueSeverity(result.Level).String(),
				Message:     message,
				Dataflow:    s.getCodeFlow(result, baseDir),
				FilePath:    absPath,
				CWEs:        testRule.Properties.Cwe,
				FingerPrint: result.Fingerprints.Num1,
			}
			if myRange.Start.Line >= 0 && myRange.Start.Character >= 0 {
				d.Line = myRange.Start.Line + 1 // Convert 0-based to 1-based
				d.Column = myRange.Start.Character + 1
			}

			d.FingerPrint = result.Fingerprints.Num1
			isIgnored, _ := GetIgnoreDetailsFromSuppressions(result.Suppressions)
			if !includeIgnores && isIgnored {
				continue
			}
			d.IsIgnored = isIgnored

			issues = append(issues, d)
		}
	}
	return issues, errs
}

var (
	issueSeverities = map[string]types.Severity{
		"3":       types.High,
		"2":       types.Medium,
		"warning": types.Medium, // Sarif Level
		"error":   types.High,   // Sarif Level
	}
)

func issueSeverity(snykSeverity string) types.Severity {
	sev, ok := issueSeverities[snykSeverity]
	if !ok {
		return types.Low
	}
	return sev
}

func GetIgnoreDetailsFromSuppressions(suppressions []codeClientSarif.Suppression) (bool, *IgnoreDetails) {
	suppression, suppressionStatus := sarifutils.GetHighestSuppression(suppressions)
	isIgnored := suppressionStatus == codeClientSarif.Accepted
	ignoreDetails := sarifSuppressionToIgnoreDetails(suppression)
	return isIgnored, ignoreDetails
}

func sarifSuppressionToIgnoreDetails(suppression *codeClientSarif.Suppression) *IgnoreDetails {
	if suppression == nil {
		return nil
	}

	reason := suppression.Justification
	if reason == "" {
		reason = "None given"
	}
	ignoreDetails := &IgnoreDetails{
		Category:   string(suppression.Properties.Category),
		Reason:     reason,
		Expiration: parseExpirationDateFromString(suppression.Properties.Expiration),
		IgnoredOn:  parseDateFromString(suppression.Properties.IgnoredOn),
		IgnoredBy:  suppression.Properties.IgnoredBy.Name,
		Status:     suppression.Status,
	}
	return ignoreDetails
}

func parseExpirationDateFromString(date *string) string {
	if date == nil {
		return ""
	}

	parsedDate := parseDateFromString(*date)
	return parsedDate.Format(time.RFC3339)
}

func parseDateFromString(date string) time.Time {
	layouts := []string{
		"Mon Jan 02 2006",
		time.RFC3339,
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, date); err == nil {
			return t
		}
	}

	return time.Now().UTC()
}

func ToAbsolutePath(baseDir types.FilePath, relativePath types.FilePath) string {
	return filepath.Join(string(baseDir), string(relativePath))
}

func DecodePath(encodedRelativePath string) (string, error) {
	return url.PathUnescape(encodedRelativePath)
}
