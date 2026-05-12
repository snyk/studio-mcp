package oss

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/snyk/studio-mcp/internal/types"
)

var lockFilesToManifestMap = map[string]string{
	"Gemfile.lock":      "Gemfile",
	"package-lock.json": "package.json",
	"yarn.lock":         "package.json",
	"Gopkg.lock":        "Gopkg.toml",
	"go.sum":            "go.mod",
	"composer.lock":     "composer.json",
	"Podfile.lock":      "Podfile",
	"poetry.lock":       "pyproject.toml",
}

func ConvertOssJsonToIssues(workDir string, res []byte, includeIgnores bool) ([]types.IssueData, error) {
	output := string(res)
	var scanResults []ScanResult
	if strings.HasPrefix(output, "[") {
		err := json.Unmarshal(res, &scanResults)
		if err != nil {
			err = errors.Join(err, fmt.Errorf("couldn't unmarshal CLI response. Input: %s", output))
			return nil, err
		}
	} else {
		var result ScanResult
		err := json.Unmarshal(res, &result)
		if err != nil {
			err = errors.Join(err, fmt.Errorf("couldn't unmarshal CLI response. Input: %s", output))
			return nil, err
		}
		scanResults = append(scanResults, result)
	}

	issues := ConvertToIssue(workDir, scanResults, includeIgnores)

	return issues, nil
}

func ConvertToIssue(workDir string, scanResults []ScanResult, includeIgnores bool) []types.IssueData {
	var allIssues []types.IssueData
	for _, res := range scanResults {
		issues := convertScanResultToIssues(workDir, &res, includeIgnores)
		allIssues = append(allIssues, issues...)
	}
	return allIssues
}

func convertScanResultToIssues(workDir string, res *ScanResult, includeIgnores bool) []types.IssueData {
	var issues []types.IssueData
	duplicateCheckMap := map[string]bool{}

	for _, issue := range res.Vulnerabilities {
		if !includeIgnores && issue.IsIgnored {
			continue
		}
		targetFilePath := getAbsTargetFilePath(workDir, res.DisplayTargetFile)
		duplicateKey := string(targetFilePath) + "|" + issue.Id + "|" + issue.PackageName
		if duplicateCheckMap[duplicateKey] {
			continue
		}
		snykIssue := toIssue(issue, targetFilePath)
		issues = append(issues, *snykIssue)
		duplicateCheckMap[duplicateKey] = true
	}
	return issues

}

func toIssue(issue ossIssue, targetFilePath string) *types.IssueData {
	title := issue.Title

	message := fmt.Sprintf(
		"%s affecting package %s. %s",
		title,
		issue.PackageName,
		issue.getRemediation(),
	)

	const maxLength = 200
	if len(message) > maxLength {
		message = message[:maxLength] + "... (Snyk)"
	}

	d := &types.IssueData{
		ID:                     issue.Id,
		Title:                  issue.Title,
		Severity:               issue.Severity,
		CWEs:                   issue.Identifiers.CWE,
		CVEs:                   issue.Identifiers.CVE,
		PackageName:            issue.PackageName,
		Version:                issue.Version,
		Ecosystem:              issue.PackageManager,
		FixedIn:                issue.FixedIn,
		Remediation:            issue.getRemediation(),
		FilePath:               targetFilePath,
		Message:                message,
		IsIgnored:              issue.IsIgnored,
		IsTransitiveDependency: isTransitiveDependency(issue),
		IntroducedThrough:      introducedThroughChain(issue),
	}

	return d
}

// isTransitiveDependency determines whether the vulnerable package was pulled
// in as a transitive (indirect) dependency or declared directly in the
// project's manifest.
//
// The Snyk CLI emits the dependency chain in `from`:
//   - from[0] is the project root (e.g. "my-app@1.0.0")
//   - from[1] is the direct dependency declared in the manifest
//   - from[2..n] are transitive packages on the path to the vulnerable package
//
// Return values:
//
//   - nil   — undeterminable. `from` is missing or has fewer than 2 entries
//     (e.g. the CLI omitted the chain, or the project root itself
//     is the affected package), so we cannot tell direct vs transitive
//     and we deliberately leave the field absent rather than guess.
//
//   - false — direct dependency. The chain has exactly 2 entries
//     (`[root, vulnerable]`) AND `from[1]` (with any `@version` suffix
//     stripped) matches `PackageName`. That means the vulnerable
//     package is declared directly in the manifest with no
//     intermediate hops.
//
//   - true  — transitive dependency. Either:
//     (a) the chain has more than 2 entries (there is at least one
//     intermediate package between the root and the vulnerable
//     package), OR
//     (b) the chain has exactly 2 entries but `from[1]` does not
//     match `PackageName` — e.g. the vulnerability is reported on a
//     bundled/aliased package whose entry in the manifest has a
//     different name than the affected package itself.
func isTransitiveDependency(issue ossIssue) *bool {
	if len(issue.From) < 2 {
		return nil
	}
	transitive := len(issue.From) != 2 || stripVersion(issue.From[1]) != issue.PackageName
	return &transitive
}

func introducedThroughChain(issue ossIssue) []string {
	if len(issue.From) < 3 {
		return nil
	}
	return slices.Clone(issue.From[1:])
}

func stripVersion(s string) string {
	if i := strings.LastIndex(s, "@"); i > 0 {
		return s[:i]
	}
	return s
}

func getAbsTargetFilePath(workDir string, displayTargetFile string) string {
	fileName := filepath.Base(displayTargetFile)
	manifestFileName := lockFilesToManifestMap[fileName]
	if manifestFileName == "" {
		return displayTargetFile
	}
	targetFilePath := strings.Replace(displayTargetFile, fileName, manifestFileName, 1)
	isAbs := filepath.IsAbs(targetFilePath)
	if isAbs {
		return targetFilePath
	}
	return filepath.Join(workDir, targetFilePath)
}

func (i *ossIssue) getUpgradeMessage() string {
	hasUpgradePath := len(i.UpgradePath) > 1
	if hasUpgradePath {
		upgradePath, ok := i.UpgradePath[1].(string)
		if !ok {
			return ""
		}
		return "Upgrade to " + upgradePath
	}
	return ""
}

func (i *ossIssue) getOutdatedDependencyMessage() string {
	remediationAdvice := fmt.Sprintf("Your dependencies are out of date, "+
		"otherwise you would be using a newer %s than %s@%s. ", i.Name, i.Name, i.Version)

	if i.PackageManager == "npm" || i.PackageManager == "yarn" || i.PackageManager == "yarn-workspace" {
		remediationAdvice += "Try relocking your lockfile or deleting node_modules and reinstalling" +
			" your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	} else {
		remediationAdvice += "Try reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	}
	return remediationAdvice
}

func (i *ossIssue) getRemediation() string {
	upgradeMessage := i.getUpgradeMessage()
	isOutdated := upgradeMessage != "" && len(i.UpgradePath) > 1 && len(i.From) > 1 && i.UpgradePath[1] == i.From[1]
	if i.IsUpgradable || i.IsPatchable {
		if isOutdated {
			if i.IsPatchable {
				return upgradeMessage
			} else {
				return i.getOutdatedDependencyMessage()
			}
		} else {
			return upgradeMessage
		}
	}
	return ""
}
