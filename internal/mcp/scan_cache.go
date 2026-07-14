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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/studio-mcp/internal/code"
	"github.com/snyk/studio-mcp/internal/oss"
	"github.com/snyk/studio-mcp/internal/types"
)

type scanType string

const (
	scanTypeSAST scanType = "sast"
	scanTypeSCA  scanType = "sca"
)

// verificationState is the per-call tag attached to a snyk_send_feedback
// analytics event, summarizing how well fixedIssueIds/preventedIssueIds claims
// checked out against the scan-result cache.
type verificationState string

const (
	verificationVerified     verificationState = "verified"
	verificationUnverifiable verificationState = "unverifiable"
	verificationMismatch     verificationState = "mismatch"
)

// verificationPrecedence orders states from weakest to strongest signal for
// the worst-case reduction below: mismatch > unverifiable > verified.
var verificationPrecedence = map[verificationState]int{
	verificationVerified:     1,
	verificationUnverifiable: 2,
	verificationMismatch:     3,
}

// scanCacheEntry is the freshest known finding set for one file path, as
// reported by the most recent snyk_code_scan/snyk_sca_scan call whose results
// included that file. ids are already scan-type-prefixed (e.g. "sast:rule",
// "sca:SNYK-JS-...") so they can be compared directly against
// fixedIssueIds/preventedIssueIds entries.
type scanCacheEntry struct {
	scanType  scanType
	ids       map[string]struct{}
	updatedAt time.Time
}

type scanCache struct {
	entries map[string]*scanCacheEntry

	// caps the scan-result cache at the maxEntries most-recently updated files.
	// When a new distinct file path would exceed the cap, the least-recently
	// updated entry is evicted first.
	maxEntries int
}

func (s *scanCache) UpdateSASTIssues(workDir string, issues []types.IssueData) {
	now := time.Now()
	s.clearEntries(now, scanTypeSAST, workDir, issues)
	s.addEntries(now, scanTypeSAST, issues)
}

func (s *scanCache) UpdateSCAIssues(manifestFile string, issues []types.IssueData) {
	now := time.Now()
	s.clearEntries(now, scanTypeSCA, manifestFile, issues)
	s.addEntries(now, scanTypeSCA, issues)
}

func (m *scanCache) VerifyID(id string) verificationState {
	scanType, ok := scanTypeFromID(id)
	if !ok {
		// No recognized scan-type prefix (including an empty string or a
		// typo'd prefix): there's no relevant scan type to check against.
		return verificationUnverifiable
	}

	foundRelevantScan := false
	for _, entry := range m.entries {
		if entry.scanType != scanType {
			continue
		}
		foundRelevantScan = true
		if _, present := entry.ids[id]; present {
			return verificationMismatch
		}
	}
	if !foundRelevantScan {
		return verificationUnverifiable
	}

	return verificationVerified
}

func (s *scanCache) clearEntries(now time.Time, scanType scanType, path string, issues []types.IssueData) {
	if info, err := os.Stat(path); err == nil {
		if info.IsDir() {
			for filePath, entry := range s.entries {
				if entry.scanType != scanType {
					continue
				}

				if isWithinDir(filePath, path) {
					entry.ids = make(map[string]struct{})
					entry.updatedAt = now
				}
			}
		} else {
			if entry, ok := s.entries[path]; ok {
				entry.ids = make(map[string]struct{})
				entry.updatedAt = now
			} else {
				s.entries[path] = &scanCacheEntry{
					scanType:  scanType,
					ids:       map[string]struct{}{},
					updatedAt: now,
				}
			}
		}
	}
}

func (s *scanCache) addEntries(now time.Time, scanType scanType, issues []types.IssueData) {
	// Group issue IDs by file path
	prefix := string(scanType + ":")
	idsByFile := make(map[string]map[string]struct{})
	for _, issue := range issues {
		if issue.FilePath == "" || issue.ID == "" {
			continue
		}
		set, ok := idsByFile[issue.FilePath]
		if !ok {
			set = make(map[string]struct{})
			idsByFile[issue.FilePath] = set
		}
		set[prefix+issue.ID] = struct{}{}
	}

	// Insert grouped ids (it's ok to over-insert, we will evict excess entries before we return)
	for filePath, ids := range idsByFile {
		s.entries[filePath] = &scanCacheEntry{
			scanType:  scanType,
			ids:       ids,
			updatedAt: now,
		}
	}

	// Evict excess issues
	// TODO: this is an N^2 solution.
	// We need a different data structure to bring the runtime down
	for len(s.entries) > s.maxEntries {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for key, entry := range s.entries {
			if first || entry.updatedAt.Before(oldestTime) {
				oldestKey = key
				oldestTime = entry.updatedAt
				first = false
			}
		}
		if oldestKey != "" {
			delete(s.entries, oldestKey)
		}
	}
}

func parseScanOutput(logger *zerolog.Logger, toolDef SnykMcpToolsDefinition, output string, workDir string, includeIgnores bool) (scanType, []types.IssueData, error) {
	switch toolDef.Name {
	case ToolName.CodeTest:
		issues, err := code.ConvertSARIFJSONToIssues(logger, []byte(output), workDir, includeIgnores)
		return scanTypeSAST, issues, err
	case ToolName.ScaTest:
		issues, err := oss.ConvertOssJsonToIssues(workDir, []byte(output), includeIgnores)
		return scanTypeSCA, issues, err
	default:
		return "", nil, fmt.Errorf("unsupported tool name %q", toolDef.Name)
	}
}

// isWithinDir reports whether filePath is dir itself or nested inside it,
// comparing cleaned paths so callers don't need to worry about trailing
// separators or relative segments.
func isWithinDir(filePath, dir string) bool {
	cleanDir := filepath.Clean(dir)
	cleanFile := filepath.Clean(filePath)
	if cleanFile == cleanDir {
		return true
	}
	rel, err := filepath.Rel(cleanDir, cleanFile)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// scanTypeFromID extracts the scan type from a scan-type-prefixed issue ID
// ("sast:"/"sca:"). ok is false for an empty string or an unrecognized prefix.
func scanTypeFromID(id string) (scanType scanType, ok bool) {
	switch {
	case strings.HasPrefix(id, "sast:"):
		return scanTypeSAST, true
	case strings.HasPrefix(id, "sca:"):
		return scanTypeSCA, true
	default:
		return "", false
	}
}
