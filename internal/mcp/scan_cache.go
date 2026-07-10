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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/studio-mcp/internal/code"
	"github.com/snyk/studio-mcp/internal/oss"
	"github.com/snyk/studio-mcp/internal/types"
)

// maxScanCacheEntries caps the scan-result cache at the 500 most-recently-updated
// files. When a new distinct file path would exceed the cap, the
// least-recently-updated entry is evicted first. This is a defensive bound, not
// a tuned production limit.
const maxScanCacheEntries = 500

const (
	scanTypeSAST = "sast"
	scanTypeSCA  = "sca"
)

// scanCacheEntry is the freshest known finding set for one file path, as
// reported by the most recent snyk_code_scan/snyk_sca_scan call whose results
// included that file. ids are already scan-type-prefixed (e.g. "sast:rule",
// "sca:SNYK-JS-...") so they can be compared directly against
// fixedIssueIds/preventedIssueIds entries.
type scanCacheEntry struct {
	scanType  string
	ids       map[string]struct{}
	updatedAt time.Time
}

// updateScanCache upserts one cache entry per file path found in a successful
// scan's own results - SARIF artifactLocation.uri for SAST, the scan's
// reported manifest path (DisplayTargetFile/Path) for SCA - not by the tool
// call's own path argument. Both scan types are keyed symmetrically by file
// path. Files the scan didn't report on are left untouched;
// only files present in this scan's results are upserted, and each upsert
// fully replaces that file's previous record with this scan's findings.
//
// The tool call's own workDir argument additionally seeds cache upserts for
// files/directories that a fresh, clean scan covers but reported no issues
// for - without this, a scan that becomes clean could never supersede an
// earlier scan's stale, still-vulnerable record for the same scope, since a
// scan with fewer (or zero) issues produces fewer (or no) idsByFile entries
// on its own. When workDir is a single file, that scan is authoritative for
// that exact file. When workDir is a directory, that scan is authoritative
// for every file already cached (of the same scan type) within that
// directory tree, on the assumption - true for this tool's default
// all_projects/recursive scanning - that a directory scan comprehensively
// covers its own scope. Without this, a genuinely successful fix could be
// tagged verification=mismatch because the cache never learned its file,
// then its containing directory, had become clean.
func (m *McpLLMBinding) updateScanCache(logger *zerolog.Logger, toolDef SnykMcpToolsDefinition, output string, workDir string, includeIgnores bool) {
	var scanType string
	var issues []types.IssueData
	var err error

	switch toolDef.Name {
	case ToolName.CodeTest:
		scanType = scanTypeSAST
		issues, err = code.ConvertSARIFJSONToIssues(logger, []byte(output), workDir, includeIgnores)
	case ToolName.ScaTest:
		scanType = scanTypeSCA
		issues, err = oss.ConvertOssJsonToIssues(workDir, []byte(output), includeIgnores)
	default:
		return
	}
	if err != nil {
		if logger != nil {
			logger.Debug().Err(err).Str("toolName", toolDef.Name).Msg("Failed to parse scan output for scan-result cache; leaving cache unchanged")
		}
		return
	}

	prefix := scanType + ":"
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

	m.scanCacheMu.Lock()
	defer m.scanCacheMu.Unlock()

	if m.scanCache == nil {
		m.scanCache = make(map[string]*scanCacheEntry)
	}

	if info, statErr := os.Stat(workDir); statErr == nil {
		if info.IsDir() {
			for filePath, entry := range m.scanCache {
				if entry.scanType != scanType {
					continue
				}
				if _, alreadyCovered := idsByFile[filePath]; alreadyCovered {
					continue
				}
				if isWithinDir(filePath, workDir) {
					idsByFile[filePath] = make(map[string]struct{})
				}
			}
		} else if _, alreadyPresent := idsByFile[workDir]; !alreadyPresent {
			idsByFile[workDir] = make(map[string]struct{})
		}
	}

	if len(idsByFile) == 0 {
		return
	}

	now := time.Now()
	for filePath, ids := range idsByFile {
		if _, exists := m.scanCache[filePath]; !exists && len(m.scanCache) >= maxScanCacheEntries {
			m.evictLeastRecentlyUpdatedLocked()
		}
		m.scanCache[filePath] = &scanCacheEntry{
			scanType:  scanType,
			ids:       ids,
			updatedAt: now,
		}
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

// evictLeastRecentlyUpdatedLocked removes the entry with the oldest updatedAt
// timestamp. Callers must hold scanCacheMu.
func (m *McpLLMBinding) evictLeastRecentlyUpdatedLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for key, entry := range m.scanCache {
		if first || entry.updatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.updatedAt
			first = false
		}
	}
	if oldestKey != "" {
		delete(m.scanCache, oldestKey)
	}
}

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

// verifyIDs resolves a single event-level verification state for a combined
// list of fixedIssueIds/preventedIssueIds by determining each ID's individual
// state and reducing by worst-case precedence. Returns "" when
// ids is empty, signaling callers should omit the verification tag entirely
// since there is nothing to verify.
func (m *McpLLMBinding) verifyIDs(ids []string) verificationState {
	if len(ids) == 0 {
		return ""
	}

	m.scanCacheMu.Lock()
	defer m.scanCacheMu.Unlock()

	worst := verificationVerified
	for _, id := range ids {
		state := m.verifyIDLocked(id)
		if verificationPrecedence[state] > verificationPrecedence[worst] {
			worst = state
		}
	}
	return worst
}

// verifyIDLocked determines the verification state of a single claimed ID by
// scanning the freshest cached record of every cached file of the relevant
// scan type (IDs carry no file information, so there is no single "its file"
// record to check). Callers must hold scanCacheMu.
func (m *McpLLMBinding) verifyIDLocked(id string) verificationState {
	scanType, ok := scanTypeFromID(id)
	if !ok {
		// No recognized scan-type prefix (including an empty string or a
		// typo'd prefix): there's no relevant scan type to check against.
		return verificationUnverifiable
	}

	foundRelevantScan := false
	for _, entry := range m.scanCache {
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

// scanTypeFromID extracts the scan type from a scan-type-prefixed issue ID
// ("sast:"/"sca:"). ok is false for an empty string or an unrecognized prefix.
func scanTypeFromID(id string) (scanType string, ok bool) {
	switch {
	case strings.HasPrefix(id, "sast:"):
		return scanTypeSAST, true
	case strings.HasPrefix(id, "sca:"):
		return scanTypeSCA, true
	default:
		return "", false
	}
}
