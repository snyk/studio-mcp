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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// nopLoggerForCache is a shared discard logger for cache tests that call
// updateScanCache directly without a full test fixture.
var nopLoggerForCache = zerolog.New(io.Discard)

// newCacheTestBinding returns a bare McpLLMBinding suitable for exercising
// scan_cache.go directly, without the rest of the tool-call machinery.
func newCacheTestBinding() *McpLLMBinding {
	return NewMcpLLMBinding()
}

// -----------------------------------------------------------------------
// Task 3.2 / 6.2: cache upsert keyed by file path found in scan results.
// -----------------------------------------------------------------------

func TestUpdateScanCache_SASTKeyedByResultFilePath(t *testing.T) {
	binding := newCacheTestBinding()
	toolDef := SnykMcpToolsDefinition{Name: ToolName.CodeTest}

	sarif := `{"runs":[{"tool":{"driver":{"rules":[
		{"id":"javascript/SqlInjection","shortDescription":{"text":"SQL Injection"},"properties":{"categories":["Security"]}},
		{"id":"javascript/XSS","shortDescription":{"text":"XSS"},"properties":{"categories":["Security"]}}
	]}},"results":[
		{"ruleId":"javascript/SqlInjection","level":"error","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/db.ts"},"region":{"startLine":1,"startColumn":1}}}]},
		{"ruleId":"javascript/XSS","level":"warning","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/view.ts"},"region":{"startLine":2,"startColumn":1}}}]}
	]}]}`

	binding.updateScanCache(&nopLoggerForCache, toolDef, sarif, "/repo", false)

	binding.scanCacheMu.Lock()
	defer binding.scanCacheMu.Unlock()

	require.Len(t, binding.scanCache, 2)

	dbEntry, ok := binding.scanCache["/repo/src/db.ts"]
	require.True(t, ok, "expected an entry keyed by the SARIF artifactLocation.uri resolved against the scan's basePath")
	require.Equal(t, scanTypeSAST, dbEntry.scanType)
	_, hasID := dbEntry.ids["sast:javascript/SqlInjection"]
	require.True(t, hasID)

	viewEntry, ok := binding.scanCache["/repo/src/view.ts"]
	require.True(t, ok)
	_, hasID = viewEntry.ids["sast:javascript/XSS"]
	require.True(t, hasID)
}

func TestUpdateScanCache_SCAKeyedByManifestPath(t *testing.T) {
	binding := newCacheTestBinding()
	toolDef := SnykMcpToolsDefinition{Name: ToolName.ScaTest}

	// displayTargetFile is a lockfile (as the Snyk CLI commonly reports for npm
	// projects); getAbsTargetFilePath resolves this to the sibling manifest
	// (package.json) joined against the scan's working directory.
	scaOutput := `{"ok":false,"displayTargetFile":"package-lock.json","vulnerabilities":[
		{"id":"SNYK-JS-LODASH-1234567","title":"Prototype Pollution","severity":"high","packageName":"lodash","version":"4.17.15","from":["my-app@1.0.0","lodash@4.17.15"],"packageManager":"npm"}
	]}`

	binding.updateScanCache(&nopLoggerForCache, toolDef, scaOutput, "/repo", false)

	binding.scanCacheMu.Lock()
	defer binding.scanCacheMu.Unlock()

	require.Len(t, binding.scanCache, 1)
	entry, ok := binding.scanCache["/repo/package.json"]
	require.True(t, ok, "expected an entry keyed by the SCA scan's reported manifest path")
	require.Equal(t, scanTypeSCA, entry.scanType)
	_, hasID := entry.ids["sca:SNYK-JS-LODASH-1234567"]
	require.True(t, hasID)
}

func TestUpdateScanCache_LaterNarrowerScanOverwritesSameFile(t *testing.T) {
	// "Cache reflects the most recent scan of a file regardless of invocation
	// path": a broad scan reports one finding for src/db.ts, then a later,
	// narrower scan of the same file reports a different finding set; the
	// cache's record for that file must reflect the later scan.
	binding := newCacheTestBinding()
	toolDef := SnykMcpToolsDefinition{Name: ToolName.CodeTest}

	broadSarif := `{"runs":[{"tool":{"driver":{"rules":[
		{"id":"javascript/SqlInjection","shortDescription":{"text":"SQLi"},"properties":{"categories":["Security"]}}
	]}},"results":[
		{"ruleId":"javascript/SqlInjection","level":"error","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/db.ts"},"region":{"startLine":1,"startColumn":1}}}]}
	]}]}`
	binding.updateScanCache(&nopLoggerForCache, toolDef, broadSarif, "/repo", false)

	narrowerSarif := `{"runs":[{"tool":{"driver":{"rules":[
		{"id":"javascript/XSS","shortDescription":{"text":"XSS"},"properties":{"categories":["Security"]}}
	]}},"results":[
		{"ruleId":"javascript/XSS","level":"warning","locations":[{"physicalLocation":{"artifactLocation":{"uri":"db.ts"},"region":{"startLine":5,"startColumn":1}}}]}
	]}]}`
	binding.updateScanCache(&nopLoggerForCache, toolDef, narrowerSarif, "/repo/src", false)

	binding.scanCacheMu.Lock()
	defer binding.scanCacheMu.Unlock()

	entry, ok := binding.scanCache["/repo/src/db.ts"]
	require.True(t, ok)
	_, hasOld := entry.ids["sast:javascript/SqlInjection"]
	require.False(t, hasOld, "the stale finding from the broad scan must not survive the later, narrower scan")
	_, hasNew := entry.ids["sast:javascript/XSS"]
	require.True(t, hasNew, "the cache must reflect the later scan's findings")
}

func TestUpdateScanCache_CleanSingleFileRescanClearsStaleVulnerableRecord(t *testing.T) {
	// Regression test for a bug found via manual end-to-end testing (task
	// 6.5): a genuinely clean re-scan targeted at a single just-fixed file
	// must supersede an earlier scan's stale, still-vulnerable record for
	// that same file, even though the clean scan reports zero issues (a
	// zero-issue result previously produced no idsByFile entries at all, so
	// the stale record was never superseded and verification wrongly read
	// "mismatch" for a fix that had actually succeeded).
	binding := newCacheTestBinding()
	toolDef := SnykMcpToolsDefinition{Name: ToolName.CodeTest}

	dir := t.TempDir()
	filePath := filepath.Join(dir, "vuln.go")
	require.NoError(t, os.WriteFile(filePath, []byte("package main\n"), 0o600))

	vulnerableSarif := `{"runs":[{"tool":{"driver":{"rules":[
		{"id":"go/CommandInjection","shortDescription":{"text":"Command Injection"},"properties":{"categories":["Security"]}}
	]}},"results":[
		{"ruleId":"go/CommandInjection","level":"error","locations":[{"physicalLocation":{"artifactLocation":{"uri":"vuln.go"},"region":{"startLine":1,"startColumn":1}}}]}
	]}]}`
	binding.updateScanCache(&nopLoggerForCache, toolDef, vulnerableSarif, dir, false)

	binding.scanCacheMu.Lock()
	_, hasVuln := binding.scanCache[filePath]
	binding.scanCacheMu.Unlock()
	require.True(t, hasVuln, "sanity check: the vulnerable finding must be cached before the clean re-scan")

	cleanSarif := `{"runs":[{"tool":{"driver":{"rules":[]}},"results":[]}]}`
	binding.updateScanCache(&nopLoggerForCache, toolDef, cleanSarif, filePath, false)

	binding.scanCacheMu.Lock()
	entry, ok := binding.scanCache[filePath]
	binding.scanCacheMu.Unlock()
	require.True(t, ok, "the file's cache entry must still exist after the clean re-scan")
	require.Empty(t, entry.ids, "a clean single-file re-scan must clear the stale vulnerable record")
}

func TestUpdateScanCache_CleanDirectoryRescanClearsStaleVulnerableRecord(t *testing.T) {
	// Regression test for the directory-scoped counterpart to the single-file
	// bug above, found via manual end-to-end testing (task 6.5): an SCA
	// validation re-scan targeted at the whole project directory (the normal
	// shape for snyk_sca_scan, unlike a single-file SAST re-scan) reported
	// zero issues after a dependency fix, but the discovery scan's stale
	// go.mod finding was never cleared because a directory-targeted,
	// zero-issue scan produced no idsByFile entries to upsert at all.
	binding := newCacheTestBinding()
	toolDef := SnykMcpToolsDefinition{Name: ToolName.ScaTest}

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "go.mod")
	require.NoError(t, os.WriteFile(manifestPath, []byte("module example\n"), 0o600))

	// displayTargetFile is the lockfile (go.sum), which getAbsTargetFilePath
	// resolves to the sibling manifest (go.mod) joined against workDir - same
	// resolution TestUpdateScanCache_SCAKeyedByManifestPath relies on.
	vulnerableOssJSON := `{
		"vulnerabilities": [{"id":"SNYK-GOLANG-STDNETHTTP-16535158","packageName":"std/net/http","version":"1.26.0"}],
		"displayTargetFile": "go.sum"
	}`
	binding.updateScanCache(&nopLoggerForCache, toolDef, vulnerableOssJSON, dir, false)

	binding.scanCacheMu.Lock()
	_, hasVuln := binding.scanCache[manifestPath]
	binding.scanCacheMu.Unlock()
	require.True(t, hasVuln, "sanity check: the vulnerable finding must be cached before the clean re-scan")

	cleanOssJSON := `{"vulnerabilities": [], "displayTargetFile": "go.sum"}`
	binding.updateScanCache(&nopLoggerForCache, toolDef, cleanOssJSON, dir, false)

	binding.scanCacheMu.Lock()
	entry, ok := binding.scanCache[manifestPath]
	binding.scanCacheMu.Unlock()
	require.True(t, ok, "the manifest's cache entry must still exist after the clean directory re-scan")
	require.Empty(t, entry.ids, "a clean directory re-scan must clear the stale vulnerable record for files within it")
}

func TestUpdateScanCache_DirectoryRescanDoesNotClearFilesOutsideItsScope(t *testing.T) {
	// A directory scan must only clear cached entries within its own scope -
	// a cached file under an unrelated directory (of the same scan type)
	// must be left untouched.
	binding := newCacheTestBinding()
	toolDef := SnykMcpToolsDefinition{Name: ToolName.ScaTest}

	scannedDir := t.TempDir()
	otherDir := t.TempDir()
	otherManifest := filepath.Join(otherDir, "go.mod")

	binding.scanCacheMu.Lock()
	binding.scanCache = map[string]*scanCacheEntry{
		otherManifest: {
			scanType:  scanTypeSCA,
			ids:       map[string]struct{}{"sca:SNYK-OTHER-VULN": {}},
			updatedAt: time.Now(),
		},
	}
	binding.scanCacheMu.Unlock()

	cleanOssJSON := `{"vulnerabilities": [], "displayTargetFile": "go.mod"}`
	binding.updateScanCache(&nopLoggerForCache, toolDef, cleanOssJSON, scannedDir, false)

	binding.scanCacheMu.Lock()
	entry, ok := binding.scanCache[otherManifest]
	binding.scanCacheMu.Unlock()
	require.True(t, ok)
	_, stillHasVuln := entry.ids["sca:SNYK-OTHER-VULN"]
	require.True(t, stillHasVuln, "a directory scan must not clear cached entries outside its own scope")
}

func TestUpdateScanCache_FilesNotInScanResultsAreUnaffected(t *testing.T) {
	// "Cache is unaffected by scans that never touch a given file."
	binding := newCacheTestBinding()
	toolDef := SnykMcpToolsDefinition{Name: ToolName.CodeTest}

	first := `{"runs":[{"tool":{"driver":{"rules":[
		{"id":"javascript/SqlInjection","shortDescription":{"text":"SQLi"},"properties":{"categories":["Security"]}}
	]}},"results":[
		{"ruleId":"javascript/SqlInjection","level":"error","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/other.ts"},"region":{"startLine":1,"startColumn":1}}}]}
	]}]}`
	binding.updateScanCache(&nopLoggerForCache, toolDef, first, "/repo", false)

	binding.scanCacheMu.Lock()
	before := binding.scanCache["/repo/src/other.ts"]
	binding.scanCacheMu.Unlock()
	require.NotNil(t, before)

	// A second scan that reports no findings for src/other.ts at all (outside its scope).
	second := `{"runs":[{"tool":{"driver":{"rules":[
		{"id":"javascript/XSS","shortDescription":{"text":"XSS"},"properties":{"categories":["Security"]}}
	]}},"results":[
		{"ruleId":"javascript/XSS","level":"warning","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/unrelated.ts"},"region":{"startLine":1,"startColumn":1}}}]}
	]}]}`
	binding.updateScanCache(&nopLoggerForCache, toolDef, second, "/repo", false)

	binding.scanCacheMu.Lock()
	after := binding.scanCache["/repo/src/other.ts"]
	binding.scanCacheMu.Unlock()

	require.Equal(t, before, after, "entry for a file untouched by the later scan must be left unchanged")
}

func TestUpdateScanCache_IgnoresUnrelatedToolsAndMalformedOutput(t *testing.T) {
	binding := newCacheTestBinding()

	t.Run("non-scan tool is a no-op", func(t *testing.T) {
		binding.updateScanCache(&nopLoggerForCache, SnykMcpToolsDefinition{Name: ToolName.Version}, `{"ok":true}`, "/repo", false)
		binding.scanCacheMu.Lock()
		defer binding.scanCacheMu.Unlock()
		require.Empty(t, binding.scanCache)
	})

	t.Run("malformed JSON does not panic and leaves cache unchanged", func(t *testing.T) {
		require.NotPanics(t, func() {
			binding.updateScanCache(&nopLoggerForCache, SnykMcpToolsDefinition{Name: ToolName.CodeTest}, "not json", "/repo", false)
		})
		binding.scanCacheMu.Lock()
		defer binding.scanCacheMu.Unlock()
		require.Empty(t, binding.scanCache)
	})
}

// -----------------------------------------------------------------------
// Task 3.3 / 6.2: 500-entry cap, evicting least-recently-updated first.
// -----------------------------------------------------------------------

func TestScanCacheEviction_501stDistinctFileEvictsLeastRecentlyUpdated(t *testing.T) {
	binding := newCacheTestBinding()
	toolDef := SnykMcpToolsDefinition{Name: ToolName.CodeTest}

	sarifForFile := func(file string) string {
		return fmt.Sprintf(`{"runs":[{"tool":{"driver":{"rules":[
			{"id":"javascript/Rule","shortDescription":{"text":"Rule"},"properties":{"categories":["Security"]}}
		]}},"results":[
			{"ruleId":"javascript/Rule","level":"warning","locations":[{"physicalLocation":{"artifactLocation":{"uri":"%s"},"region":{"startLine":1,"startColumn":1}}}]}
		]}]}`, file)
	}

	// Fill the cache to exactly the cap, one distinct file per call so each
	// gets a distinct (increasing) updatedAt timestamp.
	for i := 0; i < maxScanCacheEntries; i++ {
		binding.updateScanCache(&nopLoggerForCache, toolDef, sarifForFile(fmt.Sprintf("file%d.ts", i)), "/repo", false)
	}

	binding.scanCacheMu.Lock()
	require.Len(t, binding.scanCache, maxScanCacheEntries)
	_, leastRecentStillPresent := binding.scanCache["/repo/file0.ts"]
	binding.scanCacheMu.Unlock()
	require.True(t, leastRecentStillPresent, "cache must not have evicted anything before reaching the cap")

	// One more distinct file pushes the cache over the cap; the
	// least-recently-updated entry (file0.ts, inserted first) must be evicted.
	binding.updateScanCache(&nopLoggerForCache, toolDef, sarifForFile("file-overflow.ts"), "/repo", false)

	binding.scanCacheMu.Lock()
	defer binding.scanCacheMu.Unlock()

	require.Len(t, binding.scanCache, maxScanCacheEntries, "cache must stay capped at maxScanCacheEntries")
	_, evicted := binding.scanCache["/repo/file0.ts"]
	require.False(t, evicted, "the least-recently-updated entry must be evicted first")
	_, newEntryPresent := binding.scanCache["/repo/file-overflow.ts"]
	require.True(t, newEntryPresent)
	// A file inserted partway through (neither oldest nor newest) must survive.
	_, midEntryPresent := binding.scanCache[fmt.Sprintf("/repo/file%d.ts", maxScanCacheEntries/2)]
	require.True(t, midEntryPresent)
}

func TestScanCacheEviction_ReUpsertingExistingFileDoesNotEvict(t *testing.T) {
	binding := newCacheTestBinding()
	toolDef := SnykMcpToolsDefinition{Name: ToolName.CodeTest}

	sarifForFile := func(file, ruleID string) string {
		return fmt.Sprintf(`{"runs":[{"tool":{"driver":{"rules":[
			{"id":"%s","shortDescription":{"text":"Rule"},"properties":{"categories":["Security"]}}
		]}},"results":[
			{"ruleId":"%s","level":"warning","locations":[{"physicalLocation":{"artifactLocation":{"uri":"%s"},"region":{"startLine":1,"startColumn":1}}}]}
		]}]}`, ruleID, ruleID, file)
	}

	for i := 0; i < maxScanCacheEntries; i++ {
		binding.updateScanCache(&nopLoggerForCache, toolDef, sarifForFile(fmt.Sprintf("file%d.ts", i), "javascript/Rule"), "/repo", false)
	}

	// Re-scanning an already-cached file at the cap must not evict anything,
	// since the total distinct-file count doesn't grow.
	binding.updateScanCache(&nopLoggerForCache, toolDef, sarifForFile("file0.ts", "javascript/RuleV2"), "/repo", false)

	binding.scanCacheMu.Lock()
	defer binding.scanCacheMu.Unlock()

	require.Len(t, binding.scanCache, maxScanCacheEntries)
	entry, ok := binding.scanCache["/repo/file0.ts"]
	require.True(t, ok)
	_, hasNewID := entry.ids["sast:javascript/RuleV2"]
	require.True(t, hasNewID, "the re-scanned file's record must reflect the newer findings")
}

// -----------------------------------------------------------------------
// Task 3.4 / 3.5 / 6.3: per-ID verification state and worst-case precedence.
// -----------------------------------------------------------------------

func TestVerifyIDs_EmptyListOmitsVerification(t *testing.T) {
	binding := newCacheTestBinding()
	require.Equal(t, verificationState(""), binding.verifyIDs(nil))
	require.Equal(t, verificationState(""), binding.verifyIDs([]string{}))
}

func TestVerifyIDs_ColdCacheAtSessionStartIsUnverifiable(t *testing.T) {
	// No scan has run yet in this process: the cache is entirely empty, not
	// just missing the relevant scan type. Per design.md D4, this must
	// resolve to unverifiable, never verified.
	binding := newCacheTestBinding()
	require.Equal(t, verificationUnverifiable, binding.verifyIDs([]string{"sast:javascript/SqlInjection"}))
	require.Equal(t, verificationUnverifiable, binding.verifyIDs([]string{"sca:SNYK-JS-LODASH-1234567"}))
}

func TestVerifyIDs_MalformedOrUnrecognizedPrefixIsUnverifiable(t *testing.T) {
	binding := newCacheTestBinding()
	// Seed some cache data so we can be sure it's the prefix, not an empty
	// cache, driving the result.
	binding.scanCache = map[string]*scanCacheEntry{
		"/repo/src/db.ts": {scanType: scanTypeSAST, ids: map[string]struct{}{"sast:javascript/SqlInjection": {}}, updatedAt: time.Now()},
	}

	require.Equal(t, verificationUnverifiable, binding.verifyIDs([]string{""}), "empty string has no recognized prefix")
	require.Equal(t, verificationUnverifiable, binding.verifyIDs([]string{"iac:CKV_AWS_1"}), "unrecognized prefix")
	require.Equal(t, verificationUnverifiable, binding.verifyIDs([]string{"sast"}), "missing colon separator")
}

func TestVerifyIDs_VerifiedWhenAbsentFromEveryRelevantCachedFile(t *testing.T) {
	binding := newCacheTestBinding()
	binding.scanCache = map[string]*scanCacheEntry{
		"/repo/src/a.ts": {scanType: scanTypeSAST, ids: map[string]struct{}{"sast:javascript/XSS": {}}, updatedAt: time.Now()},
		"/repo/src/b.ts": {scanType: scanTypeSAST, ids: map[string]struct{}{"sast:javascript/CSRF": {}}, updatedAt: time.Now()},
	}

	require.Equal(t, verificationVerified, binding.verifyIDs([]string{"sast:javascript/SqlInjection"}))
}

func TestVerifyIDs_UnverifiableWhenNoCachedFileOfRelevantScanType(t *testing.T) {
	binding := newCacheTestBinding()
	// Only SCA data cached; a SAST claim has no relevant scan type to check against.
	binding.scanCache = map[string]*scanCacheEntry{
		"/repo/package.json": {scanType: scanTypeSCA, ids: map[string]struct{}{"sca:SNYK-JS-LODASH-1234567": {}}, updatedAt: time.Now()},
	}

	require.Equal(t, verificationUnverifiable, binding.verifyIDs([]string{"sast:javascript/SqlInjection"}))
}

func TestVerifyIDs_MismatchWhenStillPresentInSomeCachedFile(t *testing.T) {
	binding := newCacheTestBinding()
	binding.scanCache = map[string]*scanCacheEntry{
		"/repo/src/a.ts": {scanType: scanTypeSAST, ids: map[string]struct{}{"sast:javascript/SqlInjection": {}}, updatedAt: time.Now()},
	}

	require.Equal(t, verificationMismatch, binding.verifyIDs([]string{"sast:javascript/SqlInjection"}))
}

func TestVerifyIDs_MixedOutcomesResolveByWorstCasePrecedence(t *testing.T) {
	newBindingWithSASTCache := func() *McpLLMBinding {
		binding := newCacheTestBinding()
		binding.scanCache = map[string]*scanCacheEntry{
			"/repo/src/a.ts": {scanType: scanTypeSAST, ids: map[string]struct{}{"sast:javascript/StillThere": {}}, updatedAt: time.Now()},
		}
		return binding
	}

	t.Run("mismatch beats verified", func(t *testing.T) {
		binding := newBindingWithSASTCache()
		ids := []string{"sast:javascript/Fixed", "sast:javascript/StillThere"}
		require.Equal(t, verificationMismatch, binding.verifyIDs(ids))
	})

	t.Run("mismatch beats unverifiable", func(t *testing.T) {
		binding := newBindingWithSASTCache()
		// The sca: claim has no relevant (SCA) cache entries at all, so it's
		// individually unverifiable; the sast: claim mismatches.
		ids := []string{"sca:SNYK-UNRELATED-0000001", "sast:javascript/StillThere"}
		require.Equal(t, verificationMismatch, binding.verifyIDs(ids))
	})

	t.Run("unverifiable beats verified", func(t *testing.T) {
		binding := newBindingWithSASTCache()
		// sast:Fixed is individually verified (absent from the only SAST
		// record); the sca: claim has no relevant cache entries at all, so
		// it's individually unverifiable, which must still win overall.
		ids := []string{"sast:javascript/Fixed", "sca:SNYK-JS-UNRELATED-9999999"}
		require.Equal(t, verificationUnverifiable, binding.verifyIDs(ids))
	})
}

func TestScanTypeFromID(t *testing.T) {
	cases := []struct {
		id       string
		wantType string
		wantOK   bool
	}{
		{"sast:javascript/SqlInjection", scanTypeSAST, true},
		{"sca:SNYK-JS-LODASH-1234567", scanTypeSCA, true},
		{"", "", false},
		{"typo:foo", "", false},
		{"SAST:uppercase-not-recognized", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			gotType, gotOK := scanTypeFromID(tc.id)
			require.Equal(t, tc.wantOK, gotOK)
			require.Equal(t, tc.wantType, gotType)
		})
	}
}

// -----------------------------------------------------------------------
// Integration-level: cache population via the real defaultHandler, exercising
// the actual scan/tool-call path rather than calling updateScanCache directly.
// -----------------------------------------------------------------------

func TestDefaultHandler_ScanCache_BroadThenNarrowerScanSameFile(t *testing.T) {
	fixture := setupTestFixture(t)
	toolDef := getToolWithName(t, fixture.tools, ToolName.CodeTest)
	require.NotNil(t, toolDef)
	handler := fixture.binding.defaultHandler(fixture.invocationContext, *toolDef)
	tmpDir := t.TempDir()

	broadSarif := `{"runs":[{"tool":{"driver":{"rules":[
		{"id":"javascript/SqlInjection","shortDescription":{"text":"SQLi"},"properties":{"categories":["Security"]}}
	]}},"results":[
		{"ruleId":"javascript/SqlInjection","level":"error","locations":[{"physicalLocation":{"artifactLocation":{"uri":"db.ts"},"region":{"startLine":1,"startColumn":1}}}]}
	]}]}`
	fixture.mockCliOutput(broadSarif)

	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]interface{}{"path": tmpDir}}}
	result, err := handler(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	fixture.binding.scanCacheMu.Lock()
	entry, ok := fixture.binding.scanCache[strings.TrimRight(tmpDir, "/")+"/db.ts"]
	fixture.binding.scanCacheMu.Unlock()
	require.True(t, ok)
	_, hasBroad := entry.ids["sast:javascript/SqlInjection"]
	require.True(t, hasBroad)

	narrowerSarif := `{"runs":[{"tool":{"driver":{"rules":[
		{"id":"javascript/XSS","shortDescription":{"text":"XSS"},"properties":{"categories":["Security"]}}
	]}},"results":[
		{"ruleId":"javascript/XSS","level":"warning","locations":[{"physicalLocation":{"artifactLocation":{"uri":"db.ts"},"region":{"startLine":9,"startColumn":1}}}]}
	]}]}`
	fixture.mockCliOutput(narrowerSarif)

	result, err = handler(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	fixture.binding.scanCacheMu.Lock()
	entry, ok = fixture.binding.scanCache[strings.TrimRight(tmpDir, "/")+"/db.ts"]
	fixture.binding.scanCacheMu.Unlock()
	require.True(t, ok)
	_, hasOld := entry.ids["sast:javascript/SqlInjection"]
	require.False(t, hasOld, "the later scan's own real invocation path must supersede the earlier finding")
	_, hasNew := entry.ids["sast:javascript/XSS"]
	require.True(t, hasNew)
}
