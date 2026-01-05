package configure

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupGitRepo(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()

	// Initialize a git repository using go-git
	_, err := git.PlainInit(tempDir, false)
	require.NoError(t, err, "failed to initialize git repo")

	return tempDir
}

func TestAddToGitIgnore(t *testing.T) {
	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger

	t.Run("adds entry to existing empty gitignore", func(t *testing.T) {
		repoDir := setupGitRepo(t)

		// Create empty .gitignore
		gitignorePath := filepath.Join(repoDir, ".gitignore")
		err := os.WriteFile(gitignorePath, []byte(""), 0644)
		require.NoError(t, err)

		err = addToGitIgnore(repoDir, ".snyk/rules", logger)
		require.NoError(t, err)

		content, err := os.ReadFile(gitignorePath)
		require.NoError(t, err)
		assert.Contains(t, string(content), ".snyk/rules")
	})

	t.Run("returns error when no gitignore exists", func(t *testing.T) {
		repoDir := setupGitRepo(t)

		err := addToGitIgnore(repoDir, ".snyk/rules", logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no .gitignore found")
	})

	t.Run("adds entry to existing gitignore", func(t *testing.T) {
		repoDir := setupGitRepo(t)

		// Create existing .gitignore
		gitignorePath := filepath.Join(repoDir, ".gitignore")
		err := os.WriteFile(gitignorePath, []byte("node_modules/\n*.log\n"), 0644)
		require.NoError(t, err)

		err = addToGitIgnore(repoDir, ".snyk/rules", logger)
		require.NoError(t, err)

		content, err := os.ReadFile(gitignorePath)
		require.NoError(t, err)
		contentStr := string(content)

		assert.Contains(t, contentStr, "node_modules/")
		assert.Contains(t, contentStr, "*.log")
		assert.Contains(t, contentStr, ".snyk/rules")
	})

	t.Run("skips if entry already covered by glob pattern", func(t *testing.T) {
		repoDir := setupGitRepo(t)

		// Create .gitignore with glob pattern that covers the entry
		gitignorePath := filepath.Join(repoDir, ".gitignore")
		err := os.WriteFile(gitignorePath, []byte(".snyk/*\n"), 0644)
		require.NoError(t, err)

		err = addToGitIgnore(repoDir, ".snyk/rules", logger)
		require.NoError(t, err)

		content, err := os.ReadFile(gitignorePath)
		require.NoError(t, err)
		contentStr := string(content)

		// Should not add duplicate entry since .snyk/* covers .snyk/rules
		assert.Equal(t, ".snyk/*\n", contentStr)
	})

	t.Run("skips if exact entry already exists", func(t *testing.T) {
		repoDir := setupGitRepo(t)

		// Create .gitignore with the exact entry
		gitignorePath := filepath.Join(repoDir, ".gitignore")
		err := os.WriteFile(gitignorePath, []byte(".snyk/rules\n"), 0644)
		require.NoError(t, err)

		err = addToGitIgnore(repoDir, ".snyk/rules", logger)
		require.NoError(t, err)

		content, err := os.ReadFile(gitignorePath)
		require.NoError(t, err)

		// Should not add duplicate
		assert.Equal(t, ".snyk/rules\n", string(content))
	})

	t.Run("works from subdirectory", func(t *testing.T) {
		repoDir := setupGitRepo(t)

		// Create .gitignore at repo root
		gitignorePath := filepath.Join(repoDir, ".gitignore")
		err := os.WriteFile(gitignorePath, []byte(""), 0644)
		require.NoError(t, err)

		// Create a subdirectory
		subDir := filepath.Join(repoDir, "src", "app")
		err = os.MkdirAll(subDir, 0755)
		require.NoError(t, err)

		// Call from subdirectory
		err = addToGitIgnore(subDir, ".snyk/rules", logger)
		require.NoError(t, err)

		content, err := os.ReadFile(gitignorePath)
		require.NoError(t, err)
		assert.Contains(t, string(content), ".snyk/rules")
	})

	t.Run("returns error for non-git directory", func(t *testing.T) {
		tempDir := t.TempDir() // Not a git repo

		err := addToGitIgnore(tempDir, ".snyk/rules", logger)
		assert.Error(t, err)
	})
}

func TestRemoveFromGitIgnore(t *testing.T) {
	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger

	t.Run("removes exact entry from gitignore", func(t *testing.T) {
		repoDir := setupGitRepo(t)

		// Create .gitignore with multiple entries
		gitignorePath := filepath.Join(repoDir, ".gitignore")
		err := os.WriteFile(gitignorePath, []byte("node_modules/\n.snyk/rules\n*.log\n"), 0644)
		require.NoError(t, err)

		err = removeFromGitIgnore(repoDir, ".snyk/rules", logger)
		require.NoError(t, err)

		content, err := os.ReadFile(gitignorePath)
		require.NoError(t, err)
		contentStr := string(content)

		assert.NotContains(t, contentStr, ".snyk/rules")
		assert.Contains(t, contentStr, "node_modules/")
		assert.Contains(t, contentStr, "*.log")
	})

	t.Run("returns error when no gitignore exists", func(t *testing.T) {
		repoDir := setupGitRepo(t)

		err := removeFromGitIgnore(repoDir, ".snyk/rules", logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no .gitignore found")
	})

	t.Run("handles entry not found gracefully", func(t *testing.T) {
		repoDir := setupGitRepo(t)

		// Create .gitignore without the entry
		gitignorePath := filepath.Join(repoDir, ".gitignore")
		originalContent := "node_modules/\n*.log\n"
		err := os.WriteFile(gitignorePath, []byte(originalContent), 0644)
		require.NoError(t, err)

		err = removeFromGitIgnore(repoDir, ".snyk/rules", logger)
		require.NoError(t, err)

		// Content should be unchanged
		content, err := os.ReadFile(gitignorePath)
		require.NoError(t, err)
		assert.Equal(t, originalContent, string(content))
	})

	t.Run("removes entry with whitespace trimming", func(t *testing.T) {
		repoDir := setupGitRepo(t)

		// Create .gitignore with entry that has trailing spaces
		gitignorePath := filepath.Join(repoDir, ".gitignore")
		err := os.WriteFile(gitignorePath, []byte("node_modules/\n.snyk/rules  \n*.log\n"), 0644)
		require.NoError(t, err)

		err = removeFromGitIgnore(repoDir, ".snyk/rules", logger)
		require.NoError(t, err)

		content, err := os.ReadFile(gitignorePath)
		require.NoError(t, err)
		contentStr := string(content)

		assert.NotContains(t, contentStr, ".snyk/rules")
		assert.Contains(t, contentStr, "node_modules/")
		assert.Contains(t, contentStr, "*.log")
	})

	t.Run("works from subdirectory", func(t *testing.T) {
		repoDir := setupGitRepo(t)

		// Create .gitignore at repo root
		gitignorePath := filepath.Join(repoDir, ".gitignore")
		err := os.WriteFile(gitignorePath, []byte(".snyk/rules\n"), 0644)
		require.NoError(t, err)

		// Create a subdirectory
		subDir := filepath.Join(repoDir, "src", "app")
		err = os.MkdirAll(subDir, 0755)
		require.NoError(t, err)

		// Call from subdirectory
		err = removeFromGitIgnore(subDir, ".snyk/rules", logger)
		require.NoError(t, err)

		content, err := os.ReadFile(gitignorePath)
		require.NoError(t, err)
		assert.NotContains(t, string(content), ".snyk/rules")
	})

	t.Run("returns error for non-git directory", func(t *testing.T) {
		tempDir := t.TempDir() // Not a git repo

		err := removeFromGitIgnore(tempDir, ".snyk/rules", logger)
		assert.Error(t, err)
	})

	t.Run("preserves file structure after removal", func(t *testing.T) {
		repoDir := setupGitRepo(t)

		// Create .gitignore with comments and blank lines
		gitignorePath := filepath.Join(repoDir, ".gitignore")
		originalContent := "# Dependencies\nnode_modules/\n\n# Snyk\n.snyk/rules\n\n# Logs\n*.log\n"
		err := os.WriteFile(gitignorePath, []byte(originalContent), 0644)
		require.NoError(t, err)

		err = removeFromGitIgnore(repoDir, ".snyk/rules", logger)
		require.NoError(t, err)

		content, err := os.ReadFile(gitignorePath)
		require.NoError(t, err)
		contentStr := string(content)

		assert.NotContains(t, contentStr, ".snyk/rules")
		assert.Contains(t, contentStr, "# Dependencies")
		assert.Contains(t, contentStr, "node_modules/")
		assert.Contains(t, contentStr, "# Snyk")
		assert.Contains(t, contentStr, "# Logs")
		assert.Contains(t, contentStr, "*.log")
	})
}

func TestAddAndRemoveGitIgnoreRoundTrip(t *testing.T) {
	nopLogger := zerolog.New(io.Discard)
	logger := &nopLogger

	t.Run("add then remove leaves gitignore clean", func(t *testing.T) {
		repoDir := setupGitRepo(t)

		// Create initial .gitignore
		gitignorePath := filepath.Join(repoDir, ".gitignore")
		originalContent := "node_modules/\n*.log\n"
		err := os.WriteFile(gitignorePath, []byte(originalContent), 0644)
		require.NoError(t, err)

		// Add entry
		err = addToGitIgnore(repoDir, ".snyk/rules", logger)
		require.NoError(t, err)

		// Verify entry was added
		content, err := os.ReadFile(gitignorePath)
		require.NoError(t, err)
		assert.Contains(t, string(content), ".snyk/rules")

		// Remove entry
		err = removeFromGitIgnore(repoDir, ".snyk/rules", logger)
		require.NoError(t, err)

		// Verify entry was removed and original content preserved
		content, err = os.ReadFile(gitignorePath)
		require.NoError(t, err)
		contentStr := string(content)

		assert.NotContains(t, contentStr, ".snyk/rules")
		assert.Contains(t, contentStr, "node_modules/")
		assert.Contains(t, contentStr, "*.log")
	})
}
