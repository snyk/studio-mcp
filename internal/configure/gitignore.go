package configure

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog"
	gitignore "github.com/sabhiram/go-gitignore"
)

// resolveGitignorePath determines which .gitignore to use.
// It first checks if a .gitignore exists in the workspace directory, otherwise falls back to git root.
func resolveGitignorePath(workspacePath string, logger *zerolog.Logger) (string, error) {
	// First, check if .gitignore exists in workspace directory
	workspaceGitignore := filepath.Join(workspacePath, ".gitignore")
	if _, err := os.Stat(workspaceGitignore); err == nil {
		logger.Debug().Msgf("Using workspace .gitignore at %s", workspaceGitignore)
		return workspaceGitignore, nil
	}

	// Fall back to git root
	repo, err := git.PlainOpenWithOptions(workspacePath, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to open git repository: %w", err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get worktree: %w", err)
	}

	gitRoot := worktree.Filesystem.Root()
	gitignorePath := filepath.Join(gitRoot, ".gitignore")
	if _, err = os.Stat(gitignorePath); err == nil {
		logger.Debug().Msgf("Using git root .gitignore at %s", gitignorePath)
		return gitignorePath, nil
	}
	return "", fmt.Errorf("no .gitignore found in workspace or git root")
}

// addToGitIgnore adds a relative path to a .gitignore file.
// It first checks if a .gitignore exists in the workspace directory, otherwise falls back to git root.
func addToGitIgnore(workspacePath, relativePath string, logger *zerolog.Logger) error {
	gitignorePath, err := resolveGitignorePath(workspacePath, logger)
	if err != nil {
		return err
	}

	// Read existing content
	var content string
	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		return fmt.Errorf("failed to read .gitignore: %w", err)
	} else if !os.IsNotExist(err) {
		content = string(data)
	}

	// Check if the entry is already covered by existing gitignore patterns
	entry := strings.ReplaceAll(relativePath, "\\", "/")
	if content != "" {
		matcher := gitignore.CompileIgnoreLines(strings.Split(content, "\n")...)
		if matcher.MatchesPath(entry) {
			logger.Debug().Msgf("Entry %q is already covered by .gitignore patterns", entry)
			return nil
		}
	}

	// Append the entry
	newContent := content
	if len(newContent) > 0 && !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	newContent += entry + "\n"

	if err = os.WriteFile(gitignorePath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write .gitignore: %w", err)
	}

	logger.Debug().Msgf("Added %q to .gitignore at %s", entry, gitignorePath)
	return nil
}

// removeFromGitIgnore removes a specific entry from a .gitignore file.
// It first checks if a .gitignore exists in the workspace directory, otherwise falls back to git root.
func removeFromGitIgnore(workspacePath, relativePath string, logger *zerolog.Logger) error {
	gitignorePath, err := resolveGitignorePath(workspacePath, logger)
	if err != nil {
		return err
	}

	// Read existing content
	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		return fmt.Errorf("failed to read .gitignore: %w", err)
	}

	content := string(data)
	lines := strings.Split(content, "\n")
	entry := strings.ReplaceAll(relativePath, "\\", "/")

	// Filter out the exact entry
	var newLines []string
	found := false
	for _, line := range lines {
		if strings.TrimSpace(line) == entry {
			found = true
			continue
		}
		newLines = append(newLines, line)
	}

	if !found {
		logger.Debug().Msgf("Entry %q not found in .gitignore", entry)
		return nil
	}

	// Rebuild content
	newContent := strings.Join(newLines, "\n")

	// Clean up trailing empty lines but ensure single trailing newline if there's content
	newContent = strings.TrimRight(newContent, "\n")
	if len(newContent) > 0 {
		newContent += "\n"
	}

	if err = os.WriteFile(gitignorePath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write .gitignore: %w", err)
	}

	logger.Debug().Msgf("Removed %q from .gitignore at %s", entry, gitignorePath)
	return nil
}
