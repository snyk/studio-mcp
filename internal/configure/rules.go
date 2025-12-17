package configure

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/utils/git"
)

const (
	RuleStart = "<!--# BEGIN SNYK GLOBAL RULE -->"
	RuleEnd   = "<!--# END SNYK GLOBAL RULE -->"
)

// writeLocalRules writes rules to a workspace-relative path
func writeLocalRules(workspacePath, relativeRulesPath, rulesContent string, logger *zerolog.Logger) error {
	rulesPath := filepath.Join(workspacePath, relativeRulesPath)
	if workspacePath != "" {
		isPathSymlink, err := isSymlink(rulesPath)
		if err == nil && isPathSymlink {
			return fmt.Errorf("using symlinks for paths is not supported: %s", rulesPath)
		}
	}

	if err := os.MkdirAll(filepath.Dir(rulesPath), 0755); err != nil {
		return fmt.Errorf("failed to create rules directory: %w", err)
	}

	// Check if content is already up to date
	existing, err := os.ReadFile(rulesPath)
	if err == nil && string(existing) == rulesContent {
		logger.Debug().Msgf("Local rules already up to date at %s", rulesPath)
		return nil
	}

	if err := os.WriteFile(rulesPath, []byte(rulesContent), 0644); err != nil {
		return fmt.Errorf("failed to write local rules: %w", err)
	}

	err = gitIgnoreLocalRulesFile(workspacePath, rulesPath, logger)
	if err != nil {
		return err
	}

	logger.Debug().Msgf("Wrote local rules to %s", rulesPath)
	return nil
}

// removeLocalRules removes the local rules file from the workspace
func removeLocalRules(workspacePath, relativeRulesPath string, logger *zerolog.Logger) error {
	rulesPath := filepath.Join(workspacePath, relativeRulesPath)

	// Check if file exists
	if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
		logger.Debug().Msgf("Local rules file does not exist at %s, nothing to remove", rulesPath)
		return nil
	}

	if err := os.Remove(rulesPath); err != nil {
		return fmt.Errorf("failed to remove local rules: %w", err)
	}

	logger.Debug().Msgf("Removed local rules from %s", rulesPath)
	return nil
}

// writeGlobalRules writes rules to a global location with delimited markers
func writeGlobalRules(targetFile, rulesContent string, logger *zerolog.Logger) error {
	if err := os.MkdirAll(filepath.Dir(targetFile), 0755); err != nil {
		return fmt.Errorf("failed to create rules directory: %w", err)
	}

	block := fmt.Sprintf("%s\n%s\n%s\n", RuleStart, strings.TrimSpace(rulesContent), RuleEnd)

	var current string
	data, err := os.ReadFile(targetFile)
	if err == nil {
		current = string(data)
	}

	updated := upsertDelimitedBlock(current, RuleStart, RuleEnd, block)
	if updated == current {
		logger.Debug().Msgf("Delimited global rules already up to date at %s", targetFile)
		return nil
	}

	if err := os.WriteFile(targetFile, []byte(updated), 0644); err != nil {
		return fmt.Errorf("failed to write global rules: %w", err)
	}

	logger.Debug().Msgf("Upserted delimited global rules into %s", targetFile)
	return nil
}

// removeGlobalRules removes the Snyk rules block from the global rules file
func removeGlobalRules(targetFile string, logger *zerolog.Logger) error {
	// Check if file exists
	if _, err := os.Stat(targetFile); os.IsNotExist(err) {
		logger.Debug().Msgf("Global rules file does not exist at %s, nothing to remove", targetFile)
		return nil
	}

	data, err := os.ReadFile(targetFile)
	if err != nil {
		return fmt.Errorf("failed to read global rules file: %w", err)
	}

	current := string(data)
	updated := removeDelimitedBlock(current, RuleStart, RuleEnd)

	if updated == current {
		logger.Debug().Msgf("No Snyk rules block found in %s, nothing to remove", targetFile)
		return nil
	}

	if writeErr := os.WriteFile(targetFile, []byte(updated), 0644); writeErr != nil {
		return fmt.Errorf("failed to write updated global rules: %w", writeErr)
	}

	logger.Debug().Msgf("Removed Snyk rules block from %s", targetFile)
	return nil
}

// removeDelimitedBlock removes a delimited block from the content
func removeDelimitedBlock(source, start, end string) string {
	// Normalize newlines to \n
	src := strings.ReplaceAll(source, "\r\n", "\n")

	startIdx := strings.Index(src, start)
	endIdx := strings.Index(src, end)

	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		// No block found
		return source
	}

	// Remove from start marker to end marker (inclusive of the end marker)
	before := src[:startIdx]
	after := src[endIdx+len(end):]

	// Clean up extra newlines
	result := trimTrailingNewlines(before) + trimLeadingNewlines(after)

	// Ensure single trailing newline if there's content
	if len(strings.TrimSpace(result)) > 0 {
		result = strings.TrimRight(result, "\n\r ") + "\n"
	}

	return result
}

// upsertDelimitedBlock replaces or appends a delimited block inside a file content
func upsertDelimitedBlock(source, start, end, fullBlockToInsert string) string {
	// Normalize newlines to \n
	src := strings.ReplaceAll(source, "\r\n", "\n")

	startIdx := strings.Index(src, start)
	endIdx := strings.Index(src, end)

	if startIdx != -1 && endIdx != -1 && endIdx > startIdx {
		// Replace from start marker to end marker (inclusive)
		before := src[:startIdx]
		after := src[endIdx+len(end):]
		return trimTrailingNewlines(before) + "\n" + strings.TrimSpace(fullBlockToInsert) + "\n" + trimLeadingNewlines(after)
	}

	// No existing block: append
	prefix := ""
	if len(src) > 0 {
		prefix = trimTrailingNewlines(src) + "\n\n"
	}
	return prefix + strings.TrimSpace(fullBlockToInsert) + "\n"
}

func gitIgnoreLocalRulesFile(workspacePath string, relativeRulesPath string, logger *zerolog.Logger) error {
	repo, _, err := git.RepoFromDir(workspacePath)
	if err != nil {
		logger.Err(err).Msgf("Unable to open git repo at %s: Skipping creating .gitignore entry.", workspacePath)
		return nil
	}

	tree, err := repo.Worktree()
	if err != nil {
		logger.Err(err).Msgf("Unable to open git repo at %s: Skipping creating .gitignore entry.", workspacePath)
		return err
	}

	status, err := tree.Status()
	if err != nil {
		logger.Err(err).Msgf("Unable to inspect git repo at %s: Skipping creating .gitignore entry.", workspacePath)
		return err
	}

	_, isGitVisible := status[relativeRulesPath]

	if isGitVisible {
		gitIgnorePath := path.Join(workspacePath, ".gitignore")
		file, err := os.OpenFile(gitIgnorePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logger.Err(err).Msgf("Unable to open .gitignore at %s: Skipping creating .gitignore entry.", workspacePath)
			return err
		}
		defer func() {
			err = file.Close()
			logger.Err(err).Msgf("Unable to close .gitignore at %s", workspacePath)
		}()

		_, err = fmt.Fprintf(file, "\n\n%s\n", relativeRulesPath)
		if err != nil {
			logger.Err(err).Msgf("Unable to write .gitignore at %s: Skipping creating .gitignore entry.", workspacePath)
			return err
		}
	}

	return nil
}

func trimTrailingNewlines(s string) string {
	return strings.TrimRight(s, "\n\r ")
}

func trimLeadingNewlines(s string) string {
	return strings.TrimLeft(s, "\n\r")
}
