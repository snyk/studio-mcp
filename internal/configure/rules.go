package configure

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
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

	logger.Debug().Msgf("Wrote local rules to %s", rulesPath)
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

func trimTrailingNewlines(s string) string {
	return strings.TrimRight(s, "\n\r ")
}

func trimLeadingNewlines(s string) string {
	return strings.TrimLeft(s, "\n\r")
}
