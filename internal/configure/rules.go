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

// removeGlobalSkills removes the global skills file
func removeGlobalSkills(targetFile string, logger *zerolog.Logger) error {
	if _, err := os.Stat(targetFile); os.IsNotExist(err) {
		logger.Debug().Msgf("Global skills file does not exist at %s, nothing to remove", targetFile)
		return nil
	}

	if err := os.Remove(targetFile); err != nil {
		return fmt.Errorf("failed to remove global skills: %w", err)
	}

	logger.Debug().Msgf("Removed global skills from %s", targetFile)
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
	before := trimTrailingNewlines(src[:startIdx])
	after := trimLeadingNewlines(src[endIdx+len(end):])

	separator := ""
	if before != "" && after != "" {
		separator = "\n"
	}
	result := before + separator + after

	// Ensure single trailing newline if there's content
	if len(strings.TrimSpace(result)) > 0 {
		result = strings.TrimRight(result, "\n\r ") + "\n"
	}

	return result
}

func trimTrailingNewlines(s string) string {
	return strings.TrimRight(s, "\n\r ")
}

func trimLeadingNewlines(s string) string {
	return strings.TrimLeft(s, "\n\r")
}
