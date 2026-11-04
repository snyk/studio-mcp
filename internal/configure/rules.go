package configure

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

const (
	RuleStart = "<!--# BEGIN SNYK GLOBAL RULE -->"
	RuleEnd   = "<!--# END SNYK GLOBAL RULE -->"
)

// removeFileIfExists removes a file Snyk owns outright, such as a skill or a local rules file
func removeFileIfExists(path string, logger *zerolog.Logger) error {
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		logger.Debug().Msgf("%s does not exist, nothing to remove", path)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to remove %s: %w", path, err)
	}

	logger.Debug().Msgf("Removed %s", path)
	return nil
}

// removeGlobalRules removes the Snyk rules block from the global rules file
func removeGlobalRules(targetFile string, logger *zerolog.Logger) error {
	data, err := os.ReadFile(targetFile)
	if errors.Is(err, fs.ErrNotExist) {
		logger.Debug().Msgf("Global rules file does not exist at %s, nothing to remove", targetFile)
		return nil
	}
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
	before := strings.TrimRight(src[:startIdx], "\n\r ")
	after := strings.TrimLeft(src[endIdx+len(end):], "\n\r")

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
