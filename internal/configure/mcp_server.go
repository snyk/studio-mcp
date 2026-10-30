package configure

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/studio-mcp/shared"
)

// removeMcpServerFromJson removes an MCP server from the configuration JSON file
// This function identifies the SAI MCP server by its command and args.
// It only removes if exactly one server with the matching command and args is found.
// If multiple servers match or none match, nothing is removed.
// This function preserves all other fields in the JSON file
func removeMcpServerFromJson(filePath, serverKey string, logger *zerolog.Logger) error {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		logger.Debug().Msgf("Config file does not exist: %s, nothing to remove", filePath)
		return nil
	}

	// Read existing config
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Get mcpServers section
	serversRaw, ok := config["mcpServers"]
	if !ok {
		logger.Debug().Msg("No mcpServers section found, nothing to remove")
		return nil
	}

	mcpServers, ok := serversRaw.(map[string]interface{})
	if !ok {
		logger.Debug().Msg("mcpServers is not a valid object, nothing to remove")
		return nil
	}

	// Look for any server where command contains McpServerCommand and args are ["mcp", "-t", "stdio"]
	expectedArgs := []string{shared.McpServerStdioArg1, shared.McpServerStdioArg2, shared.McpServerStdioArg3}
	matchingKeys := findMatchingServerKeys(mcpServers, expectedArgs, 2)

	// Only remove if exactly one matching server is found
	if len(matchingKeys) == 0 {
		return nil
	}

	if len(matchingKeys) > 1 {
		logger.Debug().Msgf("Found %d servers with command containing 'snyk' and args matching SAI MCP, not removing (expected exactly 1)", len(matchingKeys))
		return nil
	}

	keyToRemove := matchingKeys[0]

	// Remove the server
	delete(mcpServers, keyToRemove)
	config["mcpServers"] = mcpServers

	// Write updated config
	data, err = json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// findMatchingServerKeys finds all server keys that match the SAI MCP server's args and command, returning up to maxResultCount results.
func findMatchingServerKeys(servers map[string]interface{}, expectedArgs []string, maxResultCount int) []string {
	var matchingKeys []string

	for key, serverConfig := range servers {
		if len(matchingKeys) >= maxResultCount {
			break
		}

		serverConfigFields, ok := serverConfig.(map[string]interface{})
		if !ok {
			continue
		}

		// check if args key exists, and has the same args as SAI MCP server's args
		argsVal, argsExists := serverConfigFields["args"].([]interface{})
		if !argsExists {
			continue
		}

		if !argsMatch(argsVal, expectedArgs) {
			continue
		}

		// check if command key exists, and is the same command as SAI MCP server's command
		cmdVal, cmdExists := serverConfigFields["command"].(string)
		if !cmdExists || cmdVal == "" {
			continue
		}

		if !matchesSnykCommand(cmdVal) {
			continue
		}

		matchingKeys = append(matchingKeys, key)
	}

	return matchingKeys
}

// argsMatch checks if two argument lists are equal
func argsMatch(ifaceArgs []interface{}, stringArgs []string) bool {
	if ifaceArgs == nil || stringArgs == nil {
		return (ifaceArgs == nil) && (stringArgs == nil)
	}

	if len(ifaceArgs) != len(stringArgs) {
		return false
	}

	for i, arg := range ifaceArgs {
		str, ok := arg.(string)
		if !ok || str != stringArgs[i] {
			return false
		}
	}
	return true
}

// matchesSnykCommand checks if the given command path matches the expected SAI MCP server's command pattern
// normalizes path separators and performs case-insensitive comparison
func matchesSnykCommand(command string) bool {
	normalizedCommand := strings.ToLower(filepath.ToSlash(command))
	normalizedCommandPattern := strings.ToLower(shared.McpServerCommandPattern)
	return strings.Contains(normalizedCommand, normalizedCommandPattern)
}
