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

type McpServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

// McpConfig represents the MCP configuration structure for testing and validation
type McpConfig struct {
	McpServers map[string]McpServer `json:"mcpServers"`
}

// ensureMcpServerInJson creates or updates MCP server configuration in a JSON file
// This function preserves all other fields in the JSON file
// It identifies the SAI MCP server by its command and args rather than by name,
// allowing it to coexist with other MCP servers like SnykAlphaPatch
func ensureMcpServerInJson(filePath, serverKey, command string, args []string, env shared.McpEnvMap, logger *zerolog.Logger) error {
	// Use a generic map to preserve all existing fields
	var config map[string]interface{}

	// Read existing config if it exists
	if _, err := os.Stat(filePath); err == nil {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}
		// empty string is invalid json, fall back to empty json
		if len(data) == 0 || strings.TrimSpace(string(data)) == "" {
			data = []byte("{}")
		}
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to unmarshal config file: %w", err)
		}
	} else {
		config = make(map[string]interface{})
	}

	// Get or create mcpServers section
	var mcpServers map[string]interface{}
	if serversRaw, ok := config["mcpServers"]; ok {
		if servers, ok := serversRaw.(map[string]interface{}); ok {
			mcpServers = servers
		} else {
			mcpServers = make(map[string]interface{})
		}
	} else {
		mcpServers = make(map[string]interface{})
	}

	// Find existing SAI MCP server by command and args
	keyToUse := findServerByCommandAndArgs(mcpServers, command, args)

	// If not found by command/args, use the server key name (creates new entry)
	if keyToUse == "" {
		keyToUse = serverKey
	}

	// Get existing server as a generic map to preserve all properties
	var existingServerMap map[string]interface{}
	var existingServer McpServer

	if existingRaw, ok := mcpServers[keyToUse]; ok {
		// Try to convert to map to preserve all properties
		if serverMap, ok := existingRaw.(map[string]interface{}); ok {
			existingServerMap = serverMap
		} else {
			existingServerMap = make(map[string]interface{})
		}

		// Also convert to struct for comparison
		if existingBytes, err := json.Marshal(existingRaw); err == nil {
			_ = json.Unmarshal(existingBytes, &existingServer)
		}
	} else {
		existingServerMap = make(map[string]interface{})
	}

	// Merge environment variables from existing env
	var existingEnvMap shared.McpEnvMap
	if envRaw, ok := existingServerMap["env"]; ok {
		if envBytes, err := json.Marshal(envRaw); err == nil {
			_ = json.Unmarshal(envBytes, &existingEnvMap)
		}
	} else {
		existingEnvMap = make(map[string]string)
	}
	resultingEnv := mergeEnv(existingEnvMap, env)

	// Check if update is needed
	needsWrite := existingServer.Command != command ||
		!stringSlicesEqual(existingServer.Args, args) ||
		!envMapsEqual(existingEnvMap, resultingEnv)

	if !needsWrite {
		logger.Debug().Msg("MCP config already up to date")
		return nil
	}

	// Update only the specific fields, preserving all other properties
	existingServerMap["command"] = command
	existingServerMap["args"] = args
	existingServerMap["env"] = resultingEnv

	mcpServers[keyToUse] = existingServerMap
	config["mcpServers"] = mcpServers

	// Write updated config
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

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

	// Look for any server where command contains 'snyk' and args are ["mcp", "-t", "stdio"]
	expectedArgs := []string{shared.McpServerStdioArg1, shared.McpServerStdioArg2, shared.McpServerStdioArg3}
	var matchingKeys []string

	for key, serverRaw := range mcpServers {
		if serverMap, ok := serverRaw.(map[string]interface{}); ok {
			if argsVal, ok := serverMap["args"].([]interface{}); ok {
				if argsMatch(argsVal, expectedArgs) {
					if cmdVal, ok := serverMap["command"].(string); ok {
						// Check if command path includes 'snyk'
						if strings.Contains(strings.ToLower(cmdVal), strings.ToLower(shared.McpServerCommand)) {
							matchingKeys = append(matchingKeys, key)
						}
					}
				}
			}
		}
	}

	// Only remove if exactly one matching server is found
	if len(matchingKeys) != 1 {
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

// findServerByCommandAndArgs finds the first server key that matches the given command and args.
// Returns empty string if no match is found.
// This is used to identify an existing SAI MCP server configuration.
func findServerByCommandAndArgs(servers map[string]interface{}, command string, args []string) string {
	for key, serverRaw := range servers {
		if serverMap, ok := serverRaw.(map[string]interface{}); ok {
			if argsVal, ok := serverMap["args"].([]interface{}); ok {
				if argsMatch(argsVal, args) {
					if cmdVal, ok := serverMap["command"].(string); ok {
						// For update operations, check if command contains the MCP server command identifier
						if strings.Contains(strings.ToLower(cmdVal), strings.ToLower(shared.McpServerCommand)) {
							return key
						}
					}
				}
			}
		}
	}
	return ""
}

// argsMatch checks if two argument lists are equal
func argsMatch(ifaceArgs []interface{}, stringArgs []string) bool {
	if len(ifaceArgs) != len(stringArgs) {
		return false
	}
	for i, arg := range ifaceArgs {
		if str, ok := arg.(string); !ok || str != stringArgs[i] {
			return false
		}
	}
	return true
}

// mergeEnv merges environment variables, overriding Snyk-specific keys
func mergeEnv(existing, new shared.McpEnvMap) shared.McpEnvMap {
	resultingEnv := existing

	// Override Snyk-specific keys
	overrideKeys := []string{"SNYK_CFG_ORG", "SNYK_API", "IDE_CONFIG_PATH", "TRUSTED_FOLDERS"}
	for _, k := range overrideKeys {
		if v, ok := new[k]; ok {
			resultingEnv[k] = v
		}
	}

	return resultingEnv
}
