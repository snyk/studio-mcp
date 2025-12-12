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

	// Find matching server key (case-insensitive)
	keyToUse := findServerKeyInGenericMap(mcpServers, serverKey)

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

	// Find matching server key (case-insensitive)
	keyToRemove := findServerKeyInGenericMap(mcpServers, serverKey)

	// Check if server exists
	if _, exists := mcpServers[keyToRemove]; !exists {
		logger.Debug().Msgf("Server '%s' not found in config, nothing to remove", serverKey)
		return nil
	}

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

// findServerKeyInGenericMap finds the matching server key in a generic map (case-insensitive)
func findServerKeyInGenericMap(servers map[string]interface{}, serverKey string) string {
	serverKeyLower := strings.ToLower(serverKey)
	for key := range servers {
		keyLower := strings.ToLower(key)
		if keyLower == serverKeyLower || strings.Contains(keyLower, serverKeyLower) {
			return key
		}
	}
	return serverKey
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
