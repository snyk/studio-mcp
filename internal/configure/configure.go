package configure

import (
	_ "embed"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/studio-mcp/shared"
)

//go:embed rules/sast/always_apply.md
var snykRulesAlwaysApply string

//go:embed rules/sast/smart_apply.md
var snykRulesSmartApply string

// Configure sets up MCP server and rules for the specified IDE host.
func Configure(logger *zerolog.Logger, config configuration.Configuration, userInterface ui.UserInterface, cliPath string) error {
	hostName := config.GetString(shared.ToolNameParam)
	removeMode := config.GetBool(shared.RemoveParam)

	// Get IDE configuration
	ideConf, err := getHostConfig(hostName)
	if err != nil {
		return err
	}

	// Handle remove mode
	if removeMode {
		return removeConfiguration(logger, config, userInterface, ideConf)
	}

	// Handle add/update mode
	return addConfiguration(logger, config, userInterface, cliPath, ideConf)
}

// removeConfiguration removes the Snyk MCP server and rules from the specified tool
func removeConfiguration(logger *zerolog.Logger, config configuration.Configuration, userInterface ui.UserInterface, ideConf *hostConfig) error {
	rulesScope := config.GetString(shared.RulesScopeParam)
	workspacePath := config.GetString(shared.WorkspacePathParam)
	configureMcp := config.GetBool(shared.ConfigureMcpParam)
	configureRules := config.GetBool(shared.ConfigureRulesParam)

	// Remove MCP server from config (only if configureMcp is true)
	if configureMcp {
		if ideConf.mcpGlobalConfigPath != "" {
			_ = userInterface.Output(fmt.Sprintf("📝 Removing MCP server from: %s", ideConf.mcpGlobalConfigPath))

			err := removeMcpServerFromJson(ideConf.mcpGlobalConfigPath, shared.ServerNameKey, logger)
			if err != nil {
				return fmt.Errorf("failed to remove MCP server for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully removed MCP server for %s", ideConf.name))
			logger.Info().Msgf("Successfully removed MCP server for %s from %s", ideConf.name, ideConf.mcpGlobalConfigPath)
		}
	}

	// Remove global rules (only if configureRules is true)
	if configureRules {
		if rulesScope == shared.RulesGlobalScope && ideConf.globalRulesPath != "" {
			_ = userInterface.Output(fmt.Sprintf("📋 Removing global rules from: %s", ideConf.globalRulesPath))

			err := removeGlobalRules(ideConf.globalRulesPath, logger)
			if err != nil {
				return fmt.Errorf("failed to remove global rules for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully removed global rules for %s", ideConf.name))
			logger.Info().Msgf("Successfully removed global rules for %s from %s", ideConf.name, ideConf.globalRulesPath)
		}

		// Remove local rules (only if configureRules is true)
		if rulesScope == shared.RulesWorkspaceScope && ideConf.localRulesPath != "" && workspacePath != "" {
			_ = userInterface.Output(fmt.Sprintf("📋 Removing local rules from workspace: %s", workspacePath))

			err := removeLocalRules(workspacePath, ideConf.localRulesPath, logger)
			if err != nil {
				return fmt.Errorf("failed to remove local rules for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully removed local rules for %s", ideConf.name))
			logger.Info().Msgf("Successfully removed local rules for %s", ideConf.name)
		}
	}

	_ = userInterface.Output("\n🎉 Removal complete!")
	_ = userInterface.Output("\nNext steps:")
	_ = userInterface.Output(fmt.Sprintf("  1. Restart %s to apply the changes", ideConf.name))

	return nil
}

// addConfiguration adds or updates the Snyk MCP server and rules for the specified tool
func addConfiguration(logger *zerolog.Logger, config configuration.Configuration, userInterface ui.UserInterface, cliPath string, ideConf *hostConfig) error {
	ruleType := config.GetString(shared.RuleTypeParam)
	rulesScope := config.GetString(shared.RulesScopeParam)
	workspacePath := config.GetString(shared.WorkspacePathParam)
	configCallback := config.Get(shared.McpRegisterCallbackParam)
	configureMcp := config.GetBool(shared.ConfigureMcpParam)
	configureRules := config.GetBool(shared.ConfigureRulesParam)

	if workspacePath != "" {
		isWorkspacePathSymlink, err := isSymlink(workspacePath)
		if err == nil && isWorkspacePathSymlink {
			return fmt.Errorf("using symlinks for workspace path is not supported: %s", workspacePath)
		}
	}

	var configureMcpCallbackFunc shared.McpRegisterCallback
	if configCallback != nil {
		callbackFunc, ok := configCallback.(shared.McpRegisterCallback)
		if !ok {
			return fmt.Errorf("invalid config callback type: %T", configCallback)
		}
		configureMcpCallbackFunc = callbackFunc
	}

	// Configure MCP server (only if configureMcp is true)
	if configureMcp {
		_ = userInterface.Output(fmt.Sprintf("\n🔧 Configuring Snyk MCP for %s...\n", ideConf.name))

		cmd, args := determineCommand(cliPath, config.GetString(configuration.INTEGRATION_NAME))
		env := getSnykMcpEnv(config)

		if ideConf.mcpGlobalConfigPath != "" {
			_ = userInterface.Output(fmt.Sprintf("📝 Configuring MCP server at: %s", ideConf.mcpGlobalConfigPath))

			err := ensureMcpServerInJson(ideConf.mcpGlobalConfigPath, shared.ServerNameKey, cmd, args, env, logger)
			if err != nil {
				return fmt.Errorf("failed to configure MCP server for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully configured MCP server for %s", ideConf.name))
			logger.Info().Msgf("Successfully configured MCP server for %s at %s", ideConf.name, ideConf.mcpGlobalConfigPath)
		}

		if configureMcpCallbackFunc != nil {
			err := configureMcpCallbackFunc(cmd, args, env)
			if err != nil {
				logger.Error().Err(err).Msgf("failed to trigger MCP configure callback for %s", ideConf.name)
			}
		}
	}

	// Configure rules (only if configureRules is true)
	if configureRules {
		var rulesContent string
		switch ruleType {
		case shared.RuleTypeAlwaysApply:
			rulesContent = snykRulesAlwaysApply
		case shared.RuleTypeSmart:
			rulesContent = snykRulesSmartApply
		default:
			return fmt.Errorf("invalid rule type: %s. supported values are %s, %s", ruleType, shared.RuleTypeAlwaysApply, shared.RuleTypeSmart)
		}

		if rulesScope == shared.RulesGlobalScope && ideConf.globalRulesPath != "" {
			_ = userInterface.Output(fmt.Sprintf("📋 Writing global rules (%s) to: %s", ruleType, ideConf.globalRulesPath))

			err := writeGlobalRules(ideConf.globalRulesPath, rulesContent, logger)
			if err != nil {
				return fmt.Errorf("failed to write global rules for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully wrote global rules for %s", ideConf.name))
			logger.Info().Msgf("Successfully wrote global rules for %s at %s", ideConf.name, ideConf.globalRulesPath)
		}

		if rulesScope == shared.RulesWorkspaceScope && ideConf.localRulesPath != "" && workspacePath != "" {
			_ = userInterface.Output(fmt.Sprintf("📋 Writing local rules (%s) to workspace: %s", ruleType, workspacePath))

			err := writeLocalRules(workspacePath, ideConf.localRulesPath, rulesContent, logger)
			if err != nil {
				return fmt.Errorf("failed to write local rules for %s: %w", ideConf.name, err)
			}

			err = gitIgnoreLocalRulesFile(workspacePath, ideConf.localRulesPath, logger)
			if err != nil {
				logger.Err(err).Msgf("Unable to add git ignore for local rules at %s", workspacePath)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully wrote local rules for %s", ideConf.name))
			logger.Info().Msgf("Successfully wrote local rules for %s", ideConf.name)
		}
	}

	_ = userInterface.Output("\n🎉 Configuration complete!")
	_ = userInterface.Output("\nNext steps:")
	_ = userInterface.Output(fmt.Sprintf("  1. Restart %s to apply the changes", ideConf.name))
	_ = userInterface.Output("  2. The Snyk MCP server will be available for AI-powered security scanning")

	return nil
}

// determineCommand returns the command and args based on execution context
func determineCommand(cliPath, integrationName string) (string, []string) {
	if utils.IsRunningFromNpm(integrationName) {
		return "npx", []string{"-y", "snyk@latest", "mcp", "-t", "stdio"}
	}
	return cliPath, []string{"mcp", "-t", "stdio"}
}
