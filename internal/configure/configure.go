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
// Parameters:
//   - invocatioanCtx: workflow invocation context
//   - cliPath: path to the Snyk CLI executable
//   - setGlobalRules: if true, writes rules globally; if false, writes to workspacePath
//   - workspacePath: path to workspace for local rules (ignored if setGlobalRules is true)
func Configure(logger *zerolog.Logger, config configuration.Configuration, userInterface ui.UserInterface, cliPath string) error {
	hostName := config.GetString(shared.ToolNameParam)
	ruleType := config.GetString(shared.RuleTypeParam)
	rulesScope := config.GetString(shared.RulesScopeParam)
	workspacePath := config.GetString(shared.WorkspacePath)
	configCallback := config.Get(shared.McpConfigureCallback)

	var configureMcpCallbackFunc shared.ConfigCallBack
	if configCallback != nil {
		callbackFunc, ok := configCallback.(shared.ConfigCallBack)
		if !ok {
			return fmt.Errorf("invalid config callback type: %T", configCallback)
		}
		configureMcpCallbackFunc = callbackFunc
	}

	if userInterface != nil {
		_ = userInterface.Output(fmt.Sprintf("\n🔧 Configuring Snyk MCP for %s...\n", hostName))
	}

	cmd, args := determineCommand(cliPath, config.GetString(configuration.INTEGRATION_NAME))

	// Get IDE configuration
	ideConf, err := getHostConfig(hostName)
	if err != nil {
		return err
	}

	env := getSnykMcpEnv(config)

	if ideConf.mcpGlobalConfigPath != "" {
		if userInterface != nil {
			_ = userInterface.Output(fmt.Sprintf("📝 Configuring MCP server at: %s", ideConf.mcpGlobalConfigPath))
		}

		err = ensureMcpServerInJson(ideConf.mcpGlobalConfigPath, shared.ServerNameKey, cmd, args, env, logger)
		if err != nil {
			return fmt.Errorf("failed to configure MCP server for %s: %w", ideConf.name, err)
		}

		if userInterface != nil {
			_ = userInterface.Output(fmt.Sprintf("✅ Successfully configured MCP server for %s", ideConf.name))
		}
		logger.Info().Msgf("Successfully configured MCP server for %s at %s", ideConf.name, ideConf.mcpGlobalConfigPath)
	}

	if configureMcpCallbackFunc != nil {
		err = configureMcpCallbackFunc(cmd, args, env)
		if err != nil {
			logger.Error().Err(err).Msgf("failed to trigger MCP configure callback for %s", ideConf.name)
		}
	}

	// Configure rules
	var rulesContent string
	if ruleType == shared.RuleTypeAlwaysApply {
		rulesContent = snykRulesAlwaysApply
	} else if ruleType == shared.RuleTypeSmart {
		rulesContent = snykRulesSmartApply
	} else {
		return fmt.Errorf("invalid rule type: %s. supported values are %s, %s", ruleType, shared.RuleTypeAlwaysApply, shared.RuleTypeSmart)
	}

	if rulesScope == shared.RulesGlobalScope && ideConf.globalRulesPath != "" {
		if userInterface != nil {
			_ = userInterface.Output(fmt.Sprintf("📋 Writing global rules (%s) to: %s", ruleType, ideConf.globalRulesPath))
		}

		err = writeGlobalRules(ideConf.globalRulesPath, rulesContent, logger)
		if err != nil {
			return fmt.Errorf("failed to write global rules for %s: %w", ideConf.name, err)
		}

		if userInterface != nil {
			_ = userInterface.Output(fmt.Sprintf("✅ Successfully wrote global rules for %s", ideConf.name))
		}
		logger.Info().Msgf("Successfully wrote global rules for %s at %s", ideConf.name, ideConf.globalRulesPath)
	}

	if rulesScope == shared.RulesWorkspaceScope && ideConf.localRulesPath != "" && workspacePath != "" {
		if userInterface != nil {
			_ = userInterface.Output(fmt.Sprintf("📋 Writing local rules (%s) to workspace: %s", ruleType, workspacePath))
		}

		// TODO: implement .gitignore here
		err = writeLocalRules(workspacePath, ideConf.localRulesPath, rulesContent, logger)
		if err != nil {
			return fmt.Errorf("failed to write local rules for %s: %w", ideConf.name, err)
		}

		if userInterface != nil {
			_ = userInterface.Output(fmt.Sprintf("✅ Successfully wrote local rules for %s", ideConf.name))
		}
		logger.Info().Msgf("Successfully wrote local rules for %s", ideConf.name)
	}

	if userInterface != nil {
		_ = userInterface.Output("\n🎉 Configuration complete!")
		_ = userInterface.Output("\nNext steps:")
		_ = userInterface.Output(fmt.Sprintf("  1. Restart %s to apply the changes", ideConf.name))
		_ = userInterface.Output("  2. The Snyk MCP server will be available for AI-powered security scanning")
	}

	return nil
}

// determineCommand returns the command and args based on execution context
func determineCommand(cliPath, integrationName string) (string, []string) {
	if utils.IsRunningFromNpm(integrationName) {
		return "npx", []string{"-y", "snyk@latest", "mcp", "-t", "stdio"}
	}
	return cliPath, []string{"mcp", "-t", "stdio"}
}
