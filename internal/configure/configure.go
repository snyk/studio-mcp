package configure

import (
	_ "embed"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
)

const (
	ConfigureParam      = "configure"
	RuleTypeParam       = "rule-type"
	RuleTypeSmart       = "smart-apply"
	RuleTypeAlwaysApply = "always-apply"
	TrustedFoldersParam = "trusted-folders"
	IdeConfigPathParam  = "ide-config-path"
	GlobalRuleParam     = "global-rule"
	WorkspacePath       = "workspace"
	serverNameKey       = "Snyk"
)

//go:embed rules/always_apply.md
var snykRulesAlwaysApply string

//go:embed rules/smart_apply.md
var snykRulesSmartApply string

// Configure sets up MCP server and rules for the specified IDE host.
// Parameters:
//   - invocatioanCtx: workflow invocation context
//   - cliPath: path to the Snyk CLI executable
//   - setGlobalRules: if true, writes rules globally; if false, writes to workspacePath
//   - workspacePath: path to workspace for local rules (ignored if setGlobalRules is true)
func Configure(logger *zerolog.Logger, config configuration.Configuration, userInterface ui.UserInterface, cliPath string) error {
	hostName := config.GetString(ConfigureParam)
	ruleType := config.GetString(RuleTypeParam)
	setGlobalRules := config.GetBool(GlobalRuleParam)
	workspacePath := config.GetString(WorkspacePath)

	if userInterface != nil {
		_ = userInterface.Output(fmt.Sprintf("\n🔧 Configuring Snyk MCP for %s...\n", hostName))
	}

	cmd, args := determineCommand(cliPath)

	// Get IDE configuration
	ideConf, err := getHostConfig(hostName)
	if err != nil {
		return err
	}

	// Configure MCP server in JSON
	if ideConf.mcpConfigPath != "" {
		if userInterface != nil {
			_ = userInterface.Output(fmt.Sprintf("📝 Configuring MCP server at: %s", ideConf.mcpConfigPath))
		}

		env := getSnykMcpEnv(config)
		err = ensureMcpServerInJson(ideConf.mcpConfigPath, serverNameKey, cmd, args, env, logger)
		if err != nil {
			return fmt.Errorf("failed to configure MCP server for %s: %w", ideConf.name, err)
		}

		if userInterface != nil {
			_ = userInterface.Output(fmt.Sprintf("✅ Successfully configured MCP server for %s", ideConf.name))
		}
		logger.Info().Msgf("Successfully configured MCP server for %s at %s", ideConf.name, ideConf.mcpConfigPath)
	}

	// Configure rules
	var rulesContent string
	if ruleType == RuleTypeAlwaysApply {
		rulesContent = snykRulesAlwaysApply
	} else if ruleType == RuleTypeSmart {
		rulesContent = snykRulesSmartApply
	} else {
		return fmt.Errorf("invalid rule type: %s. supported values are %s, %s", ruleType, RuleTypeAlwaysApply, RuleTypeSmart)
	}

	if setGlobalRules && ideConf.globalRulesPath != "" {
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

	if !setGlobalRules && ideConf.localRulesPath != "" && workspacePath != "" {
		if userInterface != nil {
			_ = userInterface.Output(fmt.Sprintf("📋 Writing local rules (%s) to workspace: %s", ruleType, workspacePath))
		}

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
		_ = userInterface.Output(fmt.Sprintf("\nNext steps:"))
		_ = userInterface.Output(fmt.Sprintf("  1. Restart %s to apply the changes", ideConf.name))
		_ = userInterface.Output(fmt.Sprintf("  2. The Snyk MCP server will be available for AI-powered security scanning"))
	}

	return nil
}

// determineCommand returns the command and args based on execution context
func determineCommand(cliPath string) (string, []string) {
	if isExecutedViaNPMContext() {
		// For npm context: npx -y snyk@latest mcp -t stdio
		return "npx", []string{"-y", "snyk@latest", "mcp", "-t", "stdio"}
	}
	// For regular execution: <cliPath> mcp -t stdio
	return cliPath, []string{"mcp", "-t", "stdio"}
}
