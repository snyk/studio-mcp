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

//go:embed skills/sast/always_apply.md
var snykSkillsAlwaysApply string

//go:embed skills/sast/smart_apply.md
var snykSkillsSmartApply string

// Claude Code's user-level rules loader (~/.claude/rules/*.md) does not use
// the Cursor SKILL.md frontmatter (name/description); these are clean
// markdown bodies tailored for that loader.
//
//go:embed rules/claude/always_apply.md
var snykClaudeRulesAlwaysApply string

//go:embed rules/claude/smart_apply.md
var snykClaudeRulesSmartApply string

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

	// Remove rules/skills (only if configureRules is true)
	if configureRules {
		// Remove global skills (e.g. Cursor)
		if ideConf.globalSkillsPath != "" {
			_ = userInterface.Output(fmt.Sprintf("📋 Removing global skills from: %s", ideConf.globalSkillsPath))

			err := removeGlobalSkills(ideConf.globalSkillsPath, logger)
			if err != nil {
				return fmt.Errorf("failed to remove global skills for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully removed global skills for %s", ideConf.name))
			logger.Info().Msgf("Successfully removed global skills for %s from %s", ideConf.name, ideConf.globalSkillsPath)
		}

		// Remove dedicated rules file (e.g. claude-cli)
		if ideConf.globalDedicatedRulesPath != "" {
			_ = userInterface.Output(fmt.Sprintf("📋 Removing dedicated rules file from: %s", ideConf.globalDedicatedRulesPath))

			err := removeGlobalSkills(ideConf.globalDedicatedRulesPath, logger)
			if err != nil {
				return fmt.Errorf("failed to remove dedicated rules file for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully removed dedicated rules file for %s", ideConf.name))
			logger.Info().Msgf("Successfully removed dedicated rules file for %s from %s", ideConf.name, ideConf.globalDedicatedRulesPath)
		}

		// Remove global rules (e.g. Windsurf, Antigravity, gemini-cli, claude-cli)
		if rulesScope == shared.RulesGlobalScope && ideConf.globalRulesPath != "" {
			_ = userInterface.Output(fmt.Sprintf("📋 Removing global rules from: %s", ideConf.globalRulesPath))

			err := removeGlobalRules(ideConf.globalRulesPath, logger)
			if err != nil {
				return fmt.Errorf("failed to remove global rules for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully removed global rules for %s", ideConf.name))
			logger.Info().Msgf("Successfully removed global rules for %s from %s", ideConf.name, ideConf.globalRulesPath)
		}

		// Remove local rules (e.g. VS Code)
		if rulesScope == shared.RulesWorkspaceScope && ideConf.localRulesPath != "" && workspacePath != "" {
			_ = userInterface.Output(fmt.Sprintf("📋 Removing local rules from workspace: %s", workspacePath))

			err := removeLocalRules(workspacePath, ideConf.localRulesPath, logger)
			if err != nil {
				return fmt.Errorf("failed to remove local rules for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully removed local rules for %s", ideConf.name))
			logger.Info().Msgf("Successfully removed local rules for %s", ideConf.name)
		}

		cleanupLegacyLocalRules(logger, workspacePath, ideConf)
	}

	// Migration housekeeping runs OUTSIDE the configureRules gate: a user
	// invoking remove with configureRules=false (e.g. wanting to remove only
	// the MCP entry) still expects stale Snyk content in their personal
	// CLAUDE.md to be cleaned up — migration is independent of whether rules
	// are configured this run.
	cleanupLegacyGlobalRules(logger, userInterface, ideConf)

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

		// Write global skills (e.g. Cursor)
		if ideConf.globalSkillsPath != "" {
			var skillsContent string
			switch ruleType {
			case shared.RuleTypeAlwaysApply:
				skillsContent = snykSkillsAlwaysApply
			case shared.RuleTypeSmart:
				skillsContent = snykSkillsSmartApply
			}

			_ = userInterface.Output(fmt.Sprintf("📋 Writing global skills (%s) to: %s", ruleType, ideConf.globalSkillsPath))

			err := writeGlobalSkills(ideConf.globalSkillsPath, skillsContent, logger)
			if err != nil {
				return fmt.Errorf("failed to write global skills for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully wrote global skills for %s", ideConf.name))
			logger.Info().Msgf("Successfully wrote global skills for %s at %s", ideConf.name, ideConf.globalSkillsPath)
		}

		// Write dedicated rules file (e.g. claude-cli ~/.claude/rules/snyk-security.md)
		if ideConf.globalDedicatedRulesPath != "" {
			var dedicatedRulesContent string
			switch ruleType {
			case shared.RuleTypeAlwaysApply:
				dedicatedRulesContent = snykClaudeRulesAlwaysApply
			case shared.RuleTypeSmart:
				dedicatedRulesContent = snykClaudeRulesSmartApply
			}

			_ = userInterface.Output(fmt.Sprintf("📋 Writing dedicated rules file (%s) to: %s", ruleType, ideConf.globalDedicatedRulesPath))

			err := writeGlobalSkills(ideConf.globalDedicatedRulesPath, dedicatedRulesContent, logger)
			if err != nil {
				return fmt.Errorf("failed to write dedicated rules file for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully wrote dedicated rules file for %s", ideConf.name))
			logger.Info().Msgf("Successfully wrote dedicated rules file for %s at %s", ideConf.name, ideConf.globalDedicatedRulesPath)
		}

		// Write global rules with delimiters (e.g. Windsurf, Antigravity, gemini-cli, claude-cli)
		if rulesScope == shared.RulesGlobalScope && ideConf.globalRulesPath != "" {
			_ = userInterface.Output(fmt.Sprintf("📋 Writing global rules (%s) to: %s", ruleType, ideConf.globalRulesPath))

			err := writeGlobalRules(ideConf.globalRulesPath, rulesContent, logger)
			if err != nil {
				return fmt.Errorf("failed to write global rules for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully wrote global rules for %s", ideConf.name))
			logger.Info().Msgf("Successfully wrote global rules for %s at %s", ideConf.name, ideConf.globalRulesPath)
		}

		// Write local rules (e.g. VS Code)
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

		cleanupLegacyLocalRules(logger, workspacePath, ideConf)
	}

	// Migration housekeeping runs OUTSIDE the configureRules gate (see
	// cleanupLegacyGlobalRules): a user running configure with
	// configureRules=false (MCP-only) has still abandoned the legacy
	// location, so the stale block in their personal CLAUDE.md should be
	// cleaned up regardless of whether rules are being configured this run.
	cleanupLegacyGlobalRules(logger, userInterface, ideConf)

	_ = userInterface.Output("\n🎉 Configuration complete!")
	_ = userInterface.Output("\nNext steps:")
	_ = userInterface.Output(fmt.Sprintf("  1. Restart %s to apply the changes", ideConf.name))
	_ = userInterface.Output("  2. The Snyk MCP server will be available for AI-powered security scanning")

	return nil
}

// cleanupLegacyLocalRules removes a workspace-relative legacy rules file
// left behind by an older install (e.g. .cursor/rules/snyk_rules.mdc from
// before the move to global skills). Best-effort: errors are logged at warn
// level and execution continues. Quiet by design — local-rules cleanup
// piggybacks on the rules-write call site and doesn't warrant its own user
// breadcrumb.
func cleanupLegacyLocalRules(logger *zerolog.Logger, workspacePath string, ideConf *hostConfig) {
	if ideConf.legacyLocalRulesPath == "" || workspacePath == "" {
		return
	}
	err := removeLocalRules(workspacePath, ideConf.legacyLocalRulesPath, logger)
	if err != nil {
		logger.Warn().Err(err).Msgf("Unable to clean up legacy local rules at %s", ideConf.legacyLocalRulesPath)
	}
}

// cleanupLegacyGlobalRules strips a Snyk delimited block left behind in a
// legacy shared file (e.g. ~/.claude/CLAUDE.md from claude-cli installs
// before the move to ~/.claude/rules/). Mutating a user-owned file is the
// kind of thing the user should see in the CLI output, so this helper
// announces the cleanup before running and surfaces any failure with a
// concrete pointer back to the legacy file. removeGlobalRules is
// idempotent (no-op when the delimited block is absent), so calling this
// on every configure/remove run is safe.
func cleanupLegacyGlobalRules(logger *zerolog.Logger, userInterface ui.UserInterface, ideConf *hostConfig) {
	if ideConf.legacyGlobalRulesPath == "" {
		return
	}
	_ = userInterface.Output(fmt.Sprintf("📋 Cleaning up legacy global rules block in: %s", ideConf.legacyGlobalRulesPath))
	err := removeGlobalRules(ideConf.legacyGlobalRulesPath, logger)
	if err != nil {
		logger.Warn().Err(err).Msgf("Unable to clean up legacy global rules at %s", ideConf.legacyGlobalRulesPath)
		_ = userInterface.Output(fmt.Sprintf("⚠️  Failed to clean up legacy global rules at %s — please inspect this file manually for the Snyk delimited block.", ideConf.legacyGlobalRulesPath))
	}
}

// determineCommand returns the command and args based on execution context
func determineCommand(cliPath, integrationName string) (string, []string) {
	if utils.IsRunningFromNpm(integrationName) {
		return "npx", []string{"-y", "snyk@latest", "mcp", "-t", "stdio"}
	}
	return cliPath, []string{"mcp", "-t", "stdio"}
}
