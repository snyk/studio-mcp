package configure

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/studio-mcp/shared"
)

// ErrConfigureRemoved is returned when Configure is called without --rm.
// `snyk studio install` now writes the Snyk MCP server, hooks, and skills.
var ErrConfigureRemoved = errors.New("snyk mcp configure only supports --rm; use `snyk studio install` to install Snyk Studio")

// Configure removes the Snyk MCP server and the legacy Snyk rules and skills
// from the specified IDE host. snyk-ls calls it once, after its first
// `snyk studio install`, to clean up what older IDE extensions wrote.
func Configure(logger *zerolog.Logger, config configuration.Configuration, userInterface ui.UserInterface) error {
	if !config.GetBool(shared.RemoveParam) {
		return ErrConfigureRemoved
	}

	ideConf, err := getHostConfig(config.GetString(shared.ToolNameParam))
	if err != nil {
		return err
	}

	rulesScope := config.GetString(shared.RulesScopeParam)
	workspacePath := config.GetString(shared.WorkspacePathParam)
	configureMcp := config.GetBool(shared.ConfigureMcpParam)
	configureRules := config.GetBool(shared.ConfigureRulesParam)

	// Remove MCP server from config (only if configureMcp is true)
	if configureMcp {
		if ideConf.mcpGlobalConfigPath != "" {
			_ = userInterface.Output(fmt.Sprintf("📝 Removing MCP server from: %s", ideConf.mcpGlobalConfigPath))

			err := removeMcpServerFromJson(ideConf.mcpGlobalConfigPath, logger)
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

			err := removeFileIfExists(ideConf.globalSkillsPath, logger)
			if err != nil {
				return fmt.Errorf("failed to remove global skills for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully removed global skills for %s", ideConf.name))
			logger.Info().Msgf("Successfully removed global skills for %s from %s", ideConf.name, ideConf.globalSkillsPath)
		}

		// Remove global rules (e.g. Windsurf, Antigravity, VS Code, gemini-cli, claude-cli)
		if rulesScope == shared.RulesGlobalScope && ideConf.globalRulesPath != "" {
			_ = userInterface.Output(fmt.Sprintf("📋 Removing global rules from: %s", ideConf.globalRulesPath))

			err := removeGlobalRules(ideConf.globalRulesPath, logger)
			if err != nil {
				return fmt.Errorf("failed to remove global rules for %s: %w", ideConf.name, err)
			}

			_ = userInterface.Output(fmt.Sprintf("✅ Successfully removed global rules for %s", ideConf.name))
			logger.Info().Msgf("Successfully removed global rules for %s from %s", ideConf.name, ideConf.globalRulesPath)
		}

		// Clean up legacy local rules
		if ideConf.legacyLocalRulesPath != "" && workspacePath != "" {
			err := removeFileIfExists(filepath.Join(workspacePath, ideConf.legacyLocalRulesPath), logger)
			if err != nil {
				logger.Warn().Err(err).Msgf("Unable to clean up legacy local rules at %s", ideConf.legacyLocalRulesPath)
			}
		}
	}

	_ = userInterface.Output("\n🎉 Removal complete!")
	_ = userInterface.Output("\nNext steps:")
	_ = userInterface.Output(fmt.Sprintf("  1. Restart %s to apply the changes", ideConf.name))

	return nil
}
