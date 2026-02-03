/*
 * © 2023 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/studio-mcp/internal/configure"
	"github.com/snyk/studio-mcp/internal/mcp"
	"github.com/snyk/studio-mcp/internal/trust"
	"github.com/snyk/studio-mcp/shared"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

var WORKFLOWID_MCP = workflow.NewWorkflowIdentifier("mcp")
var WORKFLOWID_MCP_CONFIG = workflow.NewWorkflowIdentifier("mcp.configure")

func Init(engine workflow.Engine) error {
	mcpFlags := pflag.NewFlagSet("mcp", pflag.ContinueOnError)
	mcpFlags.StringP(mcp.TransportParam, "t", "sse", "sets transport to <sse|stdio>")

	mcpFlags.Bool(configuration.FLAG_EXPERIMENTAL, false, "enable experimental mcp command")
	_ = mcpFlags.MarkDeprecated(configuration.FLAG_EXPERIMENTAL, "This is feature is in early access.")

	mcpFlags.Bool(trust.DisableTrustFlag, false, "disable folder trust")
	mcpFlags.StringP(shared.OutputDirParam, "o", "", "specifies the output directory for scan responses")
	mcpFlags.StringP(mcp.ProfileFlagName, "p", "", "sets the tool profile <lite|full|experimental>. 'full' (default) includes all non-experimental tools, 'lite' includes essential tools only, 'experimental' includes all tools")

	configureFlags := pflag.NewFlagSet("configure", pflag.ContinueOnError)
	configureFlags.StringP(shared.ToolNameParam, "t", "", "automatically configure snyk mcp server for a tool. supported tools: cursor, windsurf, antigravity, copilot, gemini-cli, claude-cli")
	configureFlags.StringP(shared.RulesScopeParam, "", "global", "set configuration scope for rules. supported values: global, workspace")
	configureFlags.String(shared.WorkspacePathParam, "", "workspace path for local rules (defaults to current directory)")
	configureFlags.String(shared.RuleTypeParam, shared.RuleTypeAlwaysApply, "choose rule type to write <always-apply|smart-apply>. default always-apply")
	configureFlags.Bool(shared.RemoveParam, false, "remove the Snyk MCP server from the specified tool configuration")
	configureFlags.Bool(shared.ConfigureMcpParam, true, "configure MCP server in tool's config file (default true)")
	configureFlags.Bool(shared.ConfigureRulesParam, true, "configure Snyk rules for the tool (default true)")

	mcpCfg := workflow.ConfigurationOptionsFromFlagset(mcpFlags)
	mcpEntry, _ := engine.Register(WORKFLOWID_MCP, mcpCfg, mcpWorkflow)

	configureCfg := workflow.ConfigurationOptionsFromFlagset(configureFlags)
	mcpConfigEntry, _ := engine.Register(WORKFLOWID_MCP_CONFIG, configureCfg, configureWorkflow)

	mcpEntry.SetVisibility(false)
	mcpConfigEntry.SetVisibility(false)

	return nil
}

func OnPanicRecover(logger *zerolog.Logger) {
	if err := recover(); err != nil {
		panickingMsg := "🚨 Panicking 🚨"
		_, _ = fmt.Fprintln(os.Stderr, panickingMsg)
		_, _ = fmt.Fprintln(os.Stderr, err)
		debug.PrintStack()

		logger.Error().Msg(panickingMsg)
		logger.Error().Any("recovered panic", err).Send()
		logger.Error().Msg(string(debug.Stack()))
	}
}

func mcpWorkflow(
	invocation workflow.InvocationContext,
	_ []workflow.Data,
) (output []workflow.Data, err error) {
	defer OnPanicRecover(invocation.GetEnhancedLogger())

	config := invocation.GetConfiguration()
	logger := invocation.GetEnhancedLogger()

	ideConfigPath := os.Getenv("IDE_CONFIG_PATH")
	if ideConfigPath != "" {
		storageErr := useIdeStorage(invocation, ideConfigPath)
		if storageErr != nil {
			logger.Err(storageErr).Msgf("Failed to use IDE storage specified in path %s", ideConfigPath)
		}
	}

	config.Set(configuration.INTEGRATION_NAME, "MCP")

	runtimeInfo := invocation.GetRuntimeInfo()
	if runtimeInfo != nil {
		config.Set(configuration.INTEGRATION_VERSION, runtimeInfo.GetVersion())
	} else {
		config.Set(configuration.INTEGRATION_VERSION, "unknown")
	}

	output = []workflow.Data{}

	cliPath, err := getCliPath(invocation)
	if err != nil {
		logger.Err(err).Msg("Failed to set cli path")
		return output, err
	}
	logger.Trace().Interface("environment", os.Environ()).Msg("start environment")
	config.PersistInStorage(trust.TrustedFoldersConfigKey)
	config.PersistInStorage(auth.CONFIG_KEY_OAUTH_TOKEN)
	config.PersistInStorage(configuration.AUTHENTICATION_TOKEN)

	mcpStart(invocation, cliPath)

	return output, nil
}

func configureWorkflow(
	invocation workflow.InvocationContext,
	_ []workflow.Data,
) (output []workflow.Data, err error) {
	defer OnPanicRecover(invocation.GetEnhancedLogger())

	config := invocation.GetConfiguration()
	logger := invocation.GetEnhancedLogger()

	config.Set(configuration.INTEGRATION_NAME, "MCP")

	runtimeInfo := invocation.GetRuntimeInfo()
	if runtimeInfo != nil {
		config.Set(configuration.INTEGRATION_VERSION, runtimeInfo.GetVersion())
	} else {
		config.Set(configuration.INTEGRATION_VERSION, "unknown")
	}

	output = []workflow.Data{}

	cliPath, err := getCliPath(invocation)
	if err != nil {
		logger.Err(err).Msg("Failed to set cli path")
		return output, err
	}
	logger.Trace().Interface("environment", os.Environ()).Msg("start environment")

	err = configure.Configure(invocation.GetEnhancedLogger(), invocation.GetConfiguration(), invocation.GetUserInterface(), cliPath)
	if err != nil {
		logger.Err(err).Msg("Failed to configure mcp server")
		return nil, err
	}

	return output, nil
}

func lsConfigFile(ideName string) (string, error) {
	fileName := fmt.Sprintf("ls-config-%s", ideName)
	path := filepath.Join("snyk", fileName)
	return xdg.ConfigFile(path)
}

func useIdeStorage(invocationCtx workflow.InvocationContext, ideConfigPath string) error {
	logger := invocationCtx.GetEnhancedLogger()
	file, err := lsConfigFile(ideConfigPath)
	if err != nil {
		return err
	}

	// The config file must exist and MCP server shouldn't create it.
	if _, err = os.Stat(file); err != nil {
		return err
	}
	storage := configuration.NewJsonStorage(file, configuration.WithConfiguration(invocationCtx.GetEngine().GetConfiguration()))

	config := invocationCtx.GetConfiguration()
	config.SetStorage(storage)
	globalConfig := invocationCtx.GetEngine().GetConfiguration()
	globalConfig.SetStorage(storage)

	// Force refresh of in-memory values
	err = storage.Refresh(config, auth.CONFIG_KEY_OAUTH_TOKEN)
	if err != nil {
		logger.Err(err).Msg("Failed to refresh oauth token for local config")
	}
	err = storage.Refresh(config, configuration.AUTHENTICATION_TOKEN)
	if err != nil {
		logger.Err(err).Msg("Failed to refresh authentication token local config")
	}
	err = storage.Refresh(globalConfig, auth.CONFIG_KEY_OAUTH_TOKEN)
	if err != nil {
		logger.Err(err).Msg("Failed to refresh oauth token for global config")
	}
	err = storage.Refresh(globalConfig, configuration.AUTHENTICATION_TOKEN)
	if err != nil {
		logger.Err(err).Msg("Failed to refresh authentication token for global config")
	}

	return nil
}

func mcpStart(invocationContext workflow.InvocationContext, cliPath string) {
	logger := invocationContext.GetEnhancedLogger()
	mcpServer := mcp.NewMcpLLMBinding(mcp.WithLogger(invocationContext.GetEnhancedLogger()), mcp.WithCliPath(cliPath))

	// start mcp server
	err := mcpServer.Start(invocationContext)

	if err != nil {
		logger.Err(err).Msg("failed to start mcp server")
	}
	defer func() {
		logger.Info().Msg("Shutting down MCP Server...")
		mcpServer.Shutdown(context.Background())
	}()
}

func getCliPath(ctx workflow.InvocationContext) (string, error) {
	logger := ctx.GetEnhancedLogger()
	exePath, err := os.Executable()
	if err != nil {
		logger.Err(err).Msg("Failed to get executable path")
		return "", err
	}

	resolvedPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		logger.Err(err).Msg("Failed to eval symlink from path")
		resolvedPath = exePath
	}
	return resolvedPath, nil
}
