package mcp

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/studio-mcp/internal/configure"
	"github.com/snyk/studio-mcp/internal/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/app"
)

func Test_redactedEnviron(t *testing.T) {
	t.Setenv("SNYK_TOKEN", "supersecret123")
	t.Setenv("SNYK_OAUTH_TOKEN", "oauthsecret456")
	t.Setenv("SNYK_CFG_ORG", "acme")

	env := redactedEnviron()

	assert.Contains(t, env, "SNYK_TOKEN=***")
	assert.Contains(t, env, "SNYK_OAUTH_TOKEN=***")
	assert.Contains(t, env, "SNYK_CFG_ORG=acme")

	for _, kv := range env {
		assert.NotContains(t, kv, "supersecret123")
		assert.NotContains(t, kv, "oauthsecret456")
		assert.NotContains(t, kv, "authsecret789")
	}
}

func Test_isSensitiveEnvName(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		expected bool
	}{
		{"snyk token", "SNYK_TOKEN", true},
		{"oauth token", "SNYK_OAUTH_TOKEN", true},
		{"lowercase", "api_token", true},
		{"non-sensitive path", "PATH", false},
		{"non-sensitive org", "SNYK_CFG_ORG", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isSensitiveEnvName(tt.envName))
		})
	}
}

func Test_ExtensionEntryPoint(t *testing.T) {
	expectedTransportType := "stdio"
	engine := app.CreateAppEngineWithOptions()

	engineConfig := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
	)
	engineConfig.Set(mcp.TransportParam, expectedTransportType)

	//register extension under test
	err := Init(engine)
	assert.Nil(t, err)

	go func() {
		err = engine.Init()
		assert.Nil(t, err)

		data, err := engine.InvokeWithConfig(WORKFLOWID_MCP, engineConfig)
		assert.Nil(t, err)
		assert.Empty(t, data)
	}()

	assert.Eventuallyf(t, func() bool {
		return expectedTransportType == engineConfig.GetString(mcp.TransportParam)
	}, time.Minute, time.Millisecond, "")
}

func Test_ConfigureWorkflow(t *testing.T) {
	// invokeConfigure parses args with the registered flags, as the CLI does,
	// and runs the workflow without the engine's network-backed defaults.
	invokeConfigure := func(t *testing.T, args []string) error {
		t.Helper()
		engine := app.CreateAppEngineWithOptions()
		require.NoError(t, Init(engine))
		entry, ok := engine.GetWorkflow(WORKFLOWID_MCP_CONFIG)
		require.True(t, ok)

		flags := workflow.FlagsetFromConfigurationOptions(entry.GetConfigurationOptions())
		require.NoError(t, flags.Parse(args))
		config := configuration.NewWithOpts()
		require.NoError(t, config.AddFlagSet(flags))

		ctrl := gomock.NewController(t)
		logger := zerolog.Nop()
		userInterface := mocks.NewMockUserInterface(ctrl)
		userInterface.EXPECT().Output(gomock.Any()).AnyTimes()
		invocation := mocks.NewMockInvocationContext(ctrl)
		invocation.EXPECT().GetConfiguration().Return(config).AnyTimes()
		invocation.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		invocation.EXPECT().GetUserInterface().Return(userInterface).AnyTimes()
		invocation.EXPECT().GetRuntimeInfo().Return(nil).AnyTimes()

		_, err := configureWorkflow(invocation, nil)
		return err
	}

	t.Run("accepts the legacy rules cleanup call", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		rulesPath := filepath.Join(home, ".claude", "CLAUDE.md")
		require.NoError(t, os.MkdirAll(filepath.Dir(rulesPath), 0755))
		require.NoError(t, os.WriteFile(rulesPath, []byte(configure.RuleStart+"\n# Snyk Rules\n"+configure.RuleEnd+"\n"), 0644))

		// The arguments the installers pass to `snyk mcp configure`.
		err := invokeConfigure(t, []string{
			"--tool", "claude-cli", "--rm",
			"--rules-scope", "global", "--rule-type", "always-apply", "--workspace", t.TempDir(),
			"--configure-mcp=false", "--configure-rules=true",
		})
		require.NoError(t, err)

		rules, err := os.ReadFile(rulesPath)
		require.NoError(t, err)
		assert.Empty(t, string(rules))
	})

	t.Run("rejects calls without --rm", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		err := invokeConfigure(t, []string{"--tool", "claude-cli"})

		assert.ErrorIs(t, err, configure.ErrConfigureRemoved)
		assert.NoFileExists(t, filepath.Join(home, ".claude.json"))
		assert.NoFileExists(t, filepath.Join(home, ".claude", "CLAUDE.md"))
	})
}
