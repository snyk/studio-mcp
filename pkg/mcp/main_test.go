package mcp

import (
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/studio-mcp/internal/mcp"
	"github.com/stretchr/testify/assert"

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
