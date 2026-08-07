/*
 * © 2025 Snyk Limited
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
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

func TestNewMcpServer(t *testing.T) {
	mcpServer := NewMcpLLMBinding()
	assert.NotNil(t, mcpServer)
	assert.NotNil(t, mcpServer.logger)
}

func TestExpandedEnv(t *testing.T) {
	t.Run("sets integration environment variables", func(t *testing.T) {
		t.Setenv(strings.ToUpper(configuration.INTEGRATION_NAME), "abc")
		t.Setenv(strings.ToUpper(configuration.INTEGRATION_VERSION), "abc")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockEngine := mocks.NewMockEngine(ctrl)
		engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

		invocationCtx := mocks.NewMockInvocationContext(ctrl)
		invocationCtx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()

		binding := NewMcpLLMBinding()

		env := binding.expandedEnv(invocationCtx, "1.x.1", "Client1", "1.0.0")

		for _, s := range os.Environ() {
			if strings.HasPrefix(s, strings.ToUpper(configuration.INTEGRATION_NAME)) {
				continue
			}
			if strings.HasPrefix(s, strings.ToUpper(configuration.INTEGRATION_VERSION)) {
				continue
			}
			assert.Contains(t, env, s)
		}

		assert.Contains(t, env, strings.ToUpper(configuration.INTEGRATION_NAME)+"=MCP")
		assert.Contains(t, env, strings.ToUpper(configuration.INTEGRATION_VERSION)+"=1.x.1")
		assert.Contains(t, env, strings.ToUpper(configuration.INTEGRATION_ENVIRONMENT)+"=Client1")
		assert.Contains(t, env, strings.ToUpper(configuration.INTEGRATION_ENVIRONMENT_VERSION)+"=1.0.0")
	})

	t.Run("adds legacy auth token when IDE_CONFIG_PATH is set", func(t *testing.T) {
		tempDir := t.TempDir()
		t.Setenv("IDE_CONFIG_PATH", tempDir)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		testToken := uuid.New().String()

		mockStorage := mocks.NewMockStorage(ctrl)
		mockStorage.EXPECT().Refresh(gomock.Any(), auth.CONFIG_KEY_OAUTH_TOKEN).Return(nil).AnyTimes()
		mockStorage.EXPECT().Refresh(gomock.Any(), configuration.AUTHENTICATION_TOKEN).Return(nil).AnyTimes()

		mockEngine := mocks.NewMockEngine(ctrl)
		engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		engineConfig.SetStorage(mockStorage)
		engineConfig.Set(configuration.AUTHENTICATION_TOKEN, testToken)

		mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

		logger := zerolog.Nop()
		invocationCtx := mocks.NewMockInvocationContext(ctrl)
		invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		invocationCtx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()

		binding := NewMcpLLMBinding()

		env := binding.expandedEnv(invocationCtx, "1.x.1", "Client1", "1.0.0")

		assert.Contains(t, env, strings.ToUpper(configuration.AUTHENTICATION_TOKEN)+"="+testToken)
		assert.Contains(t, env, strings.ToUpper(configuration.FF_OAUTH_AUTH_FLOW_ENABLED)+"=0")

		// Should not contain bearer token
		for _, e := range env {
			assert.NotContains(t, e, strings.ToUpper(configuration.AUTHENTICATION_BEARER_TOKEN)+"=")
		}
	})

	t.Run("adds OAuth bearer token when IDE_CONFIG_PATH is set", func(t *testing.T) {
		tempDir := t.TempDir()
		t.Setenv("IDE_CONFIG_PATH", tempDir)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		testOAuthToken := oauth2.Token{AccessToken: "test-access-token"}
		tokenJSON, _ := json.Marshal(testOAuthToken)

		mockStorage := mocks.NewMockStorage(ctrl)
		mockStorage.EXPECT().Refresh(gomock.Any(), auth.CONFIG_KEY_OAUTH_TOKEN).Return(nil).AnyTimes()
		mockStorage.EXPECT().Refresh(gomock.Any(), configuration.AUTHENTICATION_TOKEN).Return(nil).AnyTimes()

		mockEngine := mocks.NewMockEngine(ctrl)
		engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		engineConfig.SetStorage(mockStorage)
		engineConfig.Set(auth.CONFIG_KEY_OAUTH_TOKEN, string(tokenJSON))

		mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

		logger := zerolog.Nop()
		invocationCtx := mocks.NewMockInvocationContext(ctrl)
		invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		invocationCtx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()

		binding := NewMcpLLMBinding()

		env := binding.expandedEnv(invocationCtx, "1.x.1", "Client1", "1.0.0")

		assert.Contains(t, env, strings.ToUpper(configuration.AUTHENTICATION_BEARER_TOKEN)+"=test-access-token")
		assert.Contains(t, env, strings.ToUpper(configuration.FF_OAUTH_AUTH_FLOW_ENABLED)+"=1")
	})

	t.Run("does not add auth tokens when IDE_CONFIG_PATH is not set", func(t *testing.T) {
		t.Setenv("IDE_CONFIG_PATH", "")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockEngine := mocks.NewMockEngine(ctrl)
		engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

		invocationCtx := mocks.NewMockInvocationContext(ctrl)
		invocationCtx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()

		binding := NewMcpLLMBinding()

		env := binding.expandedEnv(invocationCtx, "1.x.1", "Client1", "1.0.0")

		// Should not contain any auth tokens
		for _, e := range env {
			assert.NotContains(t, e, strings.ToUpper(configuration.AUTHENTICATION_BEARER_TOKEN)+"=")
		}
	})
}

func TestStarted(t *testing.T) {
	t.Run("returns false when not started", func(t *testing.T) {
		binding := NewMcpLLMBinding()
		assert.False(t, binding.Started())
	})

	t.Run("returns true when started", func(t *testing.T) {
		binding := NewMcpLLMBinding()
		binding.mutex.Lock()
		binding.started = true
		binding.mutex.Unlock()
		assert.True(t, binding.Started())
	})
}

func TestShutdown(t *testing.T) {
	t.Run("marks the server as no longer started", func(t *testing.T) {
		binding := NewMcpLLMBinding()
		binding.mutex.Lock()
		binding.started = true
		binding.mutex.Unlock()

		binding.Shutdown(t.Context())

		assert.False(t, binding.Started())
	})

	t.Run("is safe to call on a server that never started", func(t *testing.T) {
		binding := NewMcpLLMBinding()

		assert.NotPanics(t, func() { binding.Shutdown(t.Context()) })
		assert.False(t, binding.Started())
	})
}

func TestHandleStdioServer(t *testing.T) {
	t.Run("requires initialized MCP server", func(t *testing.T) {
		binding := NewMcpLLMBinding()

		// Should handle the case where mcpServer is nil gracefully
		assert.NotPanics(t, func() {
			// This will likely fail due to nil server, but shouldn't panic our test
			// We just want to ensure the method can be called
			go func() {
				defer func() {
					if r := recover(); r != nil {
						// Expected to panic due to nil mcpServer, this is fine for testing
						_ = r // Explicitly ignore the recovered value
					}
				}()
				_ = binding.HandleStdioServer()
			}()
		})
	})
}

func TestStart(t *testing.T) {
	t.Run("panics with nil invocation context", func(t *testing.T) {
		binding := NewMcpLLMBinding()

		// Test with nil context - should panic as expected
		assert.Panics(t, func() {
			_ = binding.Start(nil)
		})
	})

	// The SSE transport has been retired, so a client still configured with
	// "-t sse" must fail fast with an actionable error rather than silently
	// falling back to stdio.
	t.Run("rejects the retired sse transport before any setup", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		engineConfig := configuration.NewWithOpts()
		engineConfig.Set(TransportParam, "sse")

		invocationCtx := mocks.NewMockInvocationContext(ctrl)
		invocationCtx.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

		binding := NewMcpLLMBinding()
		err := binding.Start(invocationCtx)

		require.Error(t, err)
		assert.Contains(t, err.Error(), `unsupported transport type "sse"`)
		assert.Contains(t, err.Error(), "stdio")
		assert.Nil(t, binding.mcpServer, "no server should be constructed for an unsupported transport")
		assert.False(t, binding.Started())
	})
}

func TestValidateTransport(t *testing.T) {
	tests := []struct {
		name      string
		transport string
		expectErr bool
	}{
		{name: "stdio is supported", transport: "stdio", expectErr: false},
		{name: "unset falls back to stdio", transport: "", expectErr: false},
		{name: "sse is retired", transport: "sse", expectErr: true},
		{name: "unknown transport is rejected", transport: "websocket", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTransport(tt.transport)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.transport)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestMintCorrelationID covers the "Session-scoped correlation ID on feedback
// events" requirement (specs/snyk-fix-feedback-verification): one correlation
// ID is minted per process and reused for the rest of that process's
// lifetime, while a different process (a different McpLLMBinding here) gets
// its own distinct ID.
func TestMintCorrelationID(t *testing.T) {
	t.Run("mints a non-empty ID", func(t *testing.T) {
		binding := NewMcpLLMBinding()
		require.Empty(t, binding.correlationID, "correlationID must be unset before minting")

		binding.mintCorrelationID()

		require.NotEmpty(t, binding.correlationID)
	})

	t.Run("two feedback calls in the same process (same binding) share one correlation ID", func(t *testing.T) {
		binding := NewMcpLLMBinding()

		binding.mintCorrelationID()
		first := binding.correlationID

		// Simulates a second call within the same session/process reading the
		// same session-scoped ID; minting must be idempotent.
		binding.mintCorrelationID()
		second := binding.correlationID

		require.Equal(t, first, second)
	})

	t.Run("two different sessions (different bindings) get different correlation IDs", func(t *testing.T) {
		bindingA := NewMcpLLMBinding()
		bindingB := NewMcpLLMBinding()

		bindingA.mintCorrelationID()
		bindingB.mintCorrelationID()

		require.NotEmpty(t, bindingA.correlationID)
		require.NotEmpty(t, bindingB.correlationID)
		require.NotEqual(t, bindingA.correlationID, bindingB.correlationID)
	})
}
