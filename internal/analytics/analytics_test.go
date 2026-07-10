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

package analytics

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/studio-mcp/internal/types"
	"github.com/stretchr/testify/require"
)

// These tests cover the "Session-scoped correlation ID on feedback events"
// requirement (specs/snyk-fix-feedback-verification): studio-mcp mints one
// correlation ID per process and stamps it on every snyk_send_feedback
// analytics event, replacing the previous behavior of minting a fresh random
// ID on every call.

func TestNewAnalyticsEventParam_CorrelationID(t *testing.T) {
	t.Run("stamps the provided correlation ID as InteractionUUID", func(t *testing.T) {
		event := NewAnalyticsEventParam("Send feedback", nil, types.FilePath("/tmp"), "session-correlation-id")
		require.Equal(t, "session-correlation-id", event.InteractionUUID)
	})

	t.Run("two calls with the same correlation ID (same session) share it", func(t *testing.T) {
		correlationID := "shared-session-id"
		first := NewAnalyticsEventParam("Send feedback", nil, types.FilePath("/tmp/a"), correlationID)
		second := NewAnalyticsEventParam("Send feedback", nil, types.FilePath("/tmp/b"), correlationID)

		require.Equal(t, correlationID, first.InteractionUUID)
		require.Equal(t, first.InteractionUUID, second.InteractionUUID)
	})

	t.Run("different correlation IDs (different sessions/processes) differ", func(t *testing.T) {
		first := NewAnalyticsEventParam("Send feedback", nil, types.FilePath("/tmp"), "session-a")
		second := NewAnalyticsEventParam("Send feedback", nil, types.FilePath("/tmp"), "session-b")

		require.NotEqual(t, first.InteractionUUID, second.InteractionUUID)
	})

	t.Run("empty correlation ID leaves InteractionUUID unset", func(t *testing.T) {
		event := NewAnalyticsEventParam("Send feedback", nil, types.FilePath("/tmp"), "")
		require.Empty(t, event.InteractionUUID)
	})
}

// setupMockEngine builds a minimal mock workflow.Engine sufficient for
// PayloadForAnalyticsEventParam, which only reads GetConfiguration()/GetRuntimeInfo().
func setupMockEngine(t *testing.T) *mocks.MockEngine {
	t.Helper()
	ctrl := gomock.NewController(t)
	engine := mocks.NewMockEngine(ctrl)
	engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	engine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	engine.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New(runtimeinfo.WithName("test"), runtimeinfo.WithVersion("1.0.0"))).AnyTimes()
	return engine
}

// interactionURN renders the instrumentation collector's payload to JSON and
// returns it as a string, so tests can assert on the embedded
// "urn:snyk:interaction:<id>" value without reaching into go-application-framework's
// internal API types.
func interactionURNPayload(t *testing.T, engine *mocks.MockEngine, event EventParam) string {
	t.Helper()
	ic := PayloadForAnalyticsEventParam(engine, "", event)
	obj, err := analytics.GetV2InstrumentationObject(ic)
	require.NoError(t, err)
	b, err := json.Marshal(obj)
	require.NoError(t, err)
	return string(b)
}

func TestPayloadForAnalyticsEventParam_CorrelationID(t *testing.T) {
	t.Run("preserves a pre-set session correlation ID instead of minting a fresh one", func(t *testing.T) {
		engine := setupMockEngine(t)
		correlationID := "session-correlation-id"
		event := NewAnalyticsEventParam("Send feedback", nil, types.FilePath("/tmp"), correlationID)

		payload := interactionURNPayload(t, engine, event)

		require.Contains(t, payload, "urn:snyk:interaction:"+correlationID)
	})

	t.Run("two events built from the same session correlation ID resolve to the same interaction URN", func(t *testing.T) {
		engine := setupMockEngine(t)
		correlationID := "shared-session-id"

		eventOne := NewAnalyticsEventParam("Send feedback", nil, types.FilePath("/tmp/a"), correlationID)
		eventTwo := NewAnalyticsEventParam("Send feedback", nil, types.FilePath("/tmp/b"), correlationID)

		payloadOne := interactionURNPayload(t, engine, eventOne)
		payloadTwo := interactionURNPayload(t, engine, eventTwo)

		expected := "urn:snyk:interaction:" + correlationID
		require.Contains(t, payloadOne, expected)
		require.Contains(t, payloadTwo, expected)
	})

	t.Run("mints a fresh interaction ID when InteractionUUID is unset", func(t *testing.T) {
		engine := setupMockEngine(t)
		event := NewAnalyticsEventParam("Send feedback", nil, types.FilePath("/tmp"), "")
		require.Empty(t, event.InteractionUUID, "sanity check: no correlation ID was provided")

		payload := interactionURNPayload(t, engine, event)

		require.Contains(t, payload, "urn:snyk:interaction:")
	})
}
