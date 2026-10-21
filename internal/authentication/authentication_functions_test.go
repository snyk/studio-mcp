/*
 * © 2026 Snyk Limited
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

package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	pkgerrors "github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// wrapLikeWhoAmI wraps err the way it reaches snyk_auth from a real whoami:
// the transport error inside a *url.Error from http.Client, then the whoami
// workflow's %w, then CallWhoAmI's errors.Wrap.
func wrapLikeWhoAmI(err error) error {
	transport := &url.Error{Op: "Get", URL: "https://api.snyk.io/rest/self", Err: err}
	return pkgerrors.Wrap(fmt.Errorf("error fetching user data: %w", transport), "failed to invoke whoami workflow")
}

// wrapLikeOAuthRefresh wraps err the way a failed OAuth refresh reaches
// snyk_auth: the token endpoint's error inside a *url.Error, joined with GAF's
// ErrAuthenticationFailed by the auth header middleware, then as whoami.
func wrapLikeOAuthRefresh(err error) error {
	refresh := &url.Error{Op: "Post", URL: "https://api.snyk.io/oauth2/token", Err: err}
	return wrapLikeWhoAmI(errors.Join(refresh, middleware.ErrAuthenticationFailed))
}

func TestIsAuthError(t *testing.T) {
	otherCodeWith401 := snyk.NewBadRequestError("")
	otherCodeWith401.StatusCode = 401

	testCases := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil is not an auth error",
			err:      nil,
			expected: false,
		},
		{
			name:     "unauthorised from the response middleware is an auth error",
			err:      wrapLikeWhoAmI(snyk.NewUnauthorisedError("Use `snyk auth` to authenticate.")),
			expected: true,
		},
		{
			name:     "a catalog error carrying status 401 is an auth error",
			err:      wrapLikeWhoAmI(otherCodeWith401),
			expected: true,
		},
		{
			name:     "unauthorised joined with other API errors is an auth error",
			err:      wrapLikeWhoAmI(errors.Join(snyk.NewUnauthorisedError(""), snyk_errors.Error{Title: "other"})),
			expected: true,
		},
		{
			name:     "a network failure is not an auth error",
			err:      wrapLikeWhoAmI(&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: network is unreachable")}),
			expected: false,
		},
		{
			name:     "a DNS failure is not an auth error",
			err:      wrapLikeWhoAmI(&net.DNSError{Err: "no such host", Name: "api.snyk.io"}),
			expected: false,
		},
		{
			name:     "a timeout is not an auth error",
			err:      wrapLikeWhoAmI(context.DeadlineExceeded),
			expected: false,
		},
		{
			name:     "a server error is not an auth error",
			err:      wrapLikeWhoAmI(snyk.NewServerError("Internal server error.")),
			expected: false,
		},
		{
			name:     "rate limiting is not an auth error",
			err:      wrapLikeWhoAmI(snyk.NewTooManyRequestsError("")),
			expected: false,
		},
		{
			name:     "a bad request from the API is not an auth error",
			err:      wrapLikeWhoAmI(snyk.NewBadRequestError("")),
			expected: false,
		},
		{
			name:     "an OAuth refresh the token endpoint rejected is an auth error",
			err:      wrapLikeOAuthRefresh(snyk.NewBadRequestError("")),
			expected: true,
		},
		{
			name:     "a network failure during an OAuth refresh is not an auth error",
			err:      wrapLikeOAuthRefresh(cli.NewConnectionRefusedError("")),
			expected: false,
		},
		{
			name:     "a server error during an OAuth refresh is not an auth error",
			err:      wrapLikeOAuthRefresh(snyk.NewServerError("")),
			expected: false,
		},
		{
			name:     "an unparseable whoami payload is not an auth error",
			err:      pkgerrors.Wrap(errors.New("unexpected end of JSON input"), "unable to unmarshal user data"),
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsAuthError(tc.err))
		})
	}
}

// newWhoAmIEngine builds a real GAF engine pointed at apiURL, with an error
// handler registered the way the snyk CLI does at startup (cliv2
// pkg/core/main.go). GAF only maps HTTP status codes to error catalog errors
// once a handler is registered.
func newWhoAmIEngine(t *testing.T, apiURL string, setCredentials func(configuration.Configuration)) workflow.Engine {
	t.Helper()
	logger := zerolog.Nop()
	config := configuration.NewWithOpts()
	engine := app.CreateAppEngineWithOptions(app.WithConfiguration(config), app.WithZeroLogger(&logger))
	config.Set(configuration.API_URL, apiURL)
	setCredentials(config)
	engine.GetNetworkAccess().AddErrorHandler(func(err error, _ context.Context) error { return err })
	require.NoError(t, engine.Init())
	return engine
}

func withAPIToken(config configuration.Configuration) {
	config.Set(configuration.AUTHENTICATION_TOKEN, "00000000-0000-0000-0000-000000000000")
}

// withExpiredOAuthToken stores an OAuth login whose access token has expired,
// so the next request makes GAF refresh it against the token endpoint first.
func withExpiredOAuthToken(t *testing.T) func(configuration.Configuration) {
	t.Helper()
	token, err := json.Marshal(&oauth2.Token{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", Expiry: time.Now().Add(-time.Hour)})
	require.NoError(t, err)
	return func(config configuration.Configuration) {
		config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)
		config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, string(token))
	}
}

// IsAuthError relies on GAF turning a 401 into the catalog's Unauthorised
// error. This runs the real whoami workflow through GAF's networking stack, so
// a change in that mapping fails here.
func TestCallWhoAmI_ErrorsClassifyThroughGAF(t *testing.T) {
	testCases := []struct {
		name          string
		status        int // 0: nothing listening
		expectAuthErr bool
	}{
		{
			name:          "a 401 from Snyk is an auth error",
			status:        http.StatusUnauthorized,
			expectAuthErr: true,
		},
		{
			name:          "a 500 from Snyk is not an auth error",
			status:        http.StatusInternalServerError,
			expectAuthErr: false,
		},
		{
			name:          "a refused connection is not an auth error",
			status:        0,
			expectAuthErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(server.Close)
			if tc.status == 0 {
				server.Close()
			}

			logger := zerolog.Nop()
			_, err := CallWhoAmI(&logger, newWhoAmIEngine(t, server.URL, withAPIToken))

			require.Error(t, err)
			assert.Equal(t, tc.expectAuthErr, IsAuthError(err), "whoami error: %v", err)
		})
	}
}

// With an expired OAuth access token, whoami fails in the refresh before it
// reaches /rest/self. Snyk's token endpoint answers a dead refresh token with
// 400 invalid_grant, not 401.
func TestCallWhoAmI_OAuthRefreshErrorsClassifyThroughGAF(t *testing.T) {
	testCases := []struct {
		name          string
		status        int // 0: nothing listening
		body          string
		expectAuthErr bool
	}{
		{
			name:          "a refresh token the token endpoint rejects is an auth error",
			status:        http.StatusBadRequest,
			body:          `{"error":"invalid_grant","error_description":"The provided authorization grant or refresh token is invalid, expired or revoked."}`,
			expectAuthErr: true,
		},
		{
			name:          "a 500 from the token endpoint is not an auth error",
			status:        http.StatusInternalServerError,
			expectAuthErr: false,
		},
		{
			name:          "a refused connection during the refresh is not an auth error",
			status:        0,
			expectAuthErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/oauth2/token") {
					t.Errorf("whoami reached %s; the refresh should have failed first", r.URL.Path)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(server.Close)
			if tc.status == 0 {
				server.Close()
			}

			logger := zerolog.Nop()
			_, err := CallWhoAmI(&logger, newWhoAmIEngine(t, server.URL, withExpiredOAuthToken(t)))

			require.Error(t, err)
			require.ErrorIs(t, err, middleware.ErrAuthenticationFailed)
			assert.Equal(t, tc.expectAuthErr, IsAuthError(err), "whoami error: %v", err)
		})
	}
}
