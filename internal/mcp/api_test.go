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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/require"
)

func TestEnableSnykCodeForOrg(t *testing.T) {
	testCases := []struct {
		name           string
		orgId          string
		apiToken       string
		mockStatusCode int
		mockResponse   map[string]interface{}
		expectError    bool
		errorContains  string
	}{
		{
			name:           "Successful Enable (201 Created)",
			orgId:          "test-org-123",
			apiToken:       "test-token",
			mockStatusCode: http.StatusCreated,
			mockResponse: map[string]interface{}{
				"data": map[string]interface{}{
					"type": "sast_settings",
					"id":   "test-org-123",
					"attributes": map[string]interface{}{
						"sast_enabled": true,
					},
				},
			},
			expectError: false,
		},
		{
			name:           "Missing Org ID",
			orgId:          "",
			apiToken:       "test-token",
			mockStatusCode: http.StatusCreated,
			expectError:    true,
			errorContains:  "organization ID not found",
		},
		{
			name:           "API Returns 400 Bad Request",
			orgId:          "test-org-123",
			apiToken:       "test-token",
			mockStatusCode: http.StatusBadRequest,
			mockResponse: map[string]interface{}{
				"errors": []interface{}{
					map[string]interface{}{
						"status": "400",
						"detail": "Bad request",
					},
				},
			},
			expectError:   true,
			errorContains: "API request failed with status 400",
		},
		{
			name:           "API Returns 401 Unauthorized",
			orgId:          "test-org-123",
			apiToken:       "invalid-token",
			mockStatusCode: http.StatusUnauthorized,
			mockResponse: map[string]interface{}{
				"errors": []interface{}{
					map[string]interface{}{
						"status": "401",
						"detail": "Invalid authentication credentials",
					},
				},
			},
			expectError:   true,
			errorContains: "API request failed with status 401",
		},
		{
			name:           "API Returns 403 Forbidden",
			orgId:          "test-org-123",
			apiToken:       "test-token",
			mockStatusCode: http.StatusForbidden,
			mockResponse: map[string]interface{}{
				"errors": []interface{}{
					map[string]interface{}{
						"status": "403",
						"detail": "Insufficient permissions",
					},
				},
			},
			expectError:   true,
			errorContains: "API request failed with status 403",
		},
		{
			name:           "API Returns 404 Not Found",
			orgId:          "invalid-org",
			apiToken:       "test-token",
			mockStatusCode: http.StatusNotFound,
			mockResponse: map[string]interface{}{
				"errors": []interface{}{
					map[string]interface{}{
						"status": "404",
						"detail": "Organization not found",
					},
				},
			},
			expectError:   true,
			errorContains: "API request failed with status 404",
		},
		{
			name:           "API Returns 500 Server Error",
			orgId:          "test-org-123",
			apiToken:       "test-token",
			mockStatusCode: http.StatusInternalServerError,
			mockResponse: map[string]interface{}{
				"errors": []interface{}{
					map[string]interface{}{
						"status": "500",
						"detail": "Internal server error",
					},
				},
			},
			expectError:   true,
			errorContains: "API request failed with status 500",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "PATCH", r.Method)

				if tc.orgId != "" {
					require.Contains(t, r.URL.Path, tc.orgId)
				}

				require.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))

				if tc.orgId != "" {
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)

					var requestBody map[string]interface{}
					err = json.Unmarshal(body, &requestBody)
					require.NoError(t, err)

					data, ok := requestBody["data"].(map[string]interface{})
					require.True(t, ok)

					attributes, ok := data["attributes"].(map[string]interface{})
					require.True(t, ok)

					require.Equal(t, true, attributes["sast_enabled"])
				}

				w.Header().Set("Content-Type", "application/vnd.api+json")
				w.WriteHeader(tc.mockStatusCode)
				if tc.mockResponse != nil {
					_ = json.NewEncoder(w).Encode(tc.mockResponse)
				}
			}))
			defer mockServer.Close()

			fixture := setupTestFixture(t)
			config := fixture.invocationContext.GetConfiguration()
			config.Set(configuration.API_URL, mockServer.URL)
			config.Set(configuration.AUTHENTICATION_TOKEN, tc.apiToken)
			config.Set(configuration.ORGANIZATION, tc.orgId)

			// Mock network access to return test HTTP client
			mockNetworkAccess := mocks.NewMockNetworkAccess(gomock.NewController(t))
			mockNetworkAccess.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()
			fixture.invocationContext.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()

			err := fixture.binding.enableSnykCodeForOrg(context.Background(), fixture.invocationContext, tc.orgId)

			if tc.expectError {
				require.Error(t, err)
				if tc.errorContains != "" {
					require.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEnableSnykCodeForOrg_URLConstruction(t *testing.T) {
	testCases := []struct {
		name                 string
		apiUrlSuffix         string
		orgId                string
		expectedPathContains string
	}{
		{
			name:                 "Standard API URL",
			apiUrlSuffix:         "",
			orgId:                "test-org-123",
			expectedPathContains: "/rest/orgs/test-org-123/settings/sast",
		},
		{
			name:                 "API URL with /v1",
			apiUrlSuffix:         "/v1",
			orgId:                "test-org-456",
			expectedPathContains: "/rest/orgs/test-org-456/settings/sast",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			correctURLCalled := false

			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tc.expectedPathContains {
					correctURLCalled = true
				}
				t.Logf("Received request to path: %s (expected: %s)", r.URL.Path, tc.expectedPathContains)

				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"type": "sast_settings",
						"id":   tc.orgId,
						"attributes": map[string]interface{}{
							"sast_enabled": true,
						},
					},
				})
			}))
			defer mockServer.Close()

			fixture := setupTestFixture(t)
			config := fixture.invocationContext.GetConfiguration()

			config.Set(configuration.API_URL, mockServer.URL+tc.apiUrlSuffix)
			config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")

			// Mock network access to return test HTTP client
			mockNetworkAccess := mocks.NewMockNetworkAccess(gomock.NewController(t))
			mockNetworkAccess.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()
			fixture.invocationContext.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()

			err := fixture.binding.enableSnykCodeForOrg(context.Background(), fixture.invocationContext, tc.orgId)

			require.NoError(t, err)
			require.True(t, correctURLCalled, "Expected URL path %s was not called", tc.expectedPathContains)
		})
	}
}

func TestEnableSnykCodeForOrg_Timeout(t *testing.T) {
	// Create a mock server that delays longer than the timeout
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep longer than apiRequestTimeout (30s) - but we'll use a shorter test timeout
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusCreated)
	}))
	defer mockServer.Close()

	fixture := setupTestFixture(t)
	config := fixture.invocationContext.GetConfiguration()
	config.Set(configuration.API_URL, mockServer.URL)
	config.Set(configuration.ORGANIZATION, "test-org-123")

	// Mock network access
	mockNetworkAccess := mocks.NewMockNetworkAccess(gomock.NewController(t))
	mockNetworkAccess.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()
	fixture.invocationContext.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()

	// Create a context that will timeout before the server responds
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := fixture.binding.enableSnykCodeForOrg(ctx, fixture.invocationContext, "test-org-123")

	// Should fail with a context deadline exceeded error
	require.Error(t, err)
	require.Contains(t, err.Error(), "context deadline exceeded")
}
