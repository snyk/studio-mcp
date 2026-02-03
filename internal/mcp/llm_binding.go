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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/studio-mcp/internal/logging"
	"github.com/snyk/studio-mcp/internal/networking"
	"github.com/snyk/studio-mcp/internal/trust"
	"github.com/snyk/studio-mcp/internal/types"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	TransportParam     string = "transport"
	SseTransportType   string = "sse"
	StdioTransportType string = "stdio"
	OutputDirParam     string = "output-dir"
)

// McpLLMBinding is an implementation of a mcp server that allows interaction between
// a given SnykLLMBinding and a CommandService.
type McpLLMBinding struct {
	logger          *zerolog.Logger
	mcpServer       *mcp.Server
	sseHandler      *mcp.SSEHandler
	folderTrust     *trust.FolderTrust
	baseURL         *url.URL
	mutex           sync.RWMutex
	started         bool
	cliPath         string
	openBrowserFunc types.OpenBrowserFunc
}

func NewMcpLLMBinding(opts ...Option) *McpLLMBinding {
	logger := zerolog.Nop()
	mcpServerImpl := &McpLLMBinding{
		logger:          &logger,
		openBrowserFunc: types.DefaultOpenBrowserFunc,
	}

	for _, opt := range opts {
		opt(mcpServerImpl)
	}

	return mcpServerImpl
}

// Start starts the MCP server. It blocks until the server is stopped via Shutdown.
func (m *McpLLMBinding) Start(invocationContext workflow.InvocationContext) error {
	runTimeInfo := invocationContext.GetRuntimeInfo()
	version := ""
	if runTimeInfo != nil {
		version = runTimeInfo.GetVersion()
	}

	// Create server options
	serverOpts := &mcp.ServerOptions{
		Logger: logging.NewSlogLogger(),
	}

	m.mcpServer = mcp.NewServer(
		&mcp.Implementation{
			Name:    "Snyk MCP Server",
			Version: version,
		},
		serverOpts,
	)

	m.logger = logging.ConfigureLogging(m.mcpServer)
	invocationContext.GetEngine().SetLogger(m.logger)

	m.folderTrust = trust.NewFolderTrust(m.logger, invocationContext.GetConfiguration())

	profileStr := invocationContext.GetConfiguration().GetString(ProfileFlagName)
	profile, err := GetProfile(profileStr)
	if err != nil {
		m.logger.Warn().Err(err).Str("profile", profileStr).Msg("Invalid profile specified, using default")
		profile = DefaultProfile
	}

	err = m.addSnykTools(invocationContext, profile)
	if err != nil {
		return err
	}

	transportType := invocationContext.GetConfiguration().GetString("transport")
	switch transportType {
	case StdioTransportType:
		return m.HandleStdioServer()
	case SseTransportType:
		return m.HandleSseServer()
	default:
		return fmt.Errorf("invalid transport type: %s", transportType)
	}
}

func (m *McpLLMBinding) HandleStdioServer() error {
	m.mutex.Lock()
	m.started = true
	m.mutex.Unlock()
	m.logger.Info().Msg("Starting MCP Stdio server")

	// Use the official SDK's StdioTransport
	err := m.mcpServer.Run(context.Background(), &mcp.StdioTransport{})

	if err != nil {
		m.logger.Error().Err(err).Msg("Error starting MCP Stdio server")
		return err
	}

	return nil
}

func (m *McpLLMBinding) HandleSseServer() error {
	// listen on default url/port if none was configured
	if m.baseURL == nil {
		defaultUrl, err := networking.LoopbackURL()
		if err != nil {
			return err
		}
		m.baseURL = defaultUrl
	}

	// Create SSE handler using the official SDK
	m.sseHandler = mcp.NewSSEHandler(func(request *http.Request) *mcp.Server {
		return m.mcpServer
	}, nil)

	endpoint := m.baseURL.String() + "/sse"

	m.logger.Info().Str("baseURL", endpoint).Msg("starting")
	go func() {
		// sleep initially for a few milliseconds so we actually can start the server
		time.Sleep(100 * time.Millisecond)
		for !networking.IsPortInUse(m.baseURL) {
			time.Sleep(10 * time.Millisecond)
		}

		m.mutex.Lock()
		m.logger.Info().Str("baseURL", endpoint).Msg("started")
		m.started = true
		m.mutex.Unlock()
	}()

	srv := &http.Server{
		Addr:    m.baseURL.Host,
		Handler: middleware(m.sseHandler),
	}

	err := srv.ListenAndServe()

	if err != nil {
		// expect http.ErrServerClosed when shutting down
		if !errors.Is(err, http.ErrServerClosed) {
			m.logger.Error().Err(err).Msg("Error starting MCP SSE server")
		}
		return err
	}
	return nil
}

var allowedHostnames = map[string]bool{
	"localhost": true,
	"127.0.0.1": true,
	"::1":       true,
	"":          true,
}

func middleware(sseHandler *mcp.SSEHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isValidHttpRequest(r) {
			sseHandler.ServeHTTP(w, r)
		} else {
			http.Error(w, "Forbidden: Access restricted to localhost origins", http.StatusForbidden)
		}
	})
}

func isValidHttpRequest(r *http.Request) bool {
	originHeader := r.Header.Get("Origin")
	isValidOrigin := originHeader == ""
	hostHeader := r.Host
	host, _, err := net.SplitHostPort(hostHeader)
	if err != nil {
		// Try to parse without port
		host = hostHeader
	}
	isValidHost := allowedHostnames[host]

	if !isValidOrigin {
		parsedOrigin, err := url.Parse(originHeader)
		if err == nil {
			requestHost := parsedOrigin.Hostname()
			if _, allowed := allowedHostnames[requestHost]; allowed {
				isValidOrigin = true
			}
		}
	}

	return isValidOrigin && isValidHost
}

func (m *McpLLMBinding) Shutdown(ctx context.Context) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// The official SDK doesn't have a direct shutdown method for SSE
	// The server will stop when connections are closed
	m.started = false
}

func (m *McpLLMBinding) Started() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.started
}

// getClientInfo retrieves client info from the current session
func (m *McpLLMBinding) getClientInfo(_ context.Context) ClientInfo {
	// The official SDK manages sessions internally
	// We iterate through sessions to find client info
	var clientInfo ClientInfo
	for ss := range m.mcpServer.Sessions() {
		info := ClientInfoFromSession(ss)
		if info.Name != "" {
			clientInfo = info
			break
		}
	}
	return clientInfo
}

func (m *McpLLMBinding) updateGafConfigWithIntegrationEnvironment(invocationCtx workflow.InvocationContext, environmentName, environmentVersion string) {
	getConfiguration := invocationCtx.GetEngine().GetConfiguration()
	getConfiguration.Set(configuration.INTEGRATION_NAME, "MCP")

	integrationVersion := "unknown"
	runtimeInfo := invocationCtx.GetRuntimeInfo()
	if runtimeInfo != nil {
		integrationVersion = runtimeInfo.GetVersion()
	}
	getConfiguration.Set(configuration.INTEGRATION_VERSION, integrationVersion)
	getConfiguration.Set(configuration.INTEGRATION_ENVIRONMENT, environmentName)
	getConfiguration.Set(configuration.INTEGRATION_ENVIRONMENT_VERSION, environmentVersion)
}

func (m *McpLLMBinding) expandedEnv(invocationCtx workflow.InvocationContext, integrationVersion, environmentName, environmentVersion string) []string {
	environ := os.Environ()
	var expandedEnv = []string{}
	for _, v := range environ {
		if strings.HasPrefix(strings.ToLower(v), strings.ToLower(configuration.INTEGRATION_NAME)) {
			continue
		}
		if strings.HasPrefix(strings.ToLower(v), strings.ToLower(configuration.INTEGRATION_VERSION)) {
			continue
		}
		expandedEnv = append(expandedEnv, v)
	}
	expandedEnv = append(expandedEnv, fmt.Sprintf("%s=%s", strings.ToUpper(configuration.INTEGRATION_NAME), "MCP"))

	expandedEnv = append(expandedEnv, fmt.Sprintf("%s=%s", strings.ToUpper(configuration.INTEGRATION_VERSION), integrationVersion))
	expandedEnv = append(expandedEnv, fmt.Sprintf("%s=%s", strings.ToUpper(configuration.INTEGRATION_ENVIRONMENT), environmentName))
	expandedEnv = append(expandedEnv, fmt.Sprintf("%s=%s", strings.ToUpper(configuration.INTEGRATION_ENVIRONMENT_VERSION), environmentVersion))

	if os.Getenv("IDE_CONFIG_PATH") != "" {
		expandedEnv = m.addAuthEnvVars(invocationCtx, expandedEnv)
	}

	return expandedEnv
}

func getParsedOAuthToken(tokenStr string) (*oauth2.Token, error) {
	var oauthToken oauth2.Token
	err := json.Unmarshal([]byte(tokenStr), &oauthToken)
	if err != nil {
		return nil, err
	}
	return &oauthToken, nil
}

func (m *McpLLMBinding) addAuthEnvVars(invocationCtx workflow.InvocationContext, expandedEnv []string) []string {
	globalConfig := invocationCtx.GetEngine().GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()

	storage := globalConfig.GetStorage()
	err := storage.Refresh(globalConfig, auth.CONFIG_KEY_OAUTH_TOKEN)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to refresh oauth token for global config")
	}
	err = storage.Refresh(globalConfig, configuration.AUTHENTICATION_TOKEN)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to refresh authentication token for global config")
	}

	snykToken := globalConfig.GetString(configuration.AUTHENTICATION_TOKEN)
	oAuthToken := globalConfig.GetString(auth.CONFIG_KEY_OAUTH_TOKEN)
	expandedEnv = slices.DeleteFunc(expandedEnv, func(s string) bool {
		return strings.HasPrefix(strings.ToLower(s), strings.ToLower(configuration.AUTHENTICATION_TOKEN)) || strings.HasPrefix(strings.ToLower(s), strings.ToLower(configuration.AUTHENTICATION_BEARER_TOKEN))
	})

	_, legacyTokenParseErr := uuid.Parse(snykToken)
	isPat := strings.HasPrefix(snykToken, "snyk_uat") || strings.HasPrefix(snykToken, "snyk_sat")
	parsedOAuthToken, oAuthTokenParseErr := getParsedOAuthToken(oAuthToken)
	if oAuthTokenParseErr == nil {
		expandedEnv = append(expandedEnv, fmt.Sprintf("%s=%s", strings.ToUpper(configuration.AUTHENTICATION_BEARER_TOKEN), parsedOAuthToken.AccessToken))
		expandedEnv = append(expandedEnv, fmt.Sprintf("%s=%s", strings.ToUpper(configuration.FF_OAUTH_AUTH_FLOW_ENABLED), "1"))
	} else if legacyTokenParseErr == nil || isPat {
		expandedEnv = append(expandedEnv, fmt.Sprintf("%s=%s", strings.ToUpper(configuration.AUTHENTICATION_TOKEN), snykToken))
		expandedEnv = append(expandedEnv, fmt.Sprintf("%s=%s", strings.ToUpper(configuration.FF_OAUTH_AUTH_FLOW_ENABLED), "0"))
	}

	return expandedEnv
}
