# MCP SDK Migration Notes

## Overview

This document describes the migration from `github.com/mark3labs/mcp-go v0.31.0` to the official `github.com/modelcontextprotocol/go-sdk v1.2.0`.

## Breaking Changes and API Differences

### Import Changes

All imports have been updated from:
```go
import (
    "github.com/mark3labs/mcp-go/mcp"
    "github.com/mark3labs/mcp-go/server"
)
```

To:
```go
import (
    "github.com/modelcontextprotocol/go-sdk/mcp"
)
```

### Server Creation

**Old API:**
```go
mcpServer := server.NewMCPServer("name", "version", opts...)
```

**New API:**
```go
mcpServer := mcp.NewServer(
    &mcp.Implementation{Name: "name", Version: "version"},
    &mcp.ServerOptions{
        Logger: slog.Logger,
        // ... other options
    },
)
```

### Server Options

**Old API:**
```go
server.WithLogging()
server.WithResourceCapabilities(true, true)
server.WithPromptCapabilities(true)
```

**New API:**
```go
&mcp.ServerOptions{
    Logger: NewSlogLogger(),
    // Capabilities are now detected automatically based on registered tools/resources
}
```

### Transport (Stdio)

**Old API:**
```go
err := server.ServeStdio(mcpServer)
```

**New API:**
```go
err := mcpServer.Run(ctx, &mcp.StdioTransport{})
```

### Transport (SSE)

**Old API:**
```go
sseServer := server.NewSSEServer(mcpServer, server.WithBaseURL(...))
```

**New API:**
```go
sseHandler := mcp.NewSSEHandler(func(request *http.Request) *mcp.Server {
    return mcpServer
}, &mcp.SSEOptions{})
```

### Tool Handler Signatures

**Old API:**
```go
func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)
```

**New API:**
```go
func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error)
```
Note: The request is now a pointer.

### Tool Argument Extraction

**Old API:**
```go
args := request.GetArguments() // returns map[string]any
```

**New API:**
```go
func getRequestArguments(req *mcp.CallToolRequest) map[string]any {
    if req.Params.Arguments == nil {
        return make(map[string]any)
    }
    var args map[string]any
    json.Unmarshal(req.Params.Arguments, &args)
    return args
}
```

### Tool Definition

**Old API:**
```go
tool := mcp.NewTool(name, 
    mcp.WithDescription(...),
    mcp.WithString(...),
    mcp.WithBoolean(...),
)
```

**New API:**
```go
tool := &mcp.Tool{
    Name:        name,
    Description: description,
    InputSchema: map[string]any{
        "type":       "object",
        "properties": properties,
        "required":   required,
    },
}
```

### Tool Results

**Old API:**
```go
return mcp.NewToolResultText(text), nil
```

**New API:**
```go
func NewToolResultText(text string) *mcp.CallToolResult {
    return &mcp.CallToolResult{
        Content: []mcp.Content{
            &mcp.TextContent{Text: text},
        },
    }
}
```

### Client Info Extraction

**Old API:**
```go
session := server.ClientSessionFromContext(ctx)
sessionWithClientInfo := session.(server.SessionWithClientInfo)
clientInfo := sessionWithClientInfo.GetClientInfo()
```

**New API:**
```go
for ss := range m.mcpServer.Sessions() {
    initParams := ss.InitializeParams()
    if initParams != nil && initParams.ClientInfo != nil {
        return ClientInfo{
            Name:    initParams.ClientInfo.Name,
            Version: initParams.ClientInfo.Version,
        }
    }
}
```

### Logging Notifications

**Old API:**
```go
server.SendNotificationToAllClients(method, params)
```

**New API:**
```go
for ss := range server.Sessions() {
    ss.Log(ctx, &mcp.LoggingMessageParams{
        Level:  level,
        Logger: logger,
        Data:   message,
    })
}
```

## Files Modified

- `go.mod` - Updated dependency
- `internal/mcp/llm_binding.go` - Server creation and transport handling
- `internal/mcp/tools.go` - Tool handlers and argument extraction
- `internal/mcp/utils.go` - Helper functions for tools and client info
- `internal/logging/logger.go` - Session-based logging
- `internal/trust/trust.go` - Tool result creation
- `pkg/mcp/main.go` - Entry point updates

## Test Files Modified

- `internal/mcp/tools_test.go` - Updated for new handler signatures
- `internal/mcp/llm_binding_test.go` - Updated for new SDK types
- `internal/mcp/mcp_spec_conformance_test.go` - Restructured for new SDK
- `internal/mcp/integration_test.go` - New integration tests

## New Features Available in v1.2.0

- Improved error codes (`jsonrpc.Error` sentinels)
- Better streamable transport handling
- OAuth 2.0 Protected Resource Metadata
- `Capabilities` field in `ServerOptions`
- Debounced server change notifications
- Windows CRLF handling fixes

## Testing Notes

- Run tests with `-race` flag to check for race conditions
- Some tests require network access for httptest servers
- SSE handler tests need special handling due to persistent connections
