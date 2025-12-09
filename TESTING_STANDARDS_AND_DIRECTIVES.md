# Studio MCP Testing Standards and Directives

## Document Purpose
This document provides comprehensive testing standards, patterns, and best practices for the Studio MCP repository. Use this as a reference when generating tests for new code to ensure consistency with existing testing practices.

---

## Key Takeaways (Read This First!)

### Critical Requirements

1. **Test File Location MUST Be Co-located with Source Code**
   - Test files are placed in the same directory as the source code they test
   - Example: `internal/mcp/tools.go` → `internal/mcp/tools_test.go`

2. **Use Table-Driven Tests**
   - This is the primary testing pattern throughout the codebase
   - Every new test should strongly consider table-driven design

3. **Test Both Happy and Error Paths**
   - Every function must have tests for success scenarios AND failure scenarios
   - Include edge cases like nil inputs, empty strings, invalid data

4. **Use Testify for Assertions**
   - Use `require` for fatal assertions that should stop test execution
   - Use `assert` for non-fatal assertions within table-driven tests

5. **Mark Helper Functions Properly**
   - All test helper functions MUST call `t.Helper()` at the start

6. **Use gomock for Interface Mocking**
   - Mocks are generated from interfaces in `go-application-framework/pkg/mocks`
   - Always clean up mocks with `ctrl.Finish()` or use `defer`

### Quick Start for New Tests

```go
func TestFunctionName(t *testing.T) {
    // Use table-driven tests for multiple scenarios
    testCases := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {
            name:     "valid input produces expected output",
            input:    "test",
            expected: "result",
            wantErr:  false,
        },
        {
            name:     "empty input returns error",
            input:    "",
            expected: "",
            wantErr:  true,
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            result, err := FunctionName(tc.input)

            if tc.wantErr {
                require.Error(t, err)
                return
            }
            require.NoError(t, err)
            assert.Equal(t, tc.expected, result)
        })
    }
}
```

---

## Table of Contents
1. [Test File Organization](#test-file-organization)
2. [Testing Frameworks and Tools](#testing-frameworks-and-tools)
3. [Test Types and Naming Conventions](#test-types-and-naming-conventions)
4. [What to Test - Exhaustive Checklist](#what-to-test---exhaustive-checklist)
5. [Test Structure and Patterns](#test-structure-and-patterns)
6. [Assertions and Expectations](#assertions-and-expectations)
7. [Test Fixtures and Helpers](#test-fixtures-and-helpers)
8. [Mocking and Stubbing](#mocking-and-stubbing)
9. [Setup and Teardown](#setup-and-teardown)
10. [HTTP Testing](#http-testing)
11. [OS-Specific Testing](#os-specific-testing)
12. [Environment Variable Testing](#environment-variable-testing)
13. [Error Testing](#error-testing)
14. [Security Testing](#security-testing)
15. [Exemplary Test Files](#exemplary-test-files)

---

## Test File Organization

### File Naming Conventions

- Test files: `*_test.go` (standard Go convention)
- Test files are co-located with source files in the same package
- Test functions: `Test<FunctionName>` or `Test_<functionName>` for unexported functions

### Directory Structure
```
studio-mcp/
├── internal/
│   ├── mcp/
│   │   ├── api.go
│   │   ├── api_test.go           # Tests for api.go
│   │   ├── llm_binding.go
│   │   ├── llm_binding_test.go   # Tests for llm_binding.go
│   │   ├── tools.go
│   │   ├── tools_test.go         # Tests for tools.go
│   │   ├── utils.go
│   │   └── utils_test.go         # Tests for utils.go
│   ├── networking/
│   │   ├── networking.go
│   │   └── networking_test.go
│   └── trust/
│       ├── trust.go
│       └── trust_test.go
└── pkg/
    └── mcp/
        ├── main.go
        └── main_test.go
```

### Test File Location Rule

**Test files MUST be in the same directory as the source file they test.**

```go
// ✅ CORRECT - Test file co-located with source
// Source: internal/mcp/tools.go
// Test:   internal/mcp/tools_test.go

// ❌ INCORRECT - Test file in separate test directory
// Source: internal/mcp/tools.go
// Test:   test/mcp/tools_test.go  // Wrong!
```

---

## Testing Frameworks and Tools

### Primary Frameworks

| Package | Purpose |
|---------|---------|
| `testing` | Standard Go testing package |
| `github.com/stretchr/testify/assert` | Non-fatal assertions |
| `github.com/stretchr/testify/require` | Fatal assertions |
| `github.com/golang/mock/gomock` | Interface mocking |
| `net/http/httptest` | HTTP server mocking |

### Dependencies

```go
import (
    "testing"

    "github.com/golang/mock/gomock"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)
```

### Running Tests

```bash
# Run all tests
make test

# Run all tests with verbose output
go test -v ./...

# Run tests for a specific package
go test ./internal/mcp/...

# Run a specific test
go test -run TestFunctionName ./internal/mcp/

# Run tests with coverage
go test -cover -coverprofile=coverage.out ./...

# Run tests with race detection
go test -race ./...

# Run tests with timeout
go test -timeout=45m ./...
```

---

## Test Types and Naming Conventions

### Test Function Naming

**Pattern**: `Test<ExportedFunctionName>` or `Test_<unexportedFunctionName>`

```go
// Testing exported function
func TestNewMcpLLMBinding(t *testing.T) { ... }

// Testing unexported function
func Test_verifyCommandArgument(t *testing.T) { ... }

// Testing method
func TestMcpLLMBinding_Start(t *testing.T) { ... }
```

### Subtest Naming

Use descriptive names that explain the scenario being tested:

```go
t.Run("valid request with localhost host", func(t *testing.T) { ... })
t.Run("returns error when org ID is missing", func(t *testing.T) { ... })
t.Run("handles shutdown with no SSE server", func(t *testing.T) { ... })
```

---

## What to Test - Exhaustive Checklist

### 1. **Core Functionality**
- ✅ Primary business logic and workflows
- ✅ All exported functions and methods
- ✅ Return values for different input scenarios
- ✅ Side effects (file operations, API calls)
- ✅ State changes and mutations

### 2. **Input Validation**
- ✅ Valid inputs produce expected outputs
- ✅ Invalid inputs are rejected with appropriate errors
- ✅ Boundary conditions (empty strings, nil values, max values)
- ✅ Type validation (correct types accepted, wrong types handled)
- ✅ Required vs optional parameters

### 3. **Error Handling**
- ✅ Expected errors are returned with correct messages
- ✅ Error types are correct
- ✅ Graceful degradation when dependencies fail
- ✅ Context cancellation and timeouts

### 4. **Edge Cases and Boundaries**
- ✅ Empty collections (arrays, maps, strings)
- ✅ Nil and zero values
- ✅ Special characters in strings
- ✅ Path separators on different OS

### 5. **Authentication and Authorization**
- ✅ Valid tokens are accepted
- ✅ Invalid/expired tokens are rejected
- ✅ Missing authentication is handled
- ✅ OAuth vs legacy token flows

### 6. **HTTP/Network Operations**
- ✅ Correct HTTP methods used
- ✅ Request headers are set correctly
- ✅ Response status codes handled
- ✅ Request body validation
- ✅ Timeouts and context cancellation

### 7. **File System Operations**
- ✅ Path validation (absolute vs relative)
- ✅ File existence checks
- ✅ Directory creation
- ✅ Cross-platform path handling

### 8. **Configuration**
- ✅ Default values when config missing
- ✅ Environment variable handling
- ✅ Configuration validation

### 9. **Security**
- ✅ Localhost-only access restrictions
- ✅ Origin header validation
- ✅ Path traversal prevention
- ✅ Input sanitization

---

## Test Structure and Patterns

### Table-Driven Tests (PRIMARY PATTERN)

This is the most common pattern in the codebase. Use it for any function with multiple input/output scenarios:

```go
func TestIsValidHttpRequest(t *testing.T) {
    tests := []struct {
        name     string
        host     string
        origin   string
        expected bool
    }{
        {
            name:     "valid request with localhost host",
            host:     "localhost",
            origin:   "",
            expected: true,
        },
        {
            name:     "valid request with localhost origin",
            host:     "localhost",
            origin:   "http://localhost:3000",
            expected: true,
        },
        {
            name:     "invalid request with external host",
            host:     "example.com",
            origin:   "",
            expected: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            r := &http.Request{
                Header: make(http.Header),
                Host:   tt.host,
            }
            if tt.origin != "" {
                r.Header.Set("Origin", tt.origin)
            }

            result := isValidHttpRequest(r)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

### Subtests with t.Run

Use subtests to group related test cases:

```go
func TestExpandedEnv(t *testing.T) {
    t.Run("sets integration environment variables", func(t *testing.T) {
        // Test implementation
    })

    t.Run("adds legacy auth token when IDE_CONFIG_PATH is set", func(t *testing.T) {
        // Test implementation
    })

    t.Run("adds OAuth bearer token when IDE_CONFIG_PATH is set", func(t *testing.T) {
        // Test implementation
    })
}
```

### OS-Specific Tests

Use runtime.GOOS to handle platform-specific tests:

```go
func Test_folderContains(t *testing.T) {
    tests := []struct {
        name     string
        args     args
        expected bool
        goos     string
    }{
        {
            name:     "subfolder match - linux",
            args:     args{folderPath: "/trusted/folder", path: "/trusted/folder/sub"},
            expected: true,
            goos:     "linux",
        },
        {
            name:     "subfolder match - windows",
            args:     args{folderPath: "C:\\trusted\\folder", path: "C:\\trusted\\folder\\sub"},
            expected: true,
            goos:     "windows",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if tt.goos != "" && tt.goos != runtime.GOOS {
                t.Skipf("Skipping OS-specific test %s on %s (meant for %s)", 
                    tt.name, runtime.GOOS, tt.goos)
            }
            actual := folderContains(tt.args.folderPath, tt.args.path)
            assert.Equal(t, tt.expected, actual)
        })
    }
}
```

---

## Assertions and Expectations

### Testify Assert vs Require

| Function | Use When |
|----------|----------|
| `require.*` | Test should stop if assertion fails (fatal) |
| `assert.*` | Test can continue even if assertion fails (non-fatal) |

```go
// Use require for critical setup/preconditions
ctrl := gomock.NewController(t)
defer ctrl.Finish()

mockEngine := mocks.NewMockEngine(ctrl)
engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

// Use require when test cannot proceed without success
result, err := handler(t.Context(), request)
require.NoError(t, err)
require.NotNil(t, result)

// Use assert for verification that doesn't block subsequent checks
textContent, ok := result.Content[0].(mcp.TextContent)
require.True(t, ok)
assert.Contains(t, textContent.Text, "expected string")
```

### Common Assertions

```go
// Equality
assert.Equal(t, expected, actual)
assert.NotEqual(t, unexpected, actual)

// Nil checks
assert.Nil(t, err)
assert.NotNil(t, result)
require.NoError(t, err)
require.Error(t, err)

// Boolean
assert.True(t, condition)
assert.False(t, condition)

// String
assert.Contains(t, str, substring)
assert.NotContains(t, str, substring)

// Collections
assert.Len(t, slice, expectedLen)
assert.Empty(t, slice)
assert.ElementsMatch(t, expected, actual)

// Error checking
require.Error(t, err)
require.Contains(t, err.Error(), "expected message")

// Panics
assert.Panics(t, func() { panicFunc() })
assert.NotPanics(t, func() { safeFunc() })
```

---

## Test Fixtures and Helpers

### Test Fixture Pattern

Create a fixture struct to hold common test dependencies:

```go
type testFixture struct {
    t                 *testing.T
    mockEngine        *mocks.MockEngine
    binding           *McpLLMBinding
    snykCliPath       string
    invocationContext *mocks.MockInvocationContext
    tools             *SnykMcpTools
}

func setupTestFixture(t *testing.T) *testFixture {
    t.Helper()
    
    engine, engineConfig := SetupEngineMock(t)
    logger := zerolog.New(io.Discard)

    mockctl := gomock.NewController(t)
    storage := mocks.NewMockStorage(mockctl)
    engineConfig.SetStorage(storage)

    invocationCtx := mocks.NewMockInvocationContext(mockctl)
    invocationCtx.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
    invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
    // ... more setup

    return &testFixture{
        t:                 t,
        mockEngine:        engine,
        binding:           binding,
        snykCliPath:       snykCliPath,
        invocationContext: invocationCtx,
        tools:             tools,
    }
}
```

### Helper Function Pattern

All helper functions MUST call `t.Helper()`:

```go
func SetupEngineMock(t *testing.T) (*mocks.MockEngine, configuration.Configuration) {
    t.Helper()  // REQUIRED - marks this as a helper function
    
    ctrl := gomock.NewController(t)
    mockEngine := mocks.NewMockEngine(ctrl)
    engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
    mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
    return mockEngine, engineConfig
}

func createMockSnykCli(t *testing.T, path, output string) {
    t.Helper()  // REQUIRED

    var script string
    if runtime.GOOS == "windows" {
        script = fmt.Sprintf(`@echo off
echo %s
exit /b 0
`, output)
    } else {
        script = fmt.Sprintf(`#!/bin/sh
echo '%s'
exit 0
`, output)
    }

    err := os.WriteFile(path, []byte(script), 0755)
    require.NoError(t, err)
}
```

### Fixture Methods

Add methods to fixtures for common operations:

```go
func (f *testFixture) mockCliOutput(output string) {
    createMockSnykCli(f.t, f.snykCliPath, output)
}
```

---

## Mocking and Stubbing

### Using gomock

```go
func TestSomething(t *testing.T) {
    ctrl := gomock.NewController(t)
    defer ctrl.Finish()

    // Create mock
    mockEngine := mocks.NewMockEngine(ctrl)
    
    // Set expectations
    mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
    mockEngine.EXPECT().InvokeWithConfig(
        localworkflows.WORKFLOWID_WHOAMI, 
        gomock.Any(),
    ).Return(expectedData, nil).AnyTimes()

    // Use mock in test
    result := functionUnderTest(mockEngine)
}
```

### Mock Expectations

```go
// Any number of calls
mock.EXPECT().Method().AnyTimes()

// Exactly N calls
mock.EXPECT().Method().Times(3)

// At least once
mock.EXPECT().Method().MinTimes(1)

// Parameter matching
mock.EXPECT().Method(gomock.Any()).Return(result)
mock.EXPECT().Method(gomock.Eq("specific")).Return(result)

// Return values
mock.EXPECT().Method().Return(value, nil)
mock.EXPECT().Method().Return(nil, errors.New("error"))
```

---

## Setup and Teardown

### Using t.TempDir()

Creates a temporary directory that is automatically cleaned up:

```go
func TestWithTempDir(t *testing.T) {
    tmpDir := t.TempDir()  // Automatically cleaned up after test
    
    filePath := filepath.Join(tmpDir, "test.txt")
    err := os.WriteFile(filePath, []byte("test"), 0644)
    require.NoError(t, err)
}
```

### Using t.Cleanup()

Register cleanup functions to run after the test:

```go
func TestWithCleanup(t *testing.T) {
    server := httptest.NewServer(handler)
    t.Cleanup(server.Close)  // Will be called after test completes
    
    // Use server in test
}
```

### Using t.Setenv()

Set environment variables that are automatically restored:

```go
func TestWithEnvVar(t *testing.T) {
    t.Setenv("IDE_CONFIG_PATH", "/some/path")
    t.Setenv("SNYK_TOKEN", "test-token")
    
    // Environment variables are automatically restored after test
}
```

### Using t.Context()

Get a context that is cancelled when the test completes:

```go
func TestWithContext(t *testing.T) {
    ctx := t.Context()  // Cancelled when test ends
    
    result, err := functionWithContext(ctx, args)
    require.NoError(t, err)
}
```

---

## HTTP Testing

### Mock HTTP Server

```go
func createMockAPIServer(t *testing.T, statusCode int, response map[string]interface{}) string {
    t.Helper()
    
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/vnd.api+json")
        w.WriteHeader(statusCode)
        if response != nil {
            _ = json.NewEncoder(w).Encode(response)
        }
    }))
    t.Cleanup(server.Close)
    return server.URL
}
```

### Testing HTTP Handlers

```go
func TestMiddleware(t *testing.T) {
    t.Run("allows valid localhost requests", func(t *testing.T) {
        mcpServer := server.NewMCPServer("test", "1.0.0")
        sseServer := server.NewSSEServer(mcpServer)
        handler := middleware(sseServer)

        req := httptest.NewRequest(http.MethodGet, "/", nil)
        req.Host = "localhost"
        req.Header.Set("Origin", "http://localhost:3000")

        rr := httptest.NewRecorder()
        handler.ServeHTTP(rr, req)

        assert.NotEqual(t, http.StatusForbidden, rr.Code)
    })

    t.Run("blocks invalid external requests", func(t *testing.T) {
        // Similar setup...
        assert.Equal(t, http.StatusForbidden, rr.Code)
        assert.Contains(t, rr.Body.String(), "Forbidden")
    })
}
```

### Testing API Endpoints

```go
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
                },
            },
            expectError: false,
        },
        {
            name:           "API Returns 403 Forbidden",
            orgId:          "test-org-123",
            apiToken:       "test-token",
            mockStatusCode: http.StatusForbidden,
            expectError:    true,
            errorContains:  "API request failed with status 403",
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                require.Equal(t, "PATCH", r.Method)
                w.WriteHeader(tc.mockStatusCode)
                if tc.mockResponse != nil {
                    _ = json.NewEncoder(w).Encode(tc.mockResponse)
                }
            }))
            defer mockServer.Close()

            // Test implementation...
        })
    }
}
```

---

## OS-Specific Testing

### Skipping Tests Based on OS

```go
func Test_verifyCommandArgument(t *testing.T) {
    testCases := []struct {
        name     string
        input    any
        expected bool
        goos     string  // Optional: specify target OS
    }{
        {
            name:     "Windows path to python",
            input:    "C:\\Python310\\python.exe",
            expected: true,
            goos:     "windows",  // Only run on Windows
        },
        {
            name:     "Unix path to python",
            input:    "/usr/bin/python3",
            expected: true,
            goos:     "linux",  // Only run on Linux
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            if tc.goos != "" && tc.goos != runtime.GOOS {
                t.Skip("test only for " + tc.goos)
            }
            actual := verifyCommandArgument(tc.input)
            assert.Equal(t, tc.expected, actual)
        })
    }
}
```

### Cross-Platform Path Handling

```go
func PathSafeTestName(t *testing.T) string {
    t.Helper()
    replacer := strings.NewReplacer(
        "/", "__",
        "\\", "__",
        ":", "_",
        "*", "_",
        "?", "_",
        "\"", "_",
        "<", "_",
        ">", "_",
        "|", "_",
    )
    return replacer.Replace(t.Name())
}
```

---

## Environment Variable Testing

### Using t.Setenv()

```go
func TestExpandedEnv(t *testing.T) {
    t.Run("sets integration environment variables", func(t *testing.T) {
        t.Setenv(strings.ToUpper(configuration.INTEGRATION_NAME), "abc")
        t.Setenv(strings.ToUpper(configuration.INTEGRATION_VERSION), "abc")

        // Test implementation - env vars are automatically restored
    })

    t.Run("adds legacy auth token when IDE_CONFIG_PATH is set", func(t *testing.T) {
        tempDir := t.TempDir()
        t.Setenv("IDE_CONFIG_PATH", tempDir)

        // Test implementation
    })
}
```

---

## Error Testing

### Testing Error Conditions

```go
func TestSnykTrustHandler(t *testing.T) {
    fixture := setupTestFixture(t)
    handler := fixture.binding.snykTrustHandler(fixture.invocationContext, *toolDef)

    t.Run("PathMissing", func(t *testing.T) {
        request := mcp.CallToolRequest{
            Params: mcp.CallToolParams{
                Arguments: map[string]interface{}{},
            },
        }

        result, err := handler(t.Context(), request)

        require.Error(t, err)
        require.Nil(t, result)
        require.Contains(t, err.Error(), "argument 'path' is missing")
    })

    t.Run("PathEmpty", func(t *testing.T) {
        request := mcp.CallToolRequest{
            Params: mcp.CallToolParams{
                Arguments: map[string]interface{}{"path": ""},
            },
        }

        result, err := handler(t.Context(), request)

        require.Error(t, err)
        require.Nil(t, result)
        require.Contains(t, err.Error(), "empty path given")
    })
}
```

### Testing Timeouts

```go
func TestEnableSnykCodeForOrg_Timeout(t *testing.T) {
    mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        time.Sleep(2 * time.Second)  // Simulate slow response
        w.WriteHeader(http.StatusCreated)
    }))
    defer mockServer.Close()

    // Create a context that will timeout before the server responds
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
    defer cancel()

    err := binding.enableSnykCodeForOrg(ctx, invocationCtx, "test-org")

    require.Error(t, err)
    require.Contains(t, err.Error(), "context deadline exceeded")
}
```

### Testing Panics

```go
func TestStart(t *testing.T) {
    t.Run("panics with nil invocation context", func(t *testing.T) {
        binding := NewMcpLLMBinding()

        assert.Panics(t, func() {
            _ = binding.Start(nil)
        })
    })
}
```

---

## Security Testing

### Testing Localhost Restrictions

```go
func TestIsValidHttpRequest(t *testing.T) {
    tests := []struct {
        name     string
        host     string
        origin   string
        expected bool
    }{
        {
            name:     "valid request with localhost host",
            host:     "localhost",
            origin:   "",
            expected: true,
        },
        {
            name:     "invalid request with external host",
            host:     "example.com",
            origin:   "",
            expected: false,
        },
        {
            name:     "invalid request with disallowed origin",
            host:     "localhost",
            origin:   "http://example.com",
            expected: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            r := &http.Request{
                Header: make(http.Header),
                Host:   tt.host,
            }
            if tt.origin != "" {
                r.Header.Set("Origin", tt.origin)
            }

            result := isValidHttpRequest(r)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

---

## Exemplary Test Files

### Best Examples in This Repository

#### 1. `internal/mcp/llm_binding_test.go`
**Why it's exemplary:**
- Demonstrates proper use of t.Run() for subtests
- Shows t.Setenv() for environment variable testing
- Uses gomock for interface mocking
- Tests both success and error paths
- Clean setup with helper functions

#### 2. `internal/mcp/tools_test.go`
**Why it's exemplary:**
- Comprehensive fixture pattern with `setupTestFixture()`
- Table-driven tests with clear test case structs
- Mock CLI creation for testing CLI interactions
- Tests complex handler functions
- Good use of t.TempDir() for file system testing

#### 3. `internal/mcp/api_test.go`
**Why it's exemplary:**
- HTTP testing with httptest.NewServer
- Testing different HTTP status codes
- Request/response validation
- Timeout testing with context.WithTimeout
- Clean mock server setup

#### 4. `internal/trust/trust_test.go`
**Why it's exemplary:**
- OS-specific testing with runtime.GOOS checks
- Comprehensive path testing (absolute, relative, trailing slashes)
- Case-sensitivity testing for different platforms
- Clear test case naming

#### 5. `internal/networking/networking_test.go`
**Why it's exemplary:**
- Testing network operations
- Proper cleanup with defer
- Testing port availability
- Edge case testing

---

## Summary of Key Principles

### 1. **Test Naming**
- Use descriptive names that explain what is being tested
- Include expected behavior in test name
- Use `Test_<functionName>` for unexported functions

### 2. **Test Organization**
- One test file per source file, co-located
- Use t.Run() for subtests
- Group related tests with table-driven pattern

### 3. **Test Independence**
- Each test should be runnable in isolation
- Don't depend on test execution order
- Use t.TempDir() and t.Setenv() for automatic cleanup

### 4. **Fixtures and Helpers**
- Create fixture structs for common test setup
- Mark all helpers with t.Helper()
- Reuse setup code across tests

### 5. **Mocking**
- Use gomock for interface mocking
- Always call ctrl.Finish() or use defer
- Set clear expectations with EXPECT()

### 6. **Assertions**
- Use require.* for fatal checks
- Use assert.* for non-fatal checks
- Include meaningful error messages

### 7. **Error Testing**
- Test both success and error paths
- Verify error messages contain expected text
- Test timeout and cancellation handling

### 8. **Platform Testing**
- Use runtime.GOOS checks for OS-specific tests
- Use t.Skip() to skip inapplicable tests
- Test path handling on different platforms

---

## Quick Reference Checklist

### When Writing a New Test

- [ ] Named the test file `*_test.go` in the same directory as source
- [ ] Named test function `Test<FunctionName>` or `Test_<functionName>`
- [ ] Used table-driven tests for multiple scenarios
- [ ] Used `t.Helper()` in all helper functions
- [ ] Used `require` for fatal assertions, `assert` for non-fatal
- [ ] Tested the happy path
- [ ] Tested error conditions
- [ ] Tested edge cases (nil, empty, boundaries)
- [ ] Used `t.TempDir()` for temporary file operations
- [ ] Used `t.Setenv()` for environment variables
- [ ] Used `t.Cleanup()` for cleanup operations
- [ ] Used `t.Context()` for context-aware functions
- [ ] Skipped OS-specific tests with `runtime.GOOS` check
- [ ] Used `gomock` for interface mocking

### Before Submitting PR

- [ ] All tests pass: `make test`
- [ ] New functionality has corresponding tests
- [ ] Both success and failure paths are tested
- [ ] Edge cases are covered
- [ ] Tests are deterministic (no flaky tests)
- [ ] No hardcoded paths that differ across systems
- [ ] Mocks are properly cleaned up

---

## Conclusion

This document provides a comprehensive guide to testing standards for the Studio MCP repository. Follow these patterns and practices to write high-quality, maintainable tests that ensure code reliability.

**Remember:** Good tests are as important as good code. When in doubt, look at existing tests in `internal/mcp/tools_test.go` for guidance on patterns and conventions.

