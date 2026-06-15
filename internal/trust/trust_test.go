package trust

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_folderContains(t *testing.T) {
	type args struct {
		folderPath string
		path       string
	}
	tests := []struct {
		name     string
		args     args
		expected bool
		goos     string
	}{
		{
			name:     "exact match",
			args:     args{folderPath: "/trusted/folder", path: "/trusted/folder"},
			expected: true,
			goos:     "linux",
		},
		{
			name:     "subfolder match",
			args:     args{folderPath: "/trusted/folder", path: "/trusted/folder/sub"},
			expected: true,
			goos:     "linux",
		},
		{
			name:     "subfolder with file match",
			args:     args{folderPath: "/trusted/folder", path: "/trusted/folder/sub/file.txt"},
			expected: true,
			goos:     "linux",
		},
		{
			name:     "folderPath with trailing slash",
			args:     args{folderPath: "/trusted/folder/", path: "/trusted/folder/sub/file.txt"},
			expected: true,
			goos:     "linux",
		},

		{
			name:     "exact match - windows",
			args:     args{folderPath: "C:\\trusted\\folder", path: "C:\\trusted\\folder"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "subfolder match - windows",
			args:     args{folderPath: "C:\\trusted\\folder", path: "C:\\trusted\\folder\\sub"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "subfolder with file match - windows",
			args:     args{folderPath: "C:\\trusted\\folder", path: "C:\\trusted\\folder\\sub\\file.txt"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "folderPath with trailing slash - windows",
			args:     args{folderPath: "C:\\trusted\\folder\\", path: "C:\\trusted\\folder\\sub\\file.txt"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "windows case-insensitive match - windows",
			args:     args{folderPath: "C:\\Trusted\\Folder", path: "c:\\trusted\\folder\\sub\\file.txt"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "windows case-insensitive exact match - windows",
			args:     args{folderPath: "C:\\Trusted\\Folder", path: "c:\\trusted\\folder"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "windows case-insensitive, folderPath with trailing slash - windows",
			args:     args{folderPath: "C:\\Trusted\\Folder\\", path: "c:\\trusted\\folder\\sub\\file.txt"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "windows case-insensitive, path with trailing slash - windows",
			args:     args{folderPath: "C:\\Trusted\\Folder", path: "c:\\trusted\\folder\\sub\\"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "root path as trusted folder - windows",
			args:     args{folderPath: "C:\\", path: "C:\\some\\subfolder"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "relative paths - exact match - windows",
			args:     args{folderPath: "trusted\\folder", path: "trusted\\folder"},
			expected: true,
			goos:     "windows",
		},
		{
			name:     "path with trailing slash",
			args:     args{folderPath: "/trusted/folder", path: "/trusted/folder/sub/"},
			expected: true,
			goos:     "linux",
		},
		{
			name:     "no match - different folder",
			args:     args{folderPath: "/trusted/folder", path: "/untrusted/folder/sub"},
			expected: false,
			goos:     "linux",
		},
		{
			name:     "no match - path is parent of folderPath",
			args:     args{folderPath: "/trusted/folder/sub", path: "/trusted/folder"},
			expected: false,
			goos:     "linux",
		},
		{
			name:     "no match - partial name overlap",
			args:     args{folderPath: "/trusted/fold", path: "/trusted/folder/sub"},
			expected: false,
			goos:     "linux",
		},
		{
			name:     "linux case-sensitive no match",
			args:     args{folderPath: "/Trusted/Folder", path: "/trusted/folder/sub"},
			expected: false,
			goos:     "linux",
		},
		{
			name:     "linux case-sensitive match",
			args:     args{folderPath: "/trusted/folder", path: "/trusted/folder/sub"},
			expected: true,
			goos:     "linux", // or any other non-windows OS
		},
		{
			name:     "relative paths - subfolder match",
			args:     args{folderPath: "trusted/folder", path: "trusted/folder/sub/file.txt"},
			expected: true,
			goos:     "linux",
		},
		{
			name:     "relative paths - exact match",
			args:     args{folderPath: "trusted/folder", path: "trusted/folder"},
			expected: true,
			goos:     "linux",
		},
		{
			name:     "root path as trusted folder",
			args:     args{folderPath: "/", path: "/some/subfolder"},
			expected: true,
			goos:     "linux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.goos != "" && tt.goos != runtime.GOOS {
				t.Skipf("Skipping OS-specific test %s on %s (meant for %s)", tt.name, runtime.GOOS, tt.goos)
			}
			actual := folderContains(tt.args.folderPath, tt.args.path)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestFolderTrust_AddTrustedFolder_Direct(t *testing.T) {
	logger := zerolog.Nop()
	config := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
	)
	tests := []struct {
		name                string
		initialTrustedPaths []string
		pathToAdd           string
		expectedFinalPaths  []string
		goos                string
	}{
		{
			name:                "add to empty list",
			initialTrustedPaths: []string{},
			pathToAdd:           "/my/folder",
			expectedFinalPaths:  []string{"/my/folder"},
			goos:                "linux",
		},
		{
			name:                "add to existing list",
			initialTrustedPaths: []string{"/another/folder"},
			pathToAdd:           "/my/folder",
			expectedFinalPaths:  []string{"/another/folder", "/my/folder"},
			goos:                "linux",
		},
		{
			name:                "add duplicate path",
			initialTrustedPaths: []string{"/my/folder"},
			pathToAdd:           "/my/folder",
			expectedFinalPaths:  []string{"/my/folder"},
			goos:                "linux",
		},
		{
			name:                "add to empty list",
			initialTrustedPaths: []string{},
			pathToAdd:           "C:\\my\\folder",
			expectedFinalPaths:  []string{"C:\\my\\folder"},
			goos:                "windows",
		},
		{
			name:                "add to existing list",
			initialTrustedPaths: []string{"C:\\another\\folder"},
			pathToAdd:           "C:\\my\\folder",
			expectedFinalPaths:  []string{"C:\\another\\folder", "C:\\my\\folder"},
			goos:                "windows",
		},
		{
			name:                "add duplicate path",
			initialTrustedPaths: []string{"C:\\my\\folder"},
			pathToAdd:           "C:\\my\\folder",
			expectedFinalPaths:  []string{"C:\\my\\folder"},
			goos:                "windows",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.goos != "" && tt.goos != runtime.GOOS {
				t.Skipf("Skipping OS-specific test %s on %s (meant for %s)", tt.name, runtime.GOOS, tt.goos)
			}
			if tt.initialTrustedPaths != nil {
				config.Set(TrustedFoldersConfigKey, tt.initialTrustedPaths)
			}
			folderTrust := NewFolderTrust(&logger, config)

			folderTrust.AddTrustedFolder(tt.pathToAdd)

			actualFinalPaths := config.GetStringSlice(TrustedFoldersConfigKey)
			assert.ElementsMatch(t, tt.expectedFinalPaths, actualFinalPaths, "The final list of trusted paths did not match the expected list.")
		})
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce1, err := generateNonce()
	require.NoError(t, err)
	assert.Len(t, nonce1, 64)

	nonce2, err := generateNonce()
	require.NoError(t, err)
	assert.NotEqual(t, nonce1, nonce2)
}

func newTestHandlers(t *testing.T, nonce string) (*http.ServeMux, chan *mcp.CallToolResult, chan error) {
	t.Helper()
	logger := zerolog.Nop()
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	ft := NewFolderTrust(&logger, config)
	tmpl, err := template.New("trustPage").Parse(SnykTrustPage)
	require.NoError(t, err)

	resultChan := make(chan *mcp.CallToolResult, 1)
	errorChan := make(chan error, 1)
	mux := http.NewServeMux()
	ft.addHttpHandlers(logger, mux, "/test/folder", nonce, tmpl, resultChan, errorChan)
	return mux, resultChan, errorChan
}

func TestAddHttpHandlers_NonceValidation(t *testing.T) {
	nonce := "abc123def456"

	tests := []struct {
		name           string
		path           string
		nonceHeader    string
		expectedStatus int
	}{
		{
			name:           "valid nonce on /trust",
			path:           "/trust",
			nonceHeader:    nonce,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "wrong nonce on /trust",
			path:           "/trust",
			nonceHeader:    "wrong-nonce",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "missing nonce on /trust",
			path:           "/trust",
			nonceHeader:    "",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "valid nonce on /cancel",
			path:           "/cancel",
			nonceHeader:    nonce,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "wrong nonce on /cancel",
			path:           "/cancel",
			nonceHeader:    "wrong-nonce",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux, _, _ := newTestHandlers(t, nonce)

			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			req.Host = "127.0.0.1"
			if tt.nonceHeader != "" {
				req.Header.Set("X-Trust-Nonce", tt.nonceHeader)
			}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func TestAddHttpHandlers_OriginValidation(t *testing.T) {
	nonce := "test-nonce-value"

	tests := []struct {
		name           string
		host           string
		origin         string
		expectedStatus int
	}{
		{
			name:           "loopback origin allowed",
			host:           "127.0.0.1",
			origin:         "http://127.0.0.1:54321",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "no origin allowed",
			host:           "127.0.0.1",
			origin:         "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "external origin rejected",
			host:           "127.0.0.1",
			origin:         "http://evil.com",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "external host rejected",
			host:           "evil.com",
			origin:         "",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux, _, _ := newTestHandlers(t, nonce)

			req := httptest.NewRequest(http.MethodPost, "/trust", nil)
			req.Host = tt.host
			req.Header.Set("X-Trust-Nonce", nonce)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func TestNewFolderTrust_LogsEnvSeededFolders(t *testing.T) {
	t.Setenv("TRUSTED_FOLDERS", "/foo;/bar")

	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())

	_ = NewFolderTrust(&logger, config)

	output := buf.String()
	assert.Contains(t, output, "/foo")
	assert.Contains(t, output, "/bar")
	assert.Contains(t, output, "auto-trusted")
}
