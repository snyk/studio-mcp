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

package networking

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_isPortInUse(t *testing.T) {
	// Create a listener on a port to simulate it being in use.
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", 0))
	require.NoError(t, err)
	defer func() {
		_ = listener.Close() // we don't care if this fails, it is just a catch-all
	}()

	u, err := url.Parse(fmt.Sprintf("http://%s", listener.Addr()))
	require.NoError(t, err)
	inUse := IsPortInUse(u)
	assert.True(t, inUse, "should be in listening on: %s", listener.Addr())

	// close listener, to have IsPortInUse() return false
	_ = listener.Close()
	inUse = IsPortInUse(u)
	assert.False(t, inUse, "should be in listening on: %s", listener.Addr())

	// Test with an invalid address format. This should return true, indicating the port is effectively unavailable.
	u, err = url.Parse("http://invalid-address")
	require.NoError(t, err)
	inUse = IsPortInUse(u)
	require.True(t, inUse)
}

func Test_determineFreePort(t *testing.T) {
	port := DetermineFreePort()
	if port < DefaultPort {
		t.Errorf("Expected port to be greater than %d, but got %d", DefaultPort, port)
	}

	// Try to listen on the determined port.  If it fails, the port isn't actually free.
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	defer func() {
		_ = listener.Close() // we don't care if this fails, it is just a catch-all
	}()

	// Simulate all ports being taken (unlikely, but tests the loop limit)
	portsInUse := make([]net.Listener, 1000)
	for i := 0; i < 1000; i++ {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", DefaultPort+i))
		if err != nil {
			// This could legitimately happen if we run out of ephemeral ports, so just skip in this case
			continue
		}
		portsInUse[i] = l
	}

	defer func() {
		for _, l := range portsInUse {
			if l != nil {
				_ = l.Close()
			}
		}
	}()

	// This test now relies on the limited range defined in DetermineFreePort
	// If it manages to find a free port it is considered a success otherwise a failure is expected
	port = DetermineFreePort()
	if port > DefaultPort && port < DefaultPort+1000 {
		t.Errorf("Expected to fail to find a free port. Port %d found instead ", port)
	}
}

func Test_RandomLoopbackListener(t *testing.T) {
	u, listener, err := RandomLoopbackListener()
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	assert.Equal(t, "http", u.Scheme)
	assert.Contains(t, u.Host, DefaultHost)

	addr := listener.Addr().(*net.TCPAddr)
	assert.NotEqual(t, DefaultPort, addr.Port)

	conn, dialErr := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, dialErr)
	_ = conn.Close()
}

func Test_IsValidLoopbackRequest(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		origin   string
		expected bool
	}{
		{
			name:     "valid localhost host, no origin",
			host:     "localhost",
			origin:   "",
			expected: true,
		},
		{
			name:     "valid localhost host and origin",
			host:     "localhost",
			origin:   "http://localhost:3000",
			expected: true,
		},
		{
			name:     "valid IPv4 loopback",
			host:     "127.0.0.1",
			origin:   "",
			expected: true,
		},
		{
			name:     "valid IPv6 loopback",
			host:     "::1",
			origin:   "",
			expected: true,
		},
		{
			name:     "external host rejected",
			host:     "example.com",
			origin:   "",
			expected: false,
		},
		{
			name:     "external origin rejected",
			host:     "localhost",
			origin:   "http://evil.com",
			expected: false,
		},
		{
			name:     "empty host and origin allowed",
			host:     "",
			origin:   "",
			expected: true,
		},
		{
			name:     "localhost host with port",
			host:     "localhost:8080",
			origin:   "",
			expected: true,
		},
		{
			name:     "127.0.0.1 origin with external host rejected",
			host:     "evil.com",
			origin:   "http://127.0.0.1:3000",
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
			result := IsValidLoopbackRequest(r)
			assert.Equal(t, tt.expected, result)
		})
	}
}
