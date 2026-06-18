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
)

const (
	DefaultPort = 7695
	DefaultHost = "127.0.0.1"
)

func IsPortInUse(u *url.URL) bool {
	address := u.Host
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return true
	}
	_ = listener.Close()
	return false
}

func DetermineFreePort() int {
	port := DefaultPort
	for range 1000 {
		u, err := url.Parse(fmt.Sprintf("http://%s:%d", DefaultHost, port))
		if err != nil {
			// this should not ever happen. so if it does, we panic
			panic(err)
		}
		inUse := IsPortInUse(u)
		if !inUse {
			break
		}
		port++
	}
	return port
}

func RandomLoopbackListener() (*url.URL, net.Listener, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(DefaultHost, "0"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on loopback: %w", err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	u, err := url.Parse(fmt.Sprintf("http://%s:%d", DefaultHost, addr.Port))
	if err != nil {
		_ = listener.Close()
		return nil, nil, err
	}
	return u, listener, nil
}

var AllowedLoopbackHostnames = map[string]bool{
	"localhost": true,
	"127.0.0.1": true,
	"::1":       true,
	"":          true,
}

func IsValidLoopbackRequest(r *http.Request) bool {
	originHeader := r.Header.Get("Origin")
	isValidOrigin := originHeader == ""
	hostHeader := r.Host
	host, _, err := net.SplitHostPort(hostHeader)
	if err != nil {
		host = hostHeader
	}
	isValidHost := AllowedLoopbackHostnames[host]

	if !isValidOrigin {
		parsedOrigin, err := url.Parse(originHeader)
		if err == nil {
			requestHost := parsedOrigin.Hostname()
			if _, allowed := AllowedLoopbackHostnames[requestHost]; allowed {
				isValidOrigin = true
			}
		}
	}

	return isValidOrigin && isValidHost
}

func LoopbackURL() (*url.URL, error) {
	rawURL := fmt.Sprintf("http://%s:%d", DefaultHost, DetermineFreePort())
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	return u, nil
}
