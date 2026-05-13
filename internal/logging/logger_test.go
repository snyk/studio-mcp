/*
 * © 2025 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package logging

import (
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func newTestServer() *server.MCPServer {
	return server.NewMCPServer("test", "1.0.0")
}

func TestConfigureLogging_NilOldLogger_DisablesLogging(t *testing.T) {
	logger := ConfigureLogging(newTestServer(), nil)

	assert.NotNil(t, logger)
	assert.Equal(t, zerolog.Disabled, logger.GetLevel())
}

func TestConfigureLogging_InheritsLevelFromOldLogger(t *testing.T) {
	cases := []zerolog.Level{
		zerolog.TraceLevel,
		zerolog.DebugLevel,
		zerolog.InfoLevel,
		zerolog.WarnLevel,
		zerolog.ErrorLevel,
		zerolog.Disabled,
	}
	for _, level := range cases {
		t.Run(level.String(), func(t *testing.T) {
			oldLogger := zerolog.Nop().Level(level)
			logger := ConfigureLogging(newTestServer(), &oldLogger)

			assert.NotNil(t, logger)
			assert.Equal(t, level, logger.GetLevel())
		})
	}
}
