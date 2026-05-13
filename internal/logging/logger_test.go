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

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

func newTestConfig() configuration.Configuration {
	return configuration.NewWithOpts()
}

func TestResolveLogLevel_NilConfig_DefaultsToInfo(t *testing.T) {
	assert.Equal(t, zerolog.InfoLevel, resolveLogLevel(nil))
}

func TestResolveLogLevel_Default_IsInfo(t *testing.T) {
	config := newTestConfig()
	assert.Equal(t, zerolog.InfoLevel, resolveLogLevel(config))
}

func TestResolveLogLevel_LogLevelConfig_IsParsed(t *testing.T) {
	cases := map[string]zerolog.Level{
		"trace": zerolog.TraceLevel,
		"debug": zerolog.DebugLevel,
		"info":  zerolog.InfoLevel,
		"warn":  zerolog.WarnLevel,
		"error": zerolog.ErrorLevel,
	}
	for input, expected := range cases {
		t.Run(input, func(t *testing.T) {
			config := newTestConfig()
			config.Set(configuration.LOG_LEVEL, input)
			assert.Equal(t, expected, resolveLogLevel(config))
		})
	}
}

func TestResolveLogLevel_InvalidLogLevel_FallsBackToInfo(t *testing.T) {
	config := newTestConfig()
	config.Set(configuration.LOG_LEVEL, "not-a-level")
	assert.Equal(t, zerolog.InfoLevel, resolveLogLevel(config))
}

func TestResolveLogLevel_DebugFlag_UsesDebugLevel(t *testing.T) {
	config := newTestConfig()
	config.Set(configuration.DEBUG, true)
	assert.Equal(t, zerolog.DebugLevel, resolveLogLevel(config))
}

func TestResolveLogLevel_LogLevelTakesPrecedenceOverDebug(t *testing.T) {
	config := newTestConfig()
	config.Set(configuration.DEBUG, true)
	config.Set(configuration.LOG_LEVEL, "trace")
	assert.Equal(t, zerolog.TraceLevel, resolveLogLevel(config))
}

func TestResolveLogLevel_LogLevelTakesPrecedenceOverDebug_HigherLevel(t *testing.T) {
	config := newTestConfig()
	config.Set(configuration.DEBUG, true)
	config.Set(configuration.LOG_LEVEL, "error")
	assert.Equal(t, zerolog.ErrorLevel, resolveLogLevel(config))
}
