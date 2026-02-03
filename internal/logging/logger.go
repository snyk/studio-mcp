/*
 * © 2023 Snyk Limited
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

package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/adrg/xdg"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"
	frameworkLogging "github.com/snyk/go-application-framework/pkg/logging"
)

const SNYK_MCP = "snyk-mcp"

// mcpWriter is a zerolog.LevelWriter that sends log messages to all connected MCP clients
type mcpWriter struct {
	writeChan chan logMessage
	readyChan chan bool
	server    *mcp.Server
}

type logMessage struct {
	level   mcp.LoggingLevel
	logger  string
	message string
}

// New creates a new mcpWriter that sends log messages to all connected MCP server sessions
func New(server *mcp.Server) zerolog.LevelWriter {
	readyChan := make(chan bool)
	writeChan := make(chan logMessage, 1000000)
	w := &mcpWriter{
		writeChan: writeChan,
		readyChan: readyChan,
		server:    server,
	}
	go w.startServerSenderRoutine()
	<-w.readyChan
	return w
}

func (w *mcpWriter) Write(p []byte) (n int, err error) {
	return w.WriteLevel(zerolog.InfoLevel, p)
}

func (w *mcpWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	if w.server != nil {
		w.writeChan <- logMessage{
			level:   mapLogLevel(level),
			logger:  SNYK_MCP,
			message: string(p),
		}
		return len(p), nil
	}

	return 0, nil
}

func (w *mcpWriter) startServerSenderRoutine() {
	w.readyChan <- true
	for msg := range w.writeChan {
		// Send the notification to all connected sessions using Sessions() iterator
		for ss := range w.server.Sessions() {
			_ = ss.Log(context.Background(), &mcp.LoggingMessageParams{
				Level:  msg.level,
				Logger: msg.logger,
				Data:   msg.message,
			})
		}
	}
}

func mapLogLevel(level zerolog.Level) mcp.LoggingLevel {
	switch level {
	case zerolog.PanicLevel:
		fallthrough
	case zerolog.FatalLevel:
		return "critical"
	case zerolog.ErrorLevel:
		return "error"
	case zerolog.WarnLevel:
		return "warning"
	case zerolog.InfoLevel:
		return "info"
	case zerolog.DebugLevel:
		return "debug"
	default:
		return "info"
	}
}

func getConsoleWriter(writer io.Writer) zerolog.ConsoleWriter {
	w := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.Out = writer
		w.NoColor = true
		w.TimeFormat = time.RFC3339Nano
		w.PartsOrder = []string{
			zerolog.TimestampFieldName,
			zerolog.LevelFieldName,
			"method",
			"ext",
			"separator",
			zerolog.CallerFieldName,
			zerolog.MessageFieldName,
		}
		w.FieldsExclude = []string{"method", "separator", "ext"}
	})
	return w
}

// ConfigureLogging sets up logging for the MCP server
func ConfigureLogging(server *mcp.Server) *zerolog.Logger {
	logLevel := zerolog.InfoLevel

	if envLogLevel := os.Getenv("SNYK_LOG_LEVEL"); envLogLevel != "" {
		if envLevel, err := zerolog.ParseLevel(envLogLevel); err == nil {
			logLevel = envLevel
		}
	}

	var rawWriters []io.Writer

	mcpLevelWriter := New(server)
	rawWriters = append(rawWriters, mcpLevelWriter)

	if logPath, err := xdg.ConfigFile("snyk/snyk-mcp.log"); err == nil {
		if logFile, fileOpenErr := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600); fileOpenErr == nil {
			rawWriters = append(rawWriters, logFile)
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "failed to open log file %s: %s\n", logPath, fileOpenErr)
		}
	}
	rawWriters = append(rawWriters, os.Stderr) // enhanced GAF logger writes to stderr

	scrubbingWriter := frameworkLogging.NewScrubbingWriter(
		zerolog.MultiLevelWriter(rawWriters...),
		make(frameworkLogging.ScrubbingDict),
	)

	consoleWriter := getConsoleWriter(scrubbingWriter)

	logger := zerolog.New(consoleWriter).With().
		Timestamp().
		Str("separator", "-").
		Str("method", "").
		Str("ext", SNYK_MCP).
		Logger().
		Level(logLevel)

	return &logger
}

// NewSlogLogger creates an slog.Logger for use with MCP ServerOptions
func NewSlogLogger() *slog.Logger {
	logLevel := slog.LevelInfo

	if envLogLevel := os.Getenv("SNYK_LOG_LEVEL"); envLogLevel != "" {
		switch envLogLevel {
		case "debug", "trace":
			logLevel = slog.LevelDebug
		case "warn", "warning":
			logLevel = slog.LevelWarn
		case "error":
			logLevel = slog.LevelError
		}
	}

	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))
}
