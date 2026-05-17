package gpwntools

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// LogLevel controls logger verbosity.
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelSilent
)

// Logger is a small pwntools-style logger.
type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level LogLevel
	color bool
}

// Log is the default package logger.
var Log = NewLogger(os.Stderr)

// NewLogger creates a logger that writes to out.
func NewLogger(out io.Writer) *Logger {
	if out == nil {
		out = io.Discard
	}
	return &Logger{
		out:   out,
		level: LogLevelInfo,
	}
}

// SetOutput changes the logger output.
func (l *Logger) SetOutput(out io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if out == nil {
		out = io.Discard
	}
	l.out = out
}

// SetLevel changes the minimum level that will be printed.
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetColor enables or disables ANSI color.
func (l *Logger) SetColor(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.color = enabled
}

// Debug prints a debug message.
func (l *Logger) Debug(format string, args ...any) {
	l.print(LogLevelDebug, "[DEBUG]", "\x1b[36m", format, args...)
}

// Info prints an informational message.
func (l *Logger) Info(format string, args ...any) {
	l.print(LogLevelInfo, "[*]", "\x1b[34m", format, args...)
}

// Success prints a success message.
func (l *Logger) Success(format string, args ...any) {
	l.print(LogLevelInfo, "[+]", "\x1b[32m", format, args...)
}

// Warn prints a warning message.
func (l *Logger) Warn(format string, args ...any) {
	l.print(LogLevelWarn, "[!]", "\x1b[33m", format, args...)
}

// Error prints an error message.
func (l *Logger) Error(format string, args ...any) {
	l.print(LogLevelError, "[-]", "\x1b[31m", format, args...)
}

func (l *Logger) print(level LogLevel, prefix string, color string, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	minLevel := l.effectiveLevel()
	if level < minLevel || minLevel == LogLevelSilent {
		return
	}

	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}

	if l.color {
		prefix = color + prefix + "\x1b[0m"
	}
	if strings.HasSuffix(msg, "\n") {
		fmt.Fprintf(l.out, "%s %s", prefix, msg)
		return
	}
	fmt.Fprintf(l.out, "%s %s\n", prefix, msg)
}

// Enabled reports whether a message at level would be printed.
func (l *Logger) Enabled(level LogLevel) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	minLevel := l.effectiveLevel()
	return level >= minLevel && minLevel != LogLevelSilent
}

func (l *Logger) effectiveLevel() LogLevel {
	if level, ok := parseLogLevel(Context.LogLevel); ok {
		return level
	}
	return l.level
}

func parseLogLevel(value string) (LogLevel, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return LogLevelInfo, false
	case "debug":
		return LogLevelDebug, true
	case "info", "information":
		return LogLevelInfo, true
	case "warn", "warning":
		return LogLevelWarn, true
	case "error":
		return LogLevelError, true
	case "silent", "quiet", "disabled", "none":
		return LogLevelSilent, true
	default:
		return LogLevelInfo, false
	}
}

// SetLogOutput changes the default logger output.
func SetLogOutput(out io.Writer) {
	Log.SetOutput(out)
}

// SetLogLevel changes the default logger level.
func SetLogLevel(level LogLevel) {
	Log.SetLevel(level)
}

// SetLogColor enables or disables ANSI color for the default logger.
func SetLogColor(enabled bool) {
	Log.SetColor(enabled)
}

// Debug prints through the default logger.
func Debug(format string, args ...any) {
	Log.Debug(format, args...)
}

// Info prints through the default logger.
func Info(format string, args ...any) {
	Log.Info(format, args...)
}

// Success prints through the default logger.
func Success(format string, args ...any) {
	Log.Success(format, args...)
}

// Warn prints through the default logger.
func Warn(format string, args ...any) {
	Log.Warn(format, args...)
}

// Error prints through the default logger.
func Error(format string, args ...any) {
	Log.Error(format, args...)
}
