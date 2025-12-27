/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
 * openFuyao is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

// Package tools defines log tools
package tools

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	defaultLogPath = "/var/log/logging-operator"

	// ASCII control character constants for better readability
	asciiSpace         = 0x20   // Space character (ASCII 32)
	asciiBell          = 0x07   // Bell character (ASCII 7)
	asciiEscape        = 0x1B   // Escape character (ASCII 27)
	unicodeReplacement = 0xFFFD // Unicode replacement character
)

// Logger is a globally available *zap.SugaredLogger instance
var Logger *zap.SugaredLogger

var logLevel = map[string]zapcore.Level{
	"debug": zapcore.DebugLevel,
	"info":  zapcore.InfoLevel,
	"warn":  zapcore.WarnLevel,
	"error": zapcore.ErrorLevel,
}

// LogConfig defines the configuration settings for the logging system.
type LogConfig struct {
	Level       string // - Level specifies the minimum level of logs to output.
	EncoderType string // - EncoderType determines the log output format (e.g., json or console).
	Path        string // - Path and FileName define where logs are stored on the file system.
	FileName    string // - Path and FileName define where logs are stored on the file system.
	MaxSize     int    // - MaxSize, MaxBackups, and MaxAge control log rotation behavior.
	MaxBackups  int    // - MaxSize, MaxBackups, and MaxAge control log rotation behavior.
	MaxAge      int    // - MaxSize, MaxBackups, and MaxAge control log rotation behavior.
	LocalTime   bool   // - LocalTime indicates whether to use the local time for log timestamps.
	Compress    bool   // - Compress determines whether to compress rotated log files.
	OutMod      string // - OutMod defines the output mode (e.g., file, console, or both).
}

// sanitizeLogString prevents log injection attacks by escaping all control characters and removing dangerous characters
// This function handles both ASCII and Unicode control characters
func sanitizeLogString(s string) string {
	// First pass: escape common control characters that should be visible
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	s = strings.ReplaceAll(s, "\v", "\\v")
	s = strings.ReplaceAll(s, "\f", "\\f")
	s = strings.ReplaceAll(s, "\b", "\\b")

	// Second pass: remove all other control characters and problematic characters
	var result strings.Builder
	result.Grow(len(s))

	for _, r := range s {
		switch {
		case unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t':
			// Skip all other control characters (not the common ones we already escaped)
			continue
		case r == unicodeReplacement: // Unicode replacement character (often indicates encoding issues)
			continue
		case r < asciiSpace && r != '\n' && r != '\r' && r != '\t':
			// Skip ASCII control characters except the common ones
			continue
		default:
			result.WriteRune(r)
		}
	}

	cleaned := result.String()

	// Third pass: additional safety checks for common injection patterns
	cleaned = strings.ReplaceAll(cleaned, string(rune(asciiEscape)), "\\e") // Escape character
	cleaned = strings.ReplaceAll(cleaned, string(rune(asciiBell)), "\\a")   // Bell character

	// Limit string length to prevent abuse
	const maxLogLength = 2000
	if len(cleaned) > maxLogLength {
		cleaned = cleaned[:maxLogLength] + " [TRUNCATED]"
	}

	return cleaned
}

// sanitizedCore is a custom zapcore.Core wrapper that sanitizes all log fields before writing them
// This ensures all log content processed through this logger is safe from injection attacks
type sanitizedCore struct {
	zapcore.Core
}

// With sanitizes context fields to prevent log injection attacks
func (c *sanitizedCore) With(fields []zapcore.Field) zapcore.Core {
	cleanFields := make([]zapcore.Field, len(fields))
	for i, f := range fields {
		cleanFields[i] = sanitizeField(f)
	}
	return c.Core.With(cleanFields)
}

// Check implements the zapcore.Core interface to determine if a log entry should be processed
func (c *sanitizedCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	return c.Core.Check(ent, ce)
}

// Write sanitizes log messages and fields before writing them to the output
func (c *sanitizedCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	// Sanitize the main log message thoroughly
	ent.Message = sanitizeLogString(ent.Message)

	// Sanitize all log fields
	cleanFields := make([]zapcore.Field, len(fields))
	for i, f := range fields {
		cleanFields[i] = sanitizeField(f)
	}

	// Also sanitize the logger name if present (some zap configurations include this)
	if ent.LoggerName != "" {
		ent.LoggerName = sanitizeLogString(ent.LoggerName)
	}

	return c.Core.Write(ent, cleanFields)
}

// Sync flushes any buffered log data to the underlying writer
func (c *sanitizedCore) Sync() error {
	return c.Core.Sync()
}

// sanitizeField cleans individual log fields to prevent log injection attacks
// This function handles different field types and sanitizes their content appropriately
func sanitizeField(field zapcore.Field) zapcore.Field {
	// Create a copy to avoid modifying the original field
	cleanField := field

	switch cleanField.Type {
	case zapcore.StringType:
		// Clean string type fields thoroughly
		if cleanField.String != "" {
			cleanField.String = sanitizeLogString(cleanField.String)
		}
	case zapcore.ErrorType:
		// Clean error type fields
		if cleanField.Interface != nil {
			if err, ok := cleanField.Interface.(error); ok {
				cleanField.String = sanitizeLogString(err.Error())
			} else {
				// Fallback to string conversion if not an error type
				cleanField.String = sanitizeLogString(fmt.Sprintf("%v", cleanField.Interface))
			}
			cleanField.Interface = nil // Clear interface to avoid double processing
		}
	case zapcore.ByteStringType:
		// Clean byte slice type fields
		if cleanField.Interface != nil {
			if bytes, ok := cleanField.Interface.([]byte); ok {
				cleanedStr := sanitizeLogString(string(bytes))
				cleanField.Interface = []byte(cleanedStr)
			} else {
				// Convert to string if not a byte slice
				cleanField.String = sanitizeLogString(fmt.Sprintf("%v", cleanField.Interface))
				cleanField.Type = zapcore.StringType
				cleanField.Interface = nil
			}
		}
	case zapcore.ObjectMarshalerType:
		// Handle objects that implement ObjectMarshaler interface
		if cleanField.Interface != nil {
			cleanField.String = sanitizeLogString(fmt.Sprintf("%+v", cleanField.Interface))
			cleanField.Type = zapcore.StringType
			cleanField.Interface = nil
		}
	case zapcore.StringerType:
		// Handle objects that implement String() method
		if cleanField.Interface != nil {
			if stringer, ok := cleanField.Interface.(fmt.Stringer); ok {
				cleanField.String = sanitizeLogString(stringer.String())
			} else {
				// Fallback to string conversion if not a Stringer
				cleanField.String = sanitizeLogString(fmt.Sprintf("%v", cleanField.Interface))
			}
			cleanField.Type = zapcore.StringType
			cleanField.Interface = nil
		}
	default:
		// Handle all other field types including ReflectType (corresponds to zap.Any())
		if cleanField.Interface != nil {
			cleanField.String = sanitizeLogString(fmt.Sprintf("%+v", cleanField.Interface))
			cleanField.Type = zapcore.StringType
			cleanField.Interface = nil
		}
	}
	return cleanField
}

func init() {
	fmt.Print("The user management backend started running.")
	conf := getDefaultConf()
	Logger = GetLogger(conf)
}

func getDefaultConf() *LogConfig {
	var defaultConf = &LogConfig{
		Level:       "info",
		EncoderType: "console",
		Path:        defaultLogPath,
		FileName:    "user-management.log",
		MaxSize:     20,
		MaxBackups:  0,
		MaxAge:      7,
		LocalTime:   false,
		Compress:    true,
		OutMod:      "console",
	}
	exePath, err := os.Executable()
	if err != nil {
		return defaultConf
	}
	// Get the executable name as a subdirectory under /var/log
	serviceName := strings.TrimSuffix(filepath.Base(exePath), filepath.Ext(filepath.Base(exePath)))
	defaultConf.Path = filepath.Join(defaultLogPath, serviceName)
	return defaultConf
}

// GetLogger initializes and returns a new instance of zap.SugaredLogger based on the provided LogConfig.
// This function creates a logger with built-in protection against log injection attacks.
func GetLogger(conf *LogConfig) *zap.SugaredLogger {
	writeSyncer := getLogWriter(conf)
	encoder := getEncoder(conf)
	level, ok := logLevel[strings.ToLower(conf.Level)]
	if !ok {
		level = logLevel["info"]
	}

	// Create the base core
	baseCore := zapcore.NewCore(encoder, writeSyncer, level)

	// Wrap with sanitization core to prevent log injection
	sanitizedCore := &sanitizedCore{Core: baseCore}

	// Create logger with caller information
	// AddCallerSkip(1) ensures correct caller information
	logger := zap.New(sanitizedCore, zap.AddCaller(), zap.AddCallerSkip(1))
	return logger.Sugar()
}

// getEncoder gets the log encoder, supporting JSON and console formats
func getEncoder(conf *LogConfig) zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	// Specify time format, for example: 2021-09-11t20:05:54.852+0800
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	// Display different colors by level, use zapcore.CapitalLevelEncoder if not needed
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	// NewJSONEncoder() outputs JSON format, NewConsoleEncoder() outputs plain text format
	if strings.ToLower(conf.EncoderType) == "json" {
		return zapcore.NewJSONEncoder(encoderConfig)
	}
	return zapcore.NewConsoleEncoder(encoderConfig)
}

func getLogWriter(conf *LogConfig) zapcore.WriteSyncer {
	switch conf.OutMod {
	case "console":
		return zapcore.AddSync(os.Stdout)
	case "file":
		return zapcore.AddSync(createLumberjackLogger(conf))
	case "both":
		return zapcore.NewMultiWriteSyncer(zapcore.AddSync(createLumberjackLogger(conf)), zapcore.AddSync(os.Stdout))
	default:
		return zapcore.AddSync(os.Stdout)
	}
}

func createLumberjackLogger(conf *LogConfig) *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   filepath.Join(conf.Path, conf.FileName),
		MaxSize:    conf.MaxSize,
		MaxBackups: conf.MaxBackups,
		MaxAge:     conf.MaxAge,
		LocalTime:  conf.LocalTime,
		Compress:   conf.Compress,
	}
}

// HandleError handles errors by logging and responding with the appropriate HTTP status code and error message.
func HandleError(response http.ResponseWriter, statusCode int, err error) {
	errorMessage := sanitizeLogString(fmt.Sprintf("Error occurred: %v", err))
	// Log the error
	LogError(errorMessage)
	// Respond with error message and status code
	response.WriteHeader(statusCode)
	cleanResponse := sanitizeLogString(errorMessage)
	code, err := response.Write([]byte(cleanResponse))
	if err != nil {
		errorMessage := sanitizeLogString(fmt.Sprintf("Failed to write entity: %v", err))
		LogError(errorMessage)
	}
	errorMessage = sanitizeLogString(fmt.Sprintf("Error code %v", code))
	LogError(errorMessage)
}

// AddContext adds a variadic number of fields to the logging context. It accepts a mix of strongly-typed Field objects
// and loosely-typed key-value pairs.
func AddContext(args ...interface{}) *zap.SugaredLogger {
	// Sanitize context arguments
	cleanArgs := make([]interface{}, len(args))
	for i, arg := range args {
		cleanArgs[i] = sanitizeLogArgument(arg)
	}
	return Logger.With(cleanArgs...)
}

// LogDebug writes messages at DebugLevel, inserting spaces between arguments when neither is a string.
func LogDebug(args ...interface{}) {
	cleanArgs := make([]interface{}, len(args))
	for i, arg := range args {
		cleanArgs[i] = sanitizeLogArgument(arg)
	}
	Logger.Debug(cleanArgs...)
}

// LogInfo logs the provided arguments at [].
// Spaces are added between arguments when neither is a string.
func LogInfo(args ...interface{}) {
	cleanArgs := make([]interface{}, len(args))
	for i, arg := range args {
		cleanArgs[i] = sanitizeLogArgument(arg)
	}
	Logger.Info(cleanArgs...)
}

// LogWarn logs the provided arguments at [WarnLevel].
// Spaces are added between arguments when neither is a string.
func LogWarn(args ...interface{}) {
	cleanArgs := make([]interface{}, len(args))
	for i, arg := range args {
		cleanArgs[i] = sanitizeLogArgument(arg)
	}
	Logger.Warn(cleanArgs...)
}

// LogError logs the provided arguments at [ErrorLevel].
// Spaces are added between arguments when neither is a string.
func LogError(args ...interface{}) {
	cleanArgs := make([]interface{}, len(args))
	for i, arg := range args {
		cleanArgs[i] = sanitizeLogArgument(arg)
	}
	Logger.Error(cleanArgs...)
}

// FormatDebug constructs a message based on a format specifier and logs it at DebugLevel.
func FormatDebug(template string, args ...interface{}) {
	cleanTemplate := sanitizeLogString(template)
	cleanArgs := make([]interface{}, len(args))
	for i, arg := range args {
		cleanArgs[i] = sanitizeLogArgument(arg)
	}
	Logger.Debugf(cleanTemplate, cleanArgs...)
}

// FormatInfo constructs a message based on a format specifier and logs it at InfoLevel.
func FormatInfo(template string, args ...interface{}) {
	cleanTemplate := sanitizeLogString(template)
	cleanArgs := make([]interface{}, len(args))
	for i, arg := range args {
		cleanArgs[i] = sanitizeLogArgument(arg)
	}
	Logger.Infof(cleanTemplate, cleanArgs...)
}

// FormatWarn constructs a message based on a format specifier and logs it at.WarnLevel.
func FormatWarn(template string, args ...interface{}) {
	cleanTemplate := sanitizeLogString(template)
	cleanArgs := make([]interface{}, len(args))
	for i, arg := range args {
		cleanArgs[i] = sanitizeLogArgument(arg)
	}
	Logger.Warnf(cleanTemplate, cleanArgs...)
}

// FormatError constructs a message based on a format specifier and logs it at ErrorLevel.
func FormatError(template string, args ...interface{}) {
	cleanTemplate := sanitizeLogString(template)
	cleanArgs := make([]interface{}, len(args))
	for i, arg := range args {
		cleanArgs[i] = sanitizeLogArgument(arg)
	}
	Logger.Errorf(cleanTemplate, cleanArgs...)
}

// LogDebugWithContext logs a debug-level message with additional context, optimizing performance when debugging is off.
func LogDebugWithContext(msg string, keysAndValues ...interface{}) {
	cleanMsg := sanitizeLogString(msg)
	cleanPairs := make([]interface{}, len(keysAndValues))
	for i, kv := range keysAndValues {
		cleanPairs[i] = sanitizeLogArgument(kv)
	}
	Logger.Debugw(cleanMsg, cleanPairs...)
}

// LogInfoWithContext logs an info-level message with additional context.
func LogInfoWithContext(msg string, keysAndValues ...interface{}) {
	cleanMsg := sanitizeLogString(msg)
	cleanPairs := make([]interface{}, len(keysAndValues))
	for i, kv := range keysAndValues {
		cleanPairs[i] = sanitizeLogArgument(kv)
	}
	Logger.Infow(cleanMsg, cleanPairs...)
}

// LogWarnWithContext logs a warn-level message with additional context.
func LogWarnWithContext(msg string, keysAndValues ...interface{}) {
	cleanMsg := sanitizeLogString(msg)
	cleanPairs := make([]interface{}, len(keysAndValues))
	for i, kv := range keysAndValues {
		cleanPairs[i] = sanitizeLogArgument(kv)
	}
	Logger.Warnw(cleanMsg, cleanPairs...)
}

// LogErrorWithContext logs an error-level message with additional context.
func LogErrorWithContext(msg string, keysAndValues ...interface{}) {
	cleanMsg := sanitizeLogString(msg)
	cleanPairs := make([]interface{}, len(keysAndValues))
	for i, kv := range keysAndValues {
		cleanPairs[i] = sanitizeLogArgument(kv)
	}
	Logger.Errorw(cleanMsg, cleanPairs...)
}

// LogDebugLine logs a debug-level message, always adding spaces between arguments.
func LogDebugLine(args ...interface{}) {
	cleanArgs := make([]interface{}, len(args))
	for i, arg := range args {
		cleanArgs[i] = sanitizeLogArgument(arg)
	}
	Logger.Debugln(cleanArgs...)
}

// LogInfoLine logs an info-level message, always adding spaces between arguments.
func LogInfoLine(args ...interface{}) {
	cleanArgs := make([]interface{}, len(args))
	for i, arg := range args {
		cleanArgs[i] = sanitizeLogArgument(arg)
	}
	Logger.Infoln(cleanArgs...)
}

// LogWarnLine logs a warn-level message, always adding spaces between arguments.
func LogWarnLine(args ...interface{}) {
	cleanArgs := make([]interface{}, len(args))
	for i, arg := range args {
		cleanArgs[i] = sanitizeLogArgument(arg)
	}
	Logger.Warnln(cleanArgs...)
}

// LogErrorLine logs an error-level message, always adding spaces between arguments.
func LogErrorLine(args ...interface{}) {
	cleanArgs := make([]interface{}, len(args))
	for i, arg := range args {
		cleanArgs[i] = sanitizeLogArgument(arg)
	}
	Logger.Errorln(cleanArgs...)
}

// sanitizeLogArgument sanitizes a single argument for logging
func sanitizeLogArgument(arg interface{}) interface{} {
	switch v := arg.(type) {
	case string:
		return sanitizeLogString(v)
	case error:
		return sanitizeLogString(v.Error())
	case fmt.Stringer:
		return sanitizeLogString(v.String())
	case []byte:
		return []byte(sanitizeLogString(string(v)))
	default:
		return sanitizeLogString(fmt.Sprintf("%v", v))
	}
}
