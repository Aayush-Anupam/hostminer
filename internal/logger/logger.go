// Package logger provides a two-level logger used throughout hostminer.
//
// Call [SetLevel] once at startup (typically from main) before using [Infof] or [Debugf].
//   - [LevelInfo]  — visible with -v
//   - [LevelDebug] — visible with -vv (includes all Info messages)
package logger

import (
	"log"
	"os"
)

// Level controls which log messages are emitted.
type Level int

const (
	LevelOff   Level = 0
	LevelInfo  Level = 1
	LevelDebug Level = 2
)

var (
	current  Level = LevelOff
	infoLog        = log.New(os.Stderr, "", log.Ltime|log.Lmicroseconds)
	debugLog       = log.New(os.Stderr, "[DEBUG] ", log.Ltime|log.Lmicroseconds)
)

// SetLevel sets the minimum log level. Must be called before any logging.
func SetLevel(l Level) { current = l }

// Infof emits a message at info level (visible with -v).
func Infof(format string, args ...any) {
	if current >= LevelInfo {
		infoLog.Printf(format, args...)
	}
}

// Debugf emits a message at debug level (visible with -vv).
func Debugf(format string, args ...any) {
	if current >= LevelDebug {
		debugLog.Printf(format, args...)
	}
}
