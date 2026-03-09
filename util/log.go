package util

import (
	"log/slog"
	"os"
)

// Section prefixes for log messages.
const (
	SectionEAP = "EAP"
	SectionU31 = "U31"
	SectionU62 = "U62"
	SectionSYS = "SYS"
)

// Logger wraps slog.Logger with a section prefix.
type Logger struct {
	*slog.Logger
}

// NewLogger creates a Logger with the given section name.
func NewLogger(section string) *Logger {
	return &Logger{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})).With("section", section),
	}
}
