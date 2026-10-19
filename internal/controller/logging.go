package controller

import (
	"io"
	"log/slog"
)

// coreOperationalLogger is discarded by default. Applications can opt in
// with CoreController.SetLogger when they have an operational log sink.
func coreOperationalLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// logCoreEvent accepts bounded lifecycle and approval metadata only. It
// deliberately has no path for command, packet, key, or raw error values.
func logCoreEvent(logger *slog.Logger, event string, attrs ...any) {
	if logger != nil {
		logger.Info(event, attrs...)
	}
}
