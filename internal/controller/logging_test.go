package controller

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestCoreControllerLogsSecretFreeLifecycleEvents(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	process := &fakeProcess{result: make(chan error)}
	controller := newCoreController(
		CoreCommand{BinaryPath: "core", SocketPath: "/tmp/core.sock"},
		DefaultRestartPolicy(),
		func(context.Context, CoreCommand) (CoreProcess, error) { return process, nil },
	)
	controller.SetLogger(logger)

	if err := controller.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForState(t, controller, CoreRunning)
	if err := controller.Stop(); err != nil {
		t.Fatal(err)
	}

	logs := output.String()
	for _, event := range []string{"core_start_requested", "core_start_attempt", "core_running", "core_state_changed", "core_stop_completed"} {
		if !strings.Contains(logs, event) {
			t.Fatalf("missing %q in logs: %s", event, logs)
		}
	}
	for _, forbidden := range []string{"private_key", "packet", "peer_id", "/tmp/core.sock"} {
		if strings.Contains(logs, forbidden) {
			t.Fatalf("forbidden value %q was logged: %s", forbidden, logs)
		}
	}
}

func TestCoreControllerUsesDiscardLoggerByDefault(t *testing.T) {
	controller := newCoreController(
		CoreCommand{BinaryPath: "core", SocketPath: "/tmp/core.sock"},
		DefaultRestartPolicy(),
		func(context.Context, CoreCommand) (CoreProcess, error) { return nil, context.Canceled },
	)
	if controller.logger == nil {
		t.Fatal("controller has no default logger")
	}
}
