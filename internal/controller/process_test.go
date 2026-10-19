package controller

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
)

func TestStartCoreValidatesConfiguration(t *testing.T) {
	if _, err := StartCore(context.Background(), CoreCommand{}); err == nil {
		t.Fatal("expected binary path validation error")
	}
	if _, err := StartCore(context.Background(), CoreCommand{BinaryPath: "core"}); err == nil {
		t.Fatal("expected socket path validation error")
	}
}

func TestStartCoreCanStopChildProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command fixture is Unix-specific")
	}
	process, err := StartCore(context.Background(), CoreCommand{
		BinaryPath: "/bin/sh",
		Args:       []string{"-c", "sleep 10"},
		SocketPath: "/tmp/gsm-core-test.sock",
		Env:        []string{"TUNNEL_CORE_TEST=1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Stop(); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- process.Wait() }()
	select {
	case err := <-waitDone:
		if err == nil {
			t.Fatal("expected killed child to report an exit error")
		}
		if errors.Is(err, context.Canceled) {
			t.Fatal("unexpected context cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("child process did not stop")
	}
}
