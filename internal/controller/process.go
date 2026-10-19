package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

// CoreCommand describes one Rust Core child process.
type CoreCommand struct {
	BinaryPath string
	Args       []string
	SocketPath string
	MaxPeers   uint32
	Env        []string
}

// StartCore starts a Rust Core process with its IPC configuration in the
// environment. Data packets remain inside the child process.
func StartCore(ctx context.Context, config CoreCommand) (CoreProcess, error) {
	if config.BinaryPath == "" {
		return nil, errors.New("core binary path is required")
	}
	if config.SocketPath == "" {
		return nil, errors.New("core socket path is required")
	}
	if config.MaxPeers == 0 {
		config.MaxPeers = 216
	}
	command := exec.CommandContext(ctx, config.BinaryPath, config.Args...)
	command.Env = append(os.Environ(), config.Env...)
	command.Env = append(command.Env,
		"TUNNEL_CORE_IPC_SOCKET="+config.SocketPath,
		"TUNNEL_CORE_MAX_PEERS="+strconv.FormatUint(uint64(config.MaxPeers), 10),
	)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start tunnel core: %w", err)
	}
	return &childProcess{command: command}, nil
}

type childProcess struct {
	command *exec.Cmd
}

func (process *childProcess) Wait() error {
	return process.command.Wait()
}

func (process *childProcess) Stop() error {
	if process.command.Process == nil {
		return nil
	}
	if err := process.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}
