package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/GSM-VPN/tunnel/internal/protocol"
)

var (
	ErrCoreSyncTimeout = errors.New("timed out waiting for core IPC socket")
	ErrCoreSyncFailed  = errors.New("core state synchronization failed")
)

// CoreDesiredState is the controller-owned, secret-free state that must be
// restored whenever the Rust Core process starts again.
type CoreDesiredState struct {
	configuration *protocol.NetworkConfiguration
	peers         map[uint64]protocol.PeerRegistration
}

// NewCoreDesiredState creates an empty state snapshot.
func NewCoreDesiredState() CoreDesiredState {
	return CoreDesiredState{peers: make(map[uint64]protocol.PeerRegistration)}
}

// SetConfiguration records the network policy to apply after Core startup.
func (state *CoreDesiredState) SetConfiguration(configuration protocol.NetworkConfiguration) {
	copy := configuration
	state.configuration = &copy
}

// RegisterPeer records an approved peer without retaining private material.
func (state *CoreDesiredState) RegisterPeer(peer protocol.PeerRegistration) {
	if state.peers == nil {
		state.peers = make(map[uint64]protocol.PeerRegistration)
	}
	state.peers[peer.PeerID] = clonePeer(peer)
}

// RemovePeer removes a peer from the desired approval set.
func (state *CoreDesiredState) RemovePeer(peerID uint64) {
	delete(state.peers, peerID)
}

// Snapshot returns an isolated copy safe for synchronization.
func (state CoreDesiredState) Snapshot() CoreDesiredState {
	snapshot := NewCoreDesiredState()
	if state.configuration != nil {
		configuration := *state.configuration
		snapshot.configuration = &configuration
	}
	for peerID, peer := range state.peers {
		snapshot.peers[peerID] = clonePeer(peer)
	}
	return snapshot
}

// CoreSynchronizer restores desired controller state in a deterministic order.
type CoreSynchronizer struct {
	Client       Client
	SocketWait   time.Duration
	PollInterval time.Duration
	Now          func() time.Time
}

// Synchronize waits for the Core socket and restores initialization, network
// configuration, approvals, and running state. Each successful call uses new
// request IDs, so it is safe to invoke after every Core restart.
func (s CoreSynchronizer) Synchronize(ctx context.Context, state CoreDesiredState) error {
	if s.Client.SocketPath == "" {
		return fmt.Errorf("%w: socket path is required", ErrCoreSyncFailed)
	}
	if err := waitForSocket(ctx, s.Client.SocketPath, s.SocketWait, s.PollInterval); err != nil {
		return err
	}
	requestIDs := requestIDGenerator{}
	if _, err := s.Client.Initialize(requestIDs.Next()); err != nil {
		return fmt.Errorf("%w during initialize: %v", ErrCoreSyncFailed, err)
	}
	if state.configuration != nil {
		if _, err := s.Client.UpdateConfiguration(requestIDs.Next(), *state.configuration); err != nil {
			return fmt.Errorf("%w during configuration: %v", ErrCoreSyncFailed, err)
		}
	}
	peerIDs := make([]uint64, 0, len(state.peers))
	for peerID := range state.peers {
		peerIDs = append(peerIDs, peerID)
	}
	sort.Slice(peerIDs, func(i, j int) bool { return peerIDs[i] < peerIDs[j] })
	for _, peerID := range peerIDs {
		if _, err := s.Client.RegisterPeer(requestIDs.Next(), state.peers[peerID]); err != nil {
			return fmt.Errorf("%w during peer %d: %v", ErrCoreSyncFailed, peerID, err)
		}
	}
	if _, err := s.Client.Start(requestIDs.Next()); err != nil {
		return fmt.Errorf("%w during start: %v", ErrCoreSyncFailed, err)
	}
	return nil
}

func waitForSocket(ctx context.Context, path string, timeout, interval time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if interval <= 0 {
		interval = 10 * time.Millisecond
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %v", ErrCoreSyncFailed, err)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-deadline.C:
			timer.Stop()
			return ErrCoreSyncTimeout
		case <-timer.C:
		}
	}
}

type requestIDGenerator struct{ next uint64 }

func (generator *requestIDGenerator) Next() uint64 {
	generator.next++
	return generator.next
}

func clonePeer(peer protocol.PeerRegistration) protocol.PeerRegistration {
	peer.UserID = string([]byte(peer.UserID))
	return peer
}
