package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/processor"
	"github.com/vocdoni/vocdoni-z-sandbox/storage"
)

// VoteProcessorService represents a service that handles background vote processing.
type VoteProcessorService struct {
	voteProcessor *processor.VoteProcessor
	mu            sync.Mutex
	cancel        context.CancelFunc
}

// NewVoteProcessor creates a new VoteProcessorService instance.
func NewVoteProcessor(stg *storage.Storage) *VoteProcessorService {
	return &VoteProcessorService{
		voteProcessor: processor.NewVoteProcessor(stg),
	}
}

// Start begins the vote processing service. It returns an error if the service is already running.
func (vps *VoteProcessorService) Start(ctx context.Context) error {
	vps.mu.Lock()
	defer vps.mu.Unlock()

	if vps.cancel != nil {
		return fmt.Errorf("vote processor service already running")
	}

	// Create a cancelable context that will be passed to the underlying VoteProcessor.
	ctx, cancel := context.WithCancel(ctx)
	vps.cancel = cancel

	// Start the underlying VoteProcessor. It runs in background.
	return vps.voteProcessor.Start(ctx)
}

// Stop halts the vote processing service.
func (vps *VoteProcessorService) Stop() {
	vps.mu.Lock()
	defer vps.mu.Unlock()

	if vps.cancel == nil {
		return
	}
	if err := vps.voteProcessor.Stop(); err != nil {
		log.Warnw("vote processor service stopped", "error", err)
	}
	vps.cancel = nil
}
