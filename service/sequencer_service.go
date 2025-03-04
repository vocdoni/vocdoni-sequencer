package service

import (
	"context"
	"time"

	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/processor"
	"github.com/vocdoni/vocdoni-z-sandbox/storage"
)

// SequencerService represents a service that handles background vote processing.
type SequencerService struct {
	processor *processor.Processor
}

// NewProcessorService creates a new processor instance. It will verify new votes, aggregate them into batches,
// and update the ongoing state with the new ones. The batchTimeWindow defines how long a batch can wait
// until processed (either the batch becomes full of votes or the time window expires).
func NewProcessor(stg *storage.Storage, batchTimeWindow time.Duration) *SequencerService {
	p, err := processor.New(stg, batchTimeWindow)
	if err != nil {
		log.Fatalf("failed to create processor: %v", err)
	}
	return &SequencerService{
		processor: p,
	}
}

// Start begins the vote processing service. It returns an error if the service is already running.
func (ps *SequencerService) Start(ctx context.Context) error {
	return ps.processor.Start(ctx)
}

// Stop halts the vote processing service.
func (ps *SequencerService) Stop() {
	if err := ps.processor.Stop(); err != nil {
		log.Warnw("processor service stopped", "error", err)
	}
}
