package sequencer

import (
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/storage"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// AddProcessID registers a process ID with the sequencer for ballot processing.
// Only ballots belonging to registered process IDs will be processed.
// If the process ID is already registered, this operation has no effect.
//
// Parameters:
//   - pid: The process ID to register
func (s *Sequencer) AddProcessID(pid []byte) {
	if pid == nil || len(pid) == 0 {
		log.Warnw("attempted to add empty process ID")
		return
	}

	pidStr := string(pid)
	s.pidsLock.Lock()
	defer s.pidsLock.Unlock()

	if _, exists := s.pids[pidStr]; exists {
		log.Debugw("process ID already registered", "processID", fmt.Sprintf("%x", pid))
		return
	}

	s.pids[pidStr] = time.Now()
	log.Infow("process ID registered for sequencing", "processID", fmt.Sprintf("%x", pid))
}

// DelProcessID unregisters a process ID from the sequencer.
// If the process ID is not registered, this operation has no effect.
//
// Parameters:
//   - pid: The process ID to unregister
func (s *Sequencer) DelProcessID(pid []byte) {
	if pid == nil || len(pid) == 0 {
		return
	}

	pidStr := string(pid)
	s.pidsLock.Lock()
	defer s.pidsLock.Unlock()

	if _, exists := s.pids[pidStr]; exists {
		delete(s.pids, pidStr)
		log.Infow("process ID unregistered from sequencing", "processID", fmt.Sprintf("%x", pid))
	}
}

// startAggregateProcessor starts a background goroutine that periodically checks
// for batches of verified ballots that are ready to be aggregated into a single proof.
// A batch is considered ready when either:
// 1. It contains at least VotesPerBatch ballots, or
// 2. The time since the last update exceeds maxTimeWindow
//
// The processor runs until the sequencer's context is canceled.
func (s *Sequencer) startAggregateProcessor() error {
	const tickInterval = 10 * time.Second
	ticker := time.NewTicker(tickInterval)

	go func() {
		defer ticker.Stop()
		log.Infow("aggregate processor started", "tickInterval", tickInterval)

		for {
			select {
			case <-s.ctx.Done():
				log.Infow("aggregate processor stopped")
				return
			case <-ticker.C:
				s.processPendingBatches()
			}
		}
	}()
	return nil
}

// processPendingBatches checks all registered process IDs and aggregates
// any batches that are ready for processing.
func (s *Sequencer) processPendingBatches() {
	// Copy pids to avoid locking the map for too long
	s.pidsLock.RLock()
	pids := make(map[string]time.Time, len(s.pids))
	for k, v := range s.pids {
		pids[k] = v
	}
	s.pidsLock.RUnlock()

	// Iterate over the process IDs and process the ones that are ready
	for pid, lastUpdate := range pids {
		// Check if this batch is ready for processing
		ballotCount := s.stg.CountVerifiedBallots([]byte(pid))
		timeSinceUpdate := time.Since(lastUpdate)

		// Skip if the batch is not ready
		if ballotCount < types.VotesPerBatch && timeSinceUpdate <= s.maxTimeWindow {
			continue
		}

		// Process the batch
		log.Debugw("batch ready for aggregation",
			"processID", fmt.Sprintf("%x", pid),
			"ballotCount", ballotCount,
			"timeSinceUpdate", timeSinceUpdate.String(),
			"maxTimeWindow", s.maxTimeWindow,
		)

		if err := s.aggregateBatch([]byte(pid)); err != nil {
			log.Warnw("failed to aggregate batch",
				"error", err.Error(),
				"processID", fmt.Sprintf("%x", pid),
			)
			continue
		}

		// Update the last update time
		s.pidsLock.Lock()
		s.pids[pid] = time.Now()
		s.pidsLock.Unlock()

		log.Infow("batch aggregated successfully", "processID", fmt.Sprintf("%x", pid))
	}
}

// aggregateBatch creates an aggregated zero-knowledge proof for a batch of verified ballots.
// It pulls verified ballots for the specified process ID, transforms them into a format
// suitable for the aggregator circuit, generates a proof, and stores the result.
//
// Parameters:
//   - pid: The process ID for which to aggregate ballots
//
// Returns an error if the aggregation process fails at any step.
func (s *Sequencer) aggregateBatch(pid types.HexBytes) error {
	if pid == nil || len(pid) == 0 {
		return fmt.Errorf("process ID cannot be empty")
	}

	// Pull verified ballots from storage
	ballots, keys, err := s.stg.PullVerifiedBallots(pid, types.VotesPerBatch)
	if err != nil {
		return fmt.Errorf("failed to pull verified ballots: %w", err)
	}

	if len(ballots) < 1 {
		log.Warnw("no ballots to aggregate", "processID", fmt.Sprintf("%x", pid))
		return nil
	}

	log.Debugw("aggregating ballots",
		"processID", fmt.Sprintf("%x", pid),
		"ballotCount", len(ballots),
	)

	// Prepare data structures for the aggregator circuit
	proofs := [types.VotesPerBatch]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	proofsInputHash := [types.VotesPerBatch]emulated.Element[sw_bn254.ScalarField]{}
	aggBallots := make([]*storage.AggregatorBallot, 0, len(ballots))

	// Transform each ballot's proof for the aggregator circuit
	for i := 0; i < len(ballots); i++ {
		var transformErr error
		proofs[i], transformErr = stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](ballots[i].Proof)
		if transformErr != nil {
			return fmt.Errorf("failed to transform proof for recursion (ballot %d): %w", i, transformErr)
		}

		proofsInputHash[i] = emulated.ValueOf[sw_bn254.ScalarField](ballots[i].InputsHash)
		aggBallots = append(aggBallots, &storage.AggregatorBallot{
			Nullifier:       ballots[i].Nullifier,
			Commitment:      ballots[i].Commitment,
			Address:         ballots[i].Address,
			EncryptedBallot: ballots[i].EncryptedBallot,
		})
	}

	// Create the aggregator circuit assignment
	assignment := aggregator.AggregatorCircuit{
		ValidProofs:        len(ballots),
		Proofs:             proofs,
		ProofsInputsHashes: proofsInputHash,
	}

	// Fill any remaining slots with dummy proofs if needed
	if len(ballots) < types.VotesPerBatch {
		if err := assignment.FillWithDummy(s.voteCcs, s.voteProvingKey, s.ballotVerifyingKeyCircomJSON, len(ballots)); err != nil {
			return fmt.Errorf("failed to fill with dummy proofs: %w", err)
		}
	}

	// Generate the aggregated proof
	witness, err := frontend.NewWitness(assignment, ecc.BW6_761.ScalarField())
	if err != nil {
		return fmt.Errorf("failed to create witness: %w", err)
	}

	proof, err := groth16.Prove(s.aggregateCcs, s.aggregateProvingKey, witness)
	if err != nil {
		return fmt.Errorf("failed to generate aggregate proof: %w", err)
	}

	// Store the aggregated batch
	abb := storage.AggregatorBallotBatch{
		ProcessID: pid,
		Proof:     proof,
		Ballots:   aggBallots,
	}

	if err := s.stg.PushBallotBatch(&abb); err != nil {
		return fmt.Errorf("failed to push ballot batch: %w", err)
	}

	// Mark the individual ballots as processed
	failedMarks := 0
	for _, k := range keys {
		if err := s.stg.MarkVerifiedBallotDone(k); err != nil {
			failedMarks++
			log.Warnw("failed to mark verified ballot as done",
				"error", err.Error(),
				"processID", fmt.Sprintf("%x", pid),
			)
		}
	}

	if failedMarks > 0 {
		log.Warnw("some ballots could not be marked as done",
			"failedCount", failedMarks,
			"totalCount", len(keys),
			"processID", fmt.Sprintf("%x", pid),
		)
	}

	log.Infow("batch aggregated successfully",
		"processID", fmt.Sprintf("%x", pid),
		"ballotCount", len(ballots),
	)

	return nil
}
