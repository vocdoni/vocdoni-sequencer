package processor

import (
	"context"

	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/voteverifier"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/storage"
	"github.com/vocdoni/vocdoni-z-sandbox/storage/census"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

type VoteProcessor struct {
	s      *storage.Storage
	ctx    context.Context
	cancel context.CancelFunc
}

// NewVoteProcessor creates a new VoteProcessor instance with the given storage
// instance.
func NewVoteProcessor(s *storage.Storage) *VoteProcessor {
	return &VoteProcessor{
		s: s,
	}
}

// Start method starts the vote processor. It will process ballots in the
// background. It iterates over the ballots available in the storage and
// generates proofs of the validity of the ballots, storing them back in the
// storage. It will stop processing ballots when the context is cancelled.
func (p *VoteProcessor) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)
	if err := voteverifier.Artifacts.LoadAll(); err != nil {
		return err
	}
	// run the verifier in background until its context is cancelled
	go func() {
		for {
			select {
			case <-p.ctx.Done():
				return
			default:
				// get the next ballot
				ballot, key, err := p.s.NextBallot()
				if err != nil {
					if err != storage.ErrNoMoreElements {
						log.Errorf("failed to get next ballot: %v", err)
					}
					continue
				}
				// process the ballot
				verifiedBallot, err := p.ProcessBallot(ballot)
				if err != nil {
					log.Errorf("failed to process ballot: %v", err)
					continue
				}
				// store the verified ballot
				if err := p.s.MarkBallotDone(key, verifiedBallot); err != nil {
					log.Errorf("failed to mark ballot done: %v", err)
				}
			}
		}
	}()
	return nil
}

// Stop method cancels the context of the vote processor, stopping the
// processing of ballots.
func (p *VoteProcessor) Stop() error {
	p.cancel()
	return nil
}

func (p *VoteProcessor) ProcessBallot(b *storage.Ballot) (*storage.VerifiedBallot, error) {
	// decode the process id
	pid := new(types.ProcessID)
	if err := pid.Unmarshal(b.ProcessID); err != nil {
		return nil, err
	}
	// get the process metadata
	process, err := p.s.Process(pid)
	if err != nil {
		return nil, err
	}
	// convert the process ballot mode to the circuit ballot mode format
	ballotMode := circuits.BallotModeToCircuit[emulated.Element[sw_bn254.ScalarField]](*process.BallotMode)
	// convert the encryption key to the circuit encryption key format
	encryptionKey := circuits.EncryptionKeyToCircuit[emulated.Element[sw_bn254.ScalarField]](*process.EncryptionKey)
	// unpack census proof siblings to big integers
	siblings, err := census.BigIntSiblings(b.CensusProof.Siblings)
	if err != nil {
		return nil, err
	}
	siblings = circuits.BigIntArrayToN(siblings, circuits.CensusProofMaxLevels)

	// proves the the ballot with the vote verifier circuit
	// if the ballot is valid return the proof inside the VerifiedBallot
	// if the ballot is invalid return an error
	return nil, nil
}
