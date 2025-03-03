package processor

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/storage"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// AggregateProcessor is a processor that takes verified ballots and aggregates	them into a single proof.
type AggregateProcessor struct {
	stg      *storage.Storage
	ctx      context.Context
	cancel   context.CancelFunc
	pids     map[string]time.Time
	pidsLock sync.RWMutex

	//maxTimeWindow is the maximum time window to wait for a batch to be processed.
	maxTimeWindow time.Duration
}

// NewAggregateProcessor creates a new aggregate processor.
func NewAggregateProcessor(stg *storage.Storage, batchTimeWindow time.Duration) *AggregateProcessor {
	return &AggregateProcessor{
		stg:           stg,
		maxTimeWindow: batchTimeWindow,
		pids:          make(map[string]time.Time),
	}
}

// AddProcessID adds a process ID to the processor. Only those ballots which
// belong to the process IDs added to the processor will be processed.
// If the process ID is already added, it will be ignored.
func (p *AggregateProcessor) AddProcessID(pid []byte) {
	p.pidsLock.Lock()
	defer p.pidsLock.Unlock()
	if _, ok := p.pids[string(pid)]; ok {
		return
	}
	p.pids[string(pid)] = time.Now()
}

// DelProcessID removes a process ID from the processor.
func (p *AggregateProcessor) DelProcessID(pid []byte) {
	p.pidsLock.Lock()
	defer p.pidsLock.Unlock()
	delete(p.pids, string(pid))
}

// Start method starts the processor.
func (p *AggregateProcessor) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)
	ticker := time.NewTicker(time.Second * 10)

	go func() {
		defer ticker.Stop()
		for {
			// copy pids to avoid locking the map for too long
			p.pidsLock.RLock()
			pids := make(map[string]time.Time, len(p.pids))
			for k, v := range p.pids {
				pids[k] = v
			}
			p.pidsLock.RUnlock()
			// iterate over the process IDs and process the ones that are ready
			for pid, lastUpdate := range pids {
				switch {
				case p.stg.CountVerifiedBallots([]byte(pid)) >= types.VotesPerBatch:
				case time.Since(lastUpdate) > p.maxTimeWindow:
				default:
					continue
				}
				log.Debugw("new batch to process", "processID", pid, "lastUpdate", lastUpdate.String())
				if err := p.ProcessBatch([]byte(pid)); err != nil {
					log.Errorw(err, "failed to process batch")
					continue
				}
				// update the last update time
				p.pidsLock.Lock()
				p.pids[string(pid)] = time.Now()
				p.pidsLock.Unlock()
			}

			// wait for the ticker or the context to be canceled
			select {
			case <-ticker.C:
				continue
			case <-p.ctx.Done():
				return
			}
		}
	}()
	return nil
}

// Stop method cancels the context of the vote processor, stopping the
// processing of ballots.
func (p *AggregateProcessor) Stop() error {
	p.cancel()
	return nil
}

func (p *AggregateProcessor) ProcessBatch(pid types.HexBytes) error {
	// get process metadata
	/*	process, err := p.stg.Process(new(types.ProcessID).SetBytes(pid))
		if err != nil {
			return fmt.Errorf("failed to get process metadata: %w", err)
		}
	*/

	ballots, keys, err := p.stg.PullVerifiedBallots(pid, types.VotesPerBatch)
	if err != nil {
		return fmt.Errorf("failed to pull verified ballots: %w", err)
	}
	if len(ballots) < 1 {
		log.Warnw("no ballots to process", "processID", pid)
		return nil
	}

	// get the shared parameters from the process description
	/*	processID := crypto.BigToFF(circuits.BallotProofCurve.ScalarField(), pid.BigInt().MathBigInt())
		censusRoot := arbo.BytesToBigInt(process.Census.CensusRoot)
		ballotMode := circuits.BallotModeToCircuit(*process.BallotMode)
		encryptionKey := circuits.EncryptionKeyToCircuit(*process.EncryptionKey)
	*/
	// construct the proof array and the inputs hash
	proofs := [types.VotesPerBatch]groth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	hashInputs := []*big.Int{}
	for i := 0; i < len(ballots); i++ {
		proofs[i], err = groth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](ballots[i].Proof)
		if err != nil {
			return fmt.Errorf("failed to transform proof for recursion: %w", err)
		}
		hashInputs = append(hashInputs, ballots[i].InputsHash)
	}

	// compute the inputs hash
	/*	inputsHash, err := mimc7.Hash(hashInputs, nil)
		if err != nil {
			return fmt.Errorf("failed to hash inputs: %w", err)
		}
	*/
	// final assignments
	assignment := aggregator.AggregatorCircuit{
		Proofs:      proofs,
		ValidProofs: len(proofs),
	}
	//assignment.FillWithDummy()

	// generate the zkSnark proof
	proof, err := assignment.Prove()
	if err != nil {
		return fmt.Errorf("failed to generate aggregate proof: %w", err)
	}

	// push the proof to the storage
	abb := storage.AggregatorBallotBatch{
		ProcessID: pid,
		Proof:     proof,
		Ballots:   nil, // TODO
	}

	if err := p.stg.PushBallotBatch(&abb); err != nil {
		return fmt.Errorf("failed to push ballot batch: %w", err)
	}

	// mark the ballots as done
	for _, k := range keys {
		if err := p.stg.MarkVerifiedBallotDone(k); err != nil {
			log.Errorw(err, fmt.Sprintf("failed to mark verified ballot as done for process %x", pid))
		}
	}
	return nil
}
