package processor

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

// AddProcessID adds a process ID to the processor. Only those ballots which
// belong to the process IDs added to the processor will be processed.
// If the process ID is already added, it will be ignored.
func (p *Processor) AddProcessID(pid []byte) {
	p.pidsLock.Lock()
	defer p.pidsLock.Unlock()
	if _, ok := p.pids[string(pid)]; ok {
		return
	}
	p.pids[string(pid)] = time.Now()
}

// DelProcessID removes a process ID from the processor. If the
// process ID is not present, it will be ignored.
func (p *Processor) DelProcessID(pid []byte) {
	p.pidsLock.Lock()
	defer p.pidsLock.Unlock()
	delete(p.pids, string(pid))
}

// startAggregateProcessor starts the aggregate processor.
func (p *Processor) startAggregateProcessor() error {
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
				log.Debugw("new batch to aggregate", "processID", pid, "lastUpdate", lastUpdate.String())
				if err := p.aggregateBatch([]byte(pid)); err != nil {
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

func (p *Processor) aggregateBatch(pid types.HexBytes) error {
	ballots, keys, err := p.stg.PullVerifiedBallots(pid, types.VotesPerBatch)
	if err != nil {
		return fmt.Errorf("failed to pull verified ballots: %w", err)
	}
	if len(ballots) < 1 {
		log.Warnw("no ballots to process", "processID", pid)
		return nil
	}

	proofs := [types.VotesPerBatch]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	proofsInputHash := [types.VotesPerBatch]emulated.Element[sw_bn254.ScalarField]{}
	aggBallots := []*storage.AggregatorBallot{}
	for i := 0; i < len(ballots); i++ {
		proofs[i], err = stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](ballots[i].Proof)
		if err != nil {
			return fmt.Errorf("failed to transform proof for recursion: %w", err)
		}
		proofsInputHash[i] = emulated.ValueOf[sw_bn254.ScalarField](ballots[i].InputsHash)
		aggBallots = append(aggBallots, &storage.AggregatorBallot{
			Nullifier:       ballots[i].Nullifier,
			Commitment:      ballots[i].Commitment,
			Address:         ballots[i].Address,
			EncryptedBallot: ballots[i].EncryptedBallot,
		})

	}

	// final assignments
	assignment := aggregator.AggregatorCircuit{
		ValidProofs:        len(ballots),
		Proofs:             proofs,
		ProofsInputsHashes: proofsInputHash,
	}

	// fill the remaining empty ballot slots with dummy proofs
	if len(ballots) < types.VotesPerBatch {
		if err := assignment.FillWithDummy(p.voteCcs, p.voteProvingKey, p.ballotVerifyingKeyCircomJSON, len(ballots)); err != nil {
			return fmt.Errorf("failed to fill with dummy proofs: %w", err)
		}
	}

	// calculate the witness with the assignment
	witness, err := frontend.NewWitness(assignment, ecc.BW6_761.ScalarField())
	if err != nil {
		return fmt.Errorf("failed to create witness: %w", err)
	}
	// generate the final proof
	proof, err := groth16.Prove(p.aggregateCcs, p.aggregateProvingKey, witness)
	if err != nil {
		return fmt.Errorf("failed to generate aggregate proof: %w", err)
	}

	// push the proof to the storage
	abb := storage.AggregatorBallotBatch{
		ProcessID: pid,
		Proof:     proof,
		Ballots:   aggBallots,
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
