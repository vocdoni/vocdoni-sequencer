package processor

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/voteverifier"
	"github.com/vocdoni/vocdoni-z-sandbox/storage"
)

// Processor is a worker that takes verified ballots and aggregates	them into a single proof.
type Processor struct {
	stg      *storage.Storage
	ctx      context.Context
	cancel   context.CancelFunc
	pids     map[string]time.Time
	pidsLock sync.RWMutex

	ballotVerifyingKeyCircomJSON []byte // TODO

	aggregateProvingKey groth16.ProvingKey
	aggregateCcs        constraint.ConstraintSystem

	voteProvingKey groth16.ProvingKey
	voteCcs        constraint.ConstraintSystem

	//maxTimeWindow is the maximum time window to wait for a batch to be processed.
	maxTimeWindow time.Duration
}

// New creates a ballot processor, aggregator and state builder.
func New(stg *storage.Storage, batchTimeWindow time.Duration) (*Processor, error) {
	// Prepare voteverify artifacts
	vvArtifacts := voteverifier.Artifacts
	if err := vvArtifacts.LoadAll(); err != nil {
		return nil, fmt.Errorf("failed to load vote verifier artifacts: %w", err)
	}

	// decode the circuit definition
	voteCcs := groth16.NewCS(ecc.BLS12_377)
	if _, err := voteCcs.ReadFrom(bytes.NewReader(vvArtifacts.CircuitDefinition())); err != nil {
		return nil, fmt.Errorf("failed to read vote verifier definition: %w", err)
	}

	// decode the proving key
	votePk := groth16.NewProvingKey(ecc.BLS12_377)
	if _, err := votePk.ReadFrom(bytes.NewReader(vvArtifacts.ProvingKey())); err != nil {
		return nil, fmt.Errorf("failed to read vote verifier proving key: %w", err)
	}

	// Preapre aggregator artifacts
	aggArtifacts := aggregator.Artifacts
	if err := aggArtifacts.LoadAll(); err != nil {
		return nil, fmt.Errorf("failed to load aggregator artifacts: %w", err)
	}

	// decode the circuit definition
	aggCcs := groth16.NewCS(ecc.BW6_761)
	if _, err := aggCcs.ReadFrom(bytes.NewReader(aggArtifacts.CircuitDefinition())); err != nil {
		return nil, fmt.Errorf("failed to read vote verifier definition: %w", err)
	}

	// decode the proving key
	aggPk := groth16.NewProvingKey(ecc.BW6_761)
	if _, err := aggPk.ReadFrom(bytes.NewReader(aggArtifacts.ProvingKey())); err != nil {
		return nil, fmt.Errorf("failed to read vote verifier proving key: %w", err)
	}

	return &Processor{
		stg:                          stg,
		maxTimeWindow:                batchTimeWindow,
		pids:                         make(map[string]time.Time),
		ballotVerifyingKeyCircomJSON: ballottest.TestCircomVerificationKey, // TODO: replace with a proper VK path
		aggregateProvingKey:          aggPk,
		aggregateCcs:                 aggCcs,
		voteProvingKey:               votePk,
		voteCcs:                      voteCcs,
	}, nil
}

// Start method starts the ballot and aggregate processors.
func (p *Processor) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)
	if err := p.startBallotProcessor(); err != nil {
		return fmt.Errorf("failed to start ballot processor: %w", err)
	}
	if err := p.startAggregateProcessor(); err != nil {
		return fmt.Errorf("failed to start aggregate processor: %w", err)
	}
	return nil
}

// Stop method cancels the context of the vote processor, stopping the
// processing of ballots.
func (p *Processor) Stop() error {
	p.cancel()
	return nil
}
