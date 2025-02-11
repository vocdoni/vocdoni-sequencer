package statetransitiontest

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/statetransition"
	aggregatortest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/aggregator"
	"github.com/vocdoni/vocdoni-z-sandbox/state"
	"go.vocdoni.io/dvote/db/metadb"
)

// StateTransitionTestResults struct includes relevant data after StateTransitionCircuit
// inputs generation
type StateTransitionTestResults struct {
	Process circuits.Process[*big.Int]
	Votes   []state.Vote
}

// StateTransitionInputsForTest returns the StateTransitionTestResults, the placeholder
// and the assignments of a StateTransitionCircuit for the processId provided
// generating nValidVoters. If something fails it returns an error.
func StateTransitionInputsForTest(processId []byte, nValidVoters int) (
	*StateTransitionTestResults, *statetransition.Circuit, *statetransition.Circuit, error,
) {
	// generate aggregator circuit and inputs
	agInputs, agPlaceholder, agWitness, err := aggregatortest.AggregatorInputsForTest(processId, nValidVoters, false)
	if err != nil {
		return nil, nil, nil, err
	}
	// compile aggregator circuit
	agCCS, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, agPlaceholder)
	if err != nil {
		return nil, nil, nil, err
	}
	agPk, agVk, err := groth16.Setup(agCCS)
	if err != nil {
		return nil, nil, nil, err
	}
	// parse the witness to the circuit
	fullWitness, err := frontend.NewWitness(agWitness, ecc.BLS12_377.ScalarField())
	if err != nil {
		return nil, nil, nil, err
	}
	// generate the proof
	proof, err := groth16.Prove(agCCS, agPk, fullWitness, stdgroth16.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("err proving proof: %w", err)
	}
	// convert the proof to the circuit proof type
	proofInBW6761, err := stdgroth16.ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](proof)
	if err != nil {
		return nil, nil, nil, err
	}
	// convert the public inputs to the circuit public inputs type
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return nil, nil, nil, err
	}
	err = groth16.Verify(proof, agVk, publicWitness, stdgroth16.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	if err != nil {
		return nil, nil, nil, err
	}

	// init final assignments stuff
	s := newState(
		agInputs.Process.ID.Bytes(),
		agInputs.Process.CensusRoot.Bytes(),
		circuits.MockBallotMode().Bytes(),
		agInputs.Process.EncryptionKey.Bytes())

	if err := s.StartBatch(); err != nil {
		return nil, nil, nil, err
	}
	for _, v := range agInputs.Votes {
		if err := s.AddVote(&v); err != nil {
			return nil, nil, nil, err
		}
	}
	if err := s.EndBatch(); err != nil {
		return nil, nil, nil, err
	}
	witness, err := GenerateWitnesses(s)
	if err != nil {
		return nil, nil, nil, err
	}
	witness.AggregatorProof.Proof = proofInBW6761

	// create final placeholder
	circuitPlaceholder := statetransition.CircuitPlaceholder()
	// fix the vote verifier verification key
	fixedVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](agVk)
	if err != nil {
		return nil, nil, nil, err
	}
	circuitPlaceholder.AggregatorProof.VK = fixedVk
	// // fill placeholder and witness with dummy circuits
	// if err := aggregator.FillWithDummyFixed(finalPlaceholder, finalAssigments, agCCS, nValidVoters); err != nil {
	// 	return nil, nil, nil, err
	// }
	return &StateTransitionTestResults{
		Process: agInputs.Process,
		Votes:   agInputs.Votes,
	}, circuitPlaceholder, witness, nil
}

func newState(processId, censusRoot, ballotMode, encryptionKey []byte) *state.State {
	dir, err := os.MkdirTemp(os.TempDir(), "statetransition")
	if err != nil {
		panic(err)
	}
	db, err := metadb.New("pebble", dir)
	if err != nil {
		panic(err)
	}
	s, err := state.New(db, processId)
	if err != nil {
		panic(err)
	}

	if err := s.Initialize(
		censusRoot,
		ballotMode,
		encryptionKey,
	); err != nil {
		panic(err)
	}

	return s
}
