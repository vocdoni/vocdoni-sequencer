package statetransitiontest

import (
	"bytes"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/statetransition"
	aggregatortest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/aggregator"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/state"
	"go.vocdoni.io/dvote/db/metadb"
)

// StateTransitionTestResults struct includes relevant data after StateTransitionCircuit
// inputs generation
type StateTransitionTestResults struct {
	ProcessId             []byte
	CensusRoot            *big.Int
	EncryptionPubKey      [2]*big.Int
	Nullifiers            []*big.Int
	Commitments           []*big.Int
	Addresses             []*big.Int
	EncryptedBallots      [][ballottest.NFields][2][2]*big.Int
	PlainEncryptedBallots []*big.Int
}

// StateTransitionInputsForTest returns the StateTransitionTestResults, the placeholder
// and the assigments of a StateTransitionCircuit for the processId provided
// generating nValidVoters. If something fails it returns an error.
func StateTransitionInputsForTest(processId []byte, nValidVoters int) (
	*StateTransitionTestResults, *statetransition.Circuit, *statetransition.Circuit, error,
) {
	// generate aggregator circuit and inputs
	agInputs, agPlaceholder, agWitness, err := aggregatortest.AggregarorInputsForTest(processId, nValidVoters)
	if err != nil {
		return nil, nil, nil, err
	}
	// compile aggregoar circuit
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
	proofInBLS12377, err := stdgroth16.ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](proof)
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
	agPublicInputs, err := stdgroth16.ValueOfWitness[sw_bw6761.ScalarField](publicWitness)
	if err != nil {
		return nil, nil, nil, err
	}

	// pad voters inputs (nullifiers, commitments, addresses, plain EncryptedBallots)
	nullifiers := circuits.BigIntArrayToN(agInputs.Nullifiers, aggregator.MaxVotes)
	commitments := circuits.BigIntArrayToN(agInputs.Commitments, aggregator.MaxVotes)
	addresses := circuits.BigIntArrayToN(agInputs.Addresses, aggregator.MaxVotes)
	plainEncryptedBallots := circuits.BigIntArrayToN(agInputs.PlainEncryptedBallots, aggregator.MaxVotes*ballottest.NFields*4)

	// init final assigments stuff
	s := newState(
		processId,
		agInputs.CensusRoot.Bytes(),
		ballotMode().Bytes(),
		pubkeyToBytes(agInputs.EncryptionPubKey))

	if err := s.StartBatch(); err != nil {
		return nil, nil, nil, err
	}
	for i := range agInputs.EncryptedBallots {
		if err := s.AddVote(&state.Vote{
			Nullifier:  arbo.BigIntToBytes(32, agInputs.Nullifiers[i]),
			Ballot:     toBallot(agInputs.EncryptedBallots[i]),
			Address:    arbo.BigIntToBytes(32, agInputs.Addresses[i]),
			Commitment: agInputs.Commitments[i],
		}); err != nil {
			return nil, nil, nil, err
		}
	}
	witness, err := GenerateWitnesses(s)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := s.EndBatch(); err != nil {
		return nil, nil, nil, err
	}

	witness.AggregatedProof.Proof = proofInBLS12377
	witness.AggregatedProof.Witness = agPublicInputs

	// create final placeholder
	circuitPlaceholder := statetransition.CircuitPlaceholder()
	// fix the vote verifier verification key
	fixedVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](agVk)
	if err != nil {
		return nil, nil, nil, err
	}
	circuitPlaceholder.AggregatedProof.VK = fixedVk
	// // fill placeholder and witness with dummy circuits
	// if err := aggregator.FillWithDummyFixed(finalPlaceholder, finalAssigments, agCCS, nValidVoters); err != nil {
	// 	return nil, nil, nil, err
	// }
	return &StateTransitionTestResults{
		ProcessId:             agInputs.ProcessId,
		CensusRoot:            agInputs.CensusRoot,
		EncryptionPubKey:      agInputs.EncryptionPubKey,
		Nullifiers:            nullifiers,
		Commitments:           commitments,
		Addresses:             addresses,
		EncryptedBallots:      agInputs.EncryptedBallots,
		PlainEncryptedBallots: plainEncryptedBallots,
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

func toBallot(x [8][2][2]*big.Int) *elgamal.Ciphertexts {
	z := elgamal.NewCiphertexts(state.Curve)
	for i := range x {
		z[i].C1.SetPoint(x[i][0][0], x[i][0][1])
		z[i].C2.SetPoint(x[i][1][0], x[i][1][1])
	}
	return z
}

func pubkeyToBytes(pubkey [2]*big.Int) []byte {
	buf := bytes.Buffer{}
	buf.Write(arbo.BigIntToBytes(32, pubkey[0]))
	buf.Write(arbo.BigIntToBytes(32, pubkey[1]))
	return buf.Bytes()
}