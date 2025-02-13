package aggregatortest

import (
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark/backend"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

func TestAggregatorCircuit(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	c := qt.New(t)
	// inputs generation
	now := time.Now()
	processId := util.RandomBytes(20)
	_, placeholder, assignments, err := AggregatorInputsForTest(processId, 3, false)
	c.Assert(err, qt.IsNil)
	c.Logf("inputs generation tooks %s", time.Since(now).String())
	// proving
	now = time.Now()
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&placeholder, &assignments,
		test.WithCurves(circuits.AggregatorCurve), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(stdgroth16.GetNativeProverOptions(
			circuits.StateTransitionCurve.ScalarField(),
			circuits.AggregatorCurve.ScalarField())))
	c.Logf("proving tooks %s", time.Since(now).String())
}

/*
TODO: Fix and refactor this test

func TestDummyAggregation(t *testing.T) {
	c := qt.New(t)
	now := time.Now()
	circomPlaceholder, err := circuits.Circom2GnarkPlaceholder(ballottest.TestCircomVerificationKey)
	c.Assert(err, qt.IsNil)
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &voteverifier.VerifyVoteCircuit{
		CircomVerificationKey:  circomPlaceholder.Vk,
		CircomProof:            circomPlaceholder.Proof,
		CircomPublicInputsHash: circomPlaceholder.Witness,
	})
	c.Assert(err, qt.IsNil)
	_, dummyVk, dummyProof, _, err := aggregator.RecursiveDummy(ccs, false)
	c.Assert(err, qt.IsNil)

	dummyBigInt := arbo.BigToFF(ecc.BN254.ScalarField(), new(big.Int).SetBytes(util.RandomBytes(20)))
	dummyValue := emulated.ValueOf[sw_bn254.ScalarField](dummyBigInt)
	dummy10Inputs := [aggregator.MaxVotes]emulated.Element[sw_bn254.ScalarField]{
		dummyValue, dummyValue, dummyValue, dummyValue, dummyValue,
		dummyValue, dummyValue, dummyValue, dummyValue, dummyValue,
	}
	dummyFields := [aggregator.MaxVotes][ballottest.NFields][2][2]emulated.Element[sw_bn254.ScalarField]{}
	for i := 0; i < aggregator.MaxVotes; i++ {
		for j := 0; j < ballottest.NFields; j++ {
			dummyFields[i][j] = [2][2]emulated.Element[sw_bn254.ScalarField]{
				{dummyValue, dummyValue},
				{dummyValue, dummyValue},
			}
		}
	}
	dummyProofs := [aggregator.MaxVotes]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{
		dummyProof, dummyProof, dummyProof, dummyProof, dummyProof,
		dummyProof, dummyProof, dummyProof, dummyProof, dummyProof,
	}
	dummyProofSlot := stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](ccs)
	dymmyProofSlots := [aggregator.MaxVotes]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{
		dummyProofSlot, dummyProofSlot, dummyProofSlot, dummyProofSlot, dummyProofSlot,
		dummyProofSlot, dummyProofSlot, dummyProofSlot, dummyProofSlot, dummyProofSlot,
	}

	dummyVoterHash := []*big.Int{
		// common inputs
		dummyBigInt, // processId
		dummyBigInt, // censusRoot
		dummyBigInt, // encryptionPubKey[0]
		dummyBigInt, // encryptionPubKey[1]
		dummyBigInt, // ballotMode.MaxCount
		dummyBigInt, // ballotMode.ForceUniqueness
		dummyBigInt, // ballotMode.MaxValue
		dummyBigInt, // ballotMode.MinValue
		dummyBigInt, // ballotMode.MaxTotalCost
		dummyBigInt, // ballotMode.MinTotalCost
		dummyBigInt, // ballotMode.CostExp
		dummyBigInt, // ballotMode.CostFromWeight
		// voter inputs
		dummyBigInt, // addresses[i]
		dummyBigInt, // nullifiers[i]
		dummyBigInt, // commitments[i]
	}
	// append the dummy encrypted ballots for a single voter
	for i := 0; i < aggregator.MaxFields*2*2; i++ {
		dummyVoterHash = append(dummyVoterHash, dummyBigInt)
	}
	voterHash, err := mimc7.Hash(dummyVoterHash, nil)
	c.Assert(err, qt.IsNil)
	log.Println("voter hash", voterHash)
	votersHashes := []*big.Int{}
	for i := 0; i < aggregator.MaxVotes; i++ {
		votersHashes = append(votersHashes, voterHash)
	}
	c.Assert(err, qt.IsNil)
	dummyInputsHash, err := mimc7.Hash(votersHashes, nil)
	c.Assert(err, qt.IsNil)
	log.Println("inputs hash", dummyInputsHash)
	placeholder := aggregator.AggregatorCircuit{
		BaseVerificationKey:  dummyVk,
		DummyVerificationKey: dummyVk,
		Proofs:               dymmyProofSlots,
	}
	assignments := aggregator.AggregatorCircuit{
		InputsHash: emulated.ValueOf[sw_bn254.ScalarField](dummyInputsHash),
		ValidVotes: aggregator.EncodeProofsSelector(0),
		BallotMode: circuits.BallotMode[emulated.Element[sw_bn254.ScalarField]]{
			MaxCount:        dummyValue,
			ForceUniqueness: dummyValue,
			MaxValue:        dummyValue,
			MinValue:        dummyValue,
			MaxTotalCost:    dummyValue,
			MinTotalCost:    dummyValue,
			CostExp:         dummyValue,
			CostFromWeight:  dummyValue,
		},
		EncryptionPubKey: [2]emulated.Element[sw_bn254.ScalarField]{
			dummyValue,
			dummyValue,
		},
		ProcessId:        dummyValue,
		CensusRoot:       dummyValue,
		Nullifiers:       dummy10Inputs,
		Commitments:      dummy10Inputs,
		Addresses:        dummy10Inputs,
		EncryptedBallots: dummyFields,
		Proofs:           dummyProofs,
	}
	c.Logf("inputs generation tooks %s", time.Since(now).String())
	// proving
	now = time.Now()
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&placeholder, &assignments,
		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
	c.Logf("proving tooks %s", time.Since(now).String())
}
*/

// TODO: uncomment this block when the LocalInputsForTest function is fixed
// func TestLocalAggregatorCircuit(t *testing.T) {
// 	c := qt.New(t)
// 	// inputs generation
// 	now := time.Now()
// 	_, placeholder, assignments, err := LocalInputsForTest(3)
// 	c.Assert(err, qt.IsNil)
// 	c.Logf("inputs generation tooks %s", time.Since(now).String())
// 	// proving
// 	now = time.Now()
// 	assert := test.NewAssert(t)
// 	assert.SolvingSucceeded(&placeholder, &assignments,
// 		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
// 		test.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
// 	c.Logf("proving tooks %s", time.Since(now).String())
// }
