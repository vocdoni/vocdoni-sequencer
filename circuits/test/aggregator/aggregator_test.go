package aggregatortest

import (
	"log"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/dummy"
	bjj "github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
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

func TestDummyAggregation(t *testing.T) {
	c := qt.New(t)
	now := time.Now()

	dummyBigInt := big.NewInt(1)
	dummyValue := emulated.ValueOf[sw_bn254.ScalarField](dummyBigInt)
	dummyVotes := [circuits.VotesPerBatch]circuits.EmulatedVote[sw_bn254.ScalarField]{
		{
			Nullifier:  dummyValue,
			Commitment: dummyValue,
			Address:    dummyValue,
			Ballot:     *circuits.NewEmulatedBallot[sw_bn254.ScalarField](),
		},
	}
	commonInputs := []*big.Int{
		dummyBigInt, // processId
		dummyBigInt, // censusRoot
		dummyBigInt, // ballotMode.MaxCount
		dummyBigInt, // ballotMode.ForceUniqueness
		dummyBigInt, // ballotMode.MaxValue
		dummyBigInt, // ballotMode.MinValue
		dummyBigInt, // ballotMode.MaxTotalCost
		dummyBigInt, // ballotMode.MinTotalCost
		dummyBigInt, // ballotMode.CostExp
		dummyBigInt, // ballotMode.CostFromWeight
		dummyBigInt, // encryptionPubKey[0]
		dummyBigInt, // encryptionPubKey[1]

	}
	voterInputs := append(commonInputs,
		dummyBigInt, // addresses[0]
		dummyBigInt, // commitments[0]
		dummyBigInt, // nullifiers[0]
	)
	// append the dummy encrypted ballots for a single voter
	voterInputs = append(voterInputs, elgamal.NewBallot(new(bjj.BJJ)).BigInts()...)
	voterHash, err := mimc7.Hash(voterInputs, nil)
	c.Assert(err, qt.IsNil)
	votersHashes := []*big.Int{voterHash}
	for i := 1; i < circuits.VotesPerBatch; i++ {
		dummyVoterInputs := append(commonInputs,
			big.NewInt(0), // addresses[i]
			big.NewInt(0), // commitments[i]
			big.NewInt(0), // nullifiers[i]
		)
		dummyVoterInputs = append(dummyVoterInputs, elgamal.NewBallot(new(bjj.BJJ)).BigInts()...)
		dummyVoterHash, err := mimc7.Hash(dummyVoterInputs, nil)
		c.Assert(err, qt.IsNil)
		votersHashes = append(votersHashes, dummyVoterHash)
	}
	c.Assert(err, qt.IsNil)
	dummyInputsHash, err := mimc7.Hash(votersHashes, nil)
	c.Assert(err, qt.IsNil)

	ccs, pubWitness, proof, vk, err := dummy.Prove(dummy.PlaceholderWithConstraints(1), dummy.Assignment(voterHash),
		circuits.AggregatorCurve.ScalarField(), circuits.VoteVerifierCurve.ScalarField(), false)
	c.Assert(err, qt.IsNil)
	dummyVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
	c.Assert(err, qt.IsNil)
	dummyProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
	c.Assert(err, qt.IsNil)
	dummyWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](pubWitness)
	c.Assert(err, qt.IsNil)
	log.Println("dummy witness", dummyWitness)

	placeholder := aggregator.AggregatorCircuit{
		Proofs:              [circuits.VotesPerBatch]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{},
		BaseVerificationKey: dummyVk,
	}

	assignment := aggregator.AggregatorCircuit{
		InputsHash: emulated.ValueOf[sw_bn254.ScalarField](dummyInputsHash),
		ValidVotes: aggregator.EncodeProofsSelector(1),
		Process: circuits.Process[emulated.Element[sw_bn254.ScalarField]]{
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
			EncryptionKey: circuits.EncryptionKey[emulated.Element[sw_bn254.ScalarField]]{
				PubKey: [2]emulated.Element[sw_bn254.ScalarField]{dummyValue, dummyValue},
			},
			ID:         dummyValue,
			CensusRoot: dummyValue,
		},
		Votes: dummyVotes,
		Proofs: [circuits.VotesPerBatch]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{
			dummyProof,
		},
	}
	placeholder, assignment, err = aggregator.FillWithDummyFixed(placeholder, assignment, ccs, 1, false)
	c.Assert(err, qt.IsNil)

	c.Logf("inputs generation tooks %s", time.Since(now).String())
	// proving
	now = time.Now()
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&placeholder, &assignment,
		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
	c.Logf("proving tooks %s", time.Since(now).String())
}

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
