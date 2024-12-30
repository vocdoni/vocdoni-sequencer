package aggregator

import (
	"math"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	bw6761mimc "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/ballotproof"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

func TestAggregatorCircuit(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" {
		t.Skip("skipping circuit tests...")
	}
	c := qt.New(t)
	// inputs generation
	now := time.Now()
	processId := util.RandomBytes(20)
	_, placeholder, assigments, err := GenInputsForTest(processId, 3)
	c.Assert(err, qt.IsNil)
	c.Logf("inputs generation tooks %s", time.Since(now).String())
	// proving
	now = time.Now()
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(placeholder, assigments,
		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
	c.Logf("proving tooks %s", time.Since(now).String())
}

type testCheckInputsCircuit struct {
	InputsHash       frontend.Variable `gnark:",public"`
	MaxCount         frontend.Variable
	ForceUniqueness  frontend.Variable
	MaxValue         frontend.Variable
	MinValue         frontend.Variable
	MaxTotalCost     frontend.Variable
	MinTotalCost     frontend.Variable
	CostExp          frontend.Variable
	CostFromWeight   frontend.Variable
	EncryptionPubKey [2]frontend.Variable
	ProcessId        frontend.Variable
	CensusRoot       frontend.Variable
	Nullifiers       [MaxVotes]frontend.Variable
	Commitments      [MaxVotes]frontend.Variable
	Addresses        [MaxVotes]frontend.Variable
	EncryptedBallots [MaxVotes][MaxFields][2][2]frontend.Variable
}

func (c *testCheckInputsCircuit) Define(api frontend.API) error {
	return checkInputs(api, c.InputsHash, c.MaxCount, c.ForceUniqueness,
		c.MaxValue, c.MinValue, c.MaxTotalCost, c.MinTotalCost, c.CostExp,
		c.CostFromWeight, c.ProcessId, c.CensusRoot, c.EncryptionPubKey,
		c.Nullifiers[:], c.Commitments[:], c.Addresses[:], c.EncryptedBallots[:])
}

func TestCheckInputs(t *testing.T) {
	c := qt.New(t)

	processId := arbo.BigToFF(ecc.BW6_761.ScalarField(), new(big.Int).SetBytes(util.RandomBytes(20)))
	censusRoot := arbo.BigToFF(ecc.BW6_761.ScalarField(), new(big.Int).SetBytes(util.RandomBytes(20)))
	encryptionKey := ballotproof.GenEncryptionKeyForTest()
	encryptionKeyX, encryptionKeyY := encryptionKey.Point()
	// voter data
	_, _, address, err := ballotproof.GenECDSAaccountForTest()
	c.Assert(err, qt.IsNil)
	voterProofRes, err := ballotproof.MockVoterForTest(address.Bytes(), processId.Bytes(), encryptionKey)
	c.Assert(err, qt.IsNil)

	inputs := []*big.Int{
		big.NewInt(int64(ballotproof.MaxCount)),
		big.NewInt(int64(ballotproof.ForceUniqueness)),
		big.NewInt(int64(ballotproof.MaxValue)),
		big.NewInt(int64(ballotproof.MinValue)),
		big.NewInt(int64(math.Pow(float64(ballotproof.MaxValue), float64(ballotproof.CostExp))) * int64(ballotproof.MaxCount)),
		big.NewInt(int64(ballotproof.MaxCount)),
		big.NewInt(int64(ballotproof.CostExp)),
		big.NewInt(int64(ballotproof.CostFromWeight)),
		encryptionKeyX,
		encryptionKeyY,
		processId,
		censusRoot,
	}
	// prepare lists of inputs
	bAddresses := circuits.BigIntArrayToN([]*big.Int{new(big.Int).SetBytes(address.Bytes())}, MaxVotes)
	plainEncryptedBallots := []*big.Int{}
	for i := range voterProofRes.EncryptedFields {
		plainEncryptedBallots = append(plainEncryptedBallots, voterProofRes.EncryptedFields[i][0][0])
		plainEncryptedBallots = append(plainEncryptedBallots, voterProofRes.EncryptedFields[i][0][1])
		plainEncryptedBallots = append(plainEncryptedBallots, voterProofRes.EncryptedFields[i][1][0])
		plainEncryptedBallots = append(plainEncryptedBallots, voterProofRes.EncryptedFields[i][1][1])
	}
	// append the rest of the inputs
	nullifiers := circuits.BigIntArrayToN([]*big.Int{voterProofRes.Nullifier}, MaxVotes)
	inputs = append(inputs, nullifiers...)
	commitments := circuits.BigIntArrayToN([]*big.Int{voterProofRes.Commitment}, MaxVotes)
	inputs = append(inputs, commitments...)
	inputs = append(inputs, bAddresses...)
	inputs = append(inputs, circuits.BigIntArrayToN(plainEncryptedBallots, MaxVotes*MaxFields*4)...)
	// hash the inputs to generate the inputs hash
	var buf [fr_bw6761.Bytes]byte
	aggregatorHashFn := bw6761mimc.NewMiMC()
	for _, input := range inputs {
		input.FillBytes(buf[:])
		_, err := aggregatorHashFn.Write(buf[:])
		c.Assert(err, qt.IsNil)
	}
	publicHash := new(big.Int).SetBytes(aggregatorHashFn.Sum(nil))
	assigment := testCheckInputsCircuit{
		InputsHash:       publicHash,
		MaxCount:         ballotproof.MaxCount,
		ForceUniqueness:  ballotproof.ForceUniqueness,
		MaxValue:         ballotproof.MaxValue,
		MinValue:         ballotproof.MinValue,
		MaxTotalCost:     int(math.Pow(float64(ballotproof.MaxValue), float64(ballotproof.CostExp))) * ballotproof.MaxCount,
		MinTotalCost:     ballotproof.MaxCount,
		CostExp:          ballotproof.CostExp,
		CostFromWeight:   ballotproof.CostFromWeight,
		ProcessId:        processId,
		EncryptionPubKey: [2]frontend.Variable{encryptionKeyX, encryptionKeyY},
		CensusRoot:       censusRoot,
	}
	assigment.EncryptedBallots = [MaxVotes][MaxFields][2][2]frontend.Variable{}
	assigment.Nullifiers = [MaxVotes]frontend.Variable{}
	assigment.Commitments = [MaxVotes]frontend.Variable{}
	assigment.Addresses = [MaxVotes]frontend.Variable{}
	for i := 0; i < MaxVotes; i++ {
		assigment.Nullifiers[i] = nullifiers[i]
		assigment.Commitments[i] = commitments[i]
		assigment.Addresses[i] = bAddresses[i]
		if i == 0 {
			for j := range voterProofRes.EncryptedFields {
				assigment.EncryptedBallots[0][j][0][0] = voterProofRes.EncryptedFields[j][0][0]
				assigment.EncryptedBallots[0][j][0][1] = voterProofRes.EncryptedFields[j][0][1]
				assigment.EncryptedBallots[0][j][1][0] = voterProofRes.EncryptedFields[j][1][0]
				assigment.EncryptedBallots[0][j][1][1] = voterProofRes.EncryptedFields[j][1][1]
			}
		} else {
			assigment.EncryptedBallots[i] = [MaxFields][2][2]frontend.Variable{}
			for j := range voterProofRes.EncryptedFields {
				assigment.EncryptedBallots[i][j] = [2][2]frontend.Variable{{0, 0}, {0, 0}}
			}
		}
	}

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testCheckInputsCircuit{}, &assigment,
		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
}
