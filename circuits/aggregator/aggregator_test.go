package aggregator

import (
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	bw6761mimc "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	gtest "github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

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
	encryptionKey := ballottest.GenEncryptionKeyForTest()
	encryptionKeyX, encryptionKeyY := encryptionKey.Point()
	// voter data
	_, _, address, err := ballottest.GenECDSAaccountForTest()
	c.Assert(err, qt.IsNil)
	voterProofRes, err := ballottest.BallotProofForTest(address.Bytes(), processId.Bytes(), encryptionKey)
	c.Assert(err, qt.IsNil)

	inputs := []*big.Int{
		big.NewInt(int64(ballottest.MaxCount)),
		big.NewInt(int64(ballottest.ForceUniqueness)),
		big.NewInt(int64(ballottest.MaxValue)),
		big.NewInt(int64(ballottest.MinValue)),
		big.NewInt(int64(math.Pow(float64(ballottest.MaxValue), float64(ballottest.CostExp))) * int64(ballottest.MaxCount)),
		big.NewInt(int64(ballottest.MaxCount)),
		big.NewInt(int64(ballottest.CostExp)),
		big.NewInt(int64(ballottest.CostFromWeight)),
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
		MaxCount:         ballottest.MaxCount,
		ForceUniqueness:  ballottest.ForceUniqueness,
		MaxValue:         ballottest.MaxValue,
		MinValue:         ballottest.MinValue,
		MaxTotalCost:     int(math.Pow(float64(ballottest.MaxValue), float64(ballottest.CostExp))) * ballottest.MaxCount,
		MinTotalCost:     ballottest.MaxCount,
		CostExp:          ballottest.CostExp,
		CostFromWeight:   ballottest.CostFromWeight,
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

	assert := gtest.NewAssert(t)
	assert.SolvingSucceeded(&testCheckInputsCircuit{}, &assigment,
		gtest.WithCurves(ecc.BW6_761), gtest.WithBackends(backend.GROTH16),
		gtest.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
}
