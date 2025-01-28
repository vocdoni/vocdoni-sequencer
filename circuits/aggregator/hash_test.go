package aggregator

import (
	"log"
	"math"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/vocdoni/gnark-crypto-primitives/emulated/bn254/twistededwards/mimc7"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/util"

	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	voteverifiertest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/voteverifier"
)

type innerHashesCircuit struct {
	circuits.BallotMode[emulated.Element[sw_bn254.ScalarField]]
	// Other common inputs
	EncryptionPubKey [2]emulated.Element[sw_bn254.ScalarField] // Part of InputsHash
	ProcessId        emulated.Element[sw_bn254.ScalarField]    // Part of InputsHash
	CensusRoot       emulated.Element[sw_bn254.ScalarField]    // Part of InputsHash
	// Voter inputs
	Nullifiers       [MaxVotes]emulated.Element[sw_bn254.ScalarField]                  // Part of InputsHash
	Commitments      [MaxVotes]emulated.Element[sw_bn254.ScalarField]                  // Part of InputsHash
	Addresses        [MaxVotes]emulated.Element[sw_bn254.ScalarField]                  // Part of InputsHash
	EncryptedBallots [MaxVotes][MaxFields][2][2]emulated.Element[sw_bn254.ScalarField] // Part of InputsHash
}

func (c innerHashesCircuit) Define(api frontend.API) error {
	hashFn, err := mimc7.NewMiMC(api)
	if err != nil {
		return err
	}
	// group common inputs
	commonInputs := []emulated.Element[sw_bn254.ScalarField]{
		c.ProcessId, c.CensusRoot, c.EncryptionPubKey[0], c.EncryptionPubKey[1]}
	commonInputs = append(commonInputs, c.BallotMode.List()...)
	// iterate over each voter inputs to group the remaining ones and calculate
	// every voter hash
	for i := 0; i < MaxVotes; i++ {
		// group remaining inputs
		remainingInputs := []emulated.Element[sw_bn254.ScalarField]{c.Addresses[i], c.Nullifiers[i], c.Commitments[i]}
		for j := 0; j < MaxFields; j++ {
			remainingInputs = append(remainingInputs, c.EncryptedBallots[i][j][0][0])
			remainingInputs = append(remainingInputs, c.EncryptedBallots[i][j][0][1])
			remainingInputs = append(remainingInputs, c.EncryptedBallots[i][j][1][0])
			remainingInputs = append(remainingInputs, c.EncryptedBallots[i][j][1][1])
		}
		// calculate the hash
		hashFn.Write(commonInputs...)
		hashFn.Write(remainingInputs...)
		resultHash := hashFn.Sum()
		for _, limb := range resultHash.Limbs {
			api.Println("raw hash limb", limb)
		}
		calculatedHash, err := utils.PackScalarToVar(api, resultHash)
		if err != nil {
			return err
		}
		api.Println("packed hash", calculatedHash)
		hashFn.Reset()
	}
	return nil
}

func TestInnerHashesCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	const nValidVoters = 3
	processId := util.RandomBytes(20)

	// generate users accounts and census
	vvData := []voteverifiertest.VoterTestData{}
	for i := 0; i < nValidVoters; i++ {
		privKey, pubKey, address, err := ballottest.GenECDSAaccountForTest()
		assert.NoError(err)
		vvData = append(vvData, voteverifiertest.VoterTestData{
			PrivKey: privKey,
			PubKey:  pubKey,
			Address: address,
		})
	}
	// generate vote verifier circuit and inputs
	vvInputs, _, vvAssigments, err := voteverifiertest.VoteVerifierInputsForTest(vvData, processId)
	assert.NoError(err)

	for i := range vvAssigments {
		// parse the witness to the circuit
		fullWitness, err := frontend.NewWitness(&vvAssigments[i], ecc.BLS12_377.ScalarField())
		assert.NoError(err)

		// convert the public inputs to the circuit public inputs type
		publicWitness, err := fullWitness.Public()
		assert.NoError(err)

		// proofs[i].Witness, err = aggregator.EmulatedValueOfWitness[sw_bls12377.ScalarField](publicWitness, vvInputs.InputsHashes[i])
		// if err != nil {
		// 	return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
		// }
		finalWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](publicWitness)
		assert.NoError(err)
		log.Println("emulated limbs", finalWitness.Public[0].Limbs)
		log.Println("expected hash", vvInputs.InputsHashes[i])
	}
	// init final assigments stuff
	finalAssigments := innerHashesCircuit{
		BallotMode: circuits.BallotMode[emulated.Element[sw_bn254.ScalarField]]{
			MaxCount:        emulated.ValueOf[sw_bn254.ScalarField](ballottest.MaxCount),
			ForceUniqueness: emulated.ValueOf[sw_bn254.ScalarField](ballottest.ForceUniqueness),
			MaxValue:        emulated.ValueOf[sw_bn254.ScalarField](ballottest.MaxValue),
			MinValue:        emulated.ValueOf[sw_bn254.ScalarField](ballottest.MinValue),
			MaxTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](int(math.Pow(float64(ballottest.MaxValue), float64(ballottest.CostExp))) * ballottest.MaxCount),
			MinTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](ballottest.MaxCount),
			CostExp:         emulated.ValueOf[sw_bn254.ScalarField](ballottest.CostExp),
			CostFromWeight:  emulated.ValueOf[sw_bn254.ScalarField](ballottest.CostFromWeight),
		},
		EncryptionPubKey: [2]emulated.Element[sw_bn254.ScalarField]{
			emulated.ValueOf[sw_bn254.ScalarField](vvInputs.EncryptionPubKey[0]),
			emulated.ValueOf[sw_bn254.ScalarField](vvInputs.EncryptionPubKey[1]),
		},
		ProcessId:  emulated.ValueOf[sw_bn254.ScalarField](vvInputs.ProcessID),
		CensusRoot: emulated.ValueOf[sw_bn254.ScalarField](vvInputs.CensusRoot),
	}
	// set voters final witness stuff
	for i := 0; i < nValidVoters; i++ {
		finalAssigments.Nullifiers[i] = emulated.ValueOf[sw_bn254.ScalarField](vvInputs.Nullifiers[i])
		finalAssigments.Commitments[i] = emulated.ValueOf[sw_bn254.ScalarField](vvInputs.Commitments[i])
		finalAssigments.Addresses[i] = emulated.ValueOf[sw_bn254.ScalarField](vvInputs.Addresses[i])
		for j := 0; j < ballottest.NFields; j++ {
			for n := 0; n < 2; n++ {
				for m := 0; m < 2; m++ {
					finalAssigments.EncryptedBallots[i][j][n][m] = emulated.ValueOf[sw_bn254.ScalarField](vvInputs.EncryptedBallots[i][j][n][m])
				}
			}
		}
	}

	assert.SolvingSucceeded(&innerHashesCircuit{}, &finalAssigments,
		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
}
