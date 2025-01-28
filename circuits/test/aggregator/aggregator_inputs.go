package aggregatortest

import (
	"fmt"
	"math"
	"math/big"

	gecc "github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	voteverifiertest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/voteverifier"
)

// AggregateTestResults struct includes relevant data after AggregateCircuit
// inputs generation, including the encrypted ballots in both formats: matrix
// and plain (for hashing)
type AggregateTestResults struct {
	ProcessId             *big.Int
	CensusRoot            *big.Int
	EncryptionPubKey      [2]*big.Int
	Nullifiers            []*big.Int
	Commitments           []*big.Int
	Addresses             []*big.Int
	EncryptedBallots      [][ballottest.NFields][2][2]*big.Int
	PlainEncryptedBallots []*big.Int
}

// AggregarorInputsForTest returns the AggregateTestResults, the placeholder
// and the assigments of a AggregatorCircuit for the processId provided
// generating nValidVoters. If something fails it returns an error.
func AggregarorInputsForTest(processId []byte, nValidVoters int) (
	AggregateTestResults, aggregator.AggregatorCircuit, aggregator.AggregatorCircuit, error,
) {
	// generate users accounts and census
	vvData := []voteverifiertest.VoterTestData{}
	for i := 0; i < nValidVoters; i++ {
		privKey, pubKey, address, err := ballottest.GenECDSAaccountForTest()
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
		}
		vvData = append(vvData, voteverifiertest.VoterTestData{
			PrivKey: privKey,
			PubKey:  pubKey,
			Address: address,
		})
	}
	// generate vote verifier circuit and inputs
	vvInputs, vvPlaceholder, vvAssigments, err := voteverifiertest.VoteVerifierInputsForTest(vvData, processId)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// compile vote verifier circuit
	vvCCS, err := frontend.Compile(gecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &vvPlaceholder)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	vvPk, vvVk, err := groth16.Setup(vvCCS)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// generate voters proofs
	totalPlainEncryptedBallots := []*big.Int{}
	proofs := [aggregator.MaxVotes]circuits.InnerProofBLS12377{}
	for i := range vvAssigments {
		// flat encrypted ballots
		for _, b := range vvInputs.EncryptedBallots[i] {
			totalPlainEncryptedBallots = append(totalPlainEncryptedBallots, b[0][0], b[0][1], b[1][0], b[1][1])
		}
		// parse the witness to the circuit
		fullWitness, err := frontend.NewWitness(&vvAssigments[i], gecc.BLS12_377.ScalarField())
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
		}
		// generate the proof
		proof, err := groth16.Prove(vvCCS, vvPk, fullWitness, stdgroth16.GetNativeProverOptions(gecc.BW6_761.ScalarField(), gecc.BLS12_377.ScalarField()))
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("err proving proof %d: %w", i, err)
		}
		// convert the proof to the circuit proof type
		proofs[i].Proof, err = stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
		}
		// convert the public inputs to the circuit public inputs type
		publicWitness, err := fullWitness.Public()
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
		}
		err = groth16.Verify(proof, vvVk, publicWitness, stdgroth16.GetNativeVerifierOptions(gecc.BW6_761.ScalarField(), gecc.BLS12_377.ScalarField()))
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
		}
		proofs[i].Witness, err = stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](publicWitness)
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
		}
		// log.Println("original limbs", proofs[i].Witness.Public[0].Limbs)
		// fixedHash := emulated.ValueOf[sw_bn254.ScalarField](vvInputs.InputsHashes[i])
		// log.Println("fixed limbs", fixedHash.Limbs)
		// proofs[i].Witness.Public[0].Limbs = fixedHash.Limbs
	}
	// compute public inputs hash
	hashInputs := []*big.Int{
		vvInputs.ProcessID,
		vvInputs.CensusRoot,
		vvInputs.EncryptionPubKey[0],
		vvInputs.EncryptionPubKey[1],
		big.NewInt(int64(ballottest.MaxCount)),
		big.NewInt(int64(ballottest.ForceUniqueness)),
		big.NewInt(int64(ballottest.MaxValue)),
		big.NewInt(int64(ballottest.MinValue)),
		big.NewInt(int64(math.Pow(float64(ballottest.MaxValue), float64(ballottest.CostExp))) * int64(ballottest.MaxCount)),
		big.NewInt(int64(ballottest.MaxCount)),
		big.NewInt(int64(ballottest.CostExp)),
		big.NewInt(int64(ballottest.CostFromWeight)),
	}
	// pad voters inputs (nullifiers, commitments, addresses, plain EncryptedBallots)
	nullifiers := circuits.BigIntArrayToN(vvInputs.Nullifiers, aggregator.MaxVotes)
	commitments := circuits.BigIntArrayToN(vvInputs.Commitments, aggregator.MaxVotes)
	addresses := circuits.BigIntArrayToN(vvInputs.Addresses, aggregator.MaxVotes)
	plainEncryptedBallots := circuits.BigIntArrayToN(totalPlainEncryptedBallots, aggregator.MaxVotes*ballottest.NFields*4)
	// append voters inputs (nullifiers, commitments, addresses, plain EncryptedBallots)
	hashInputs = append(hashInputs, nullifiers...)
	hashInputs = append(hashInputs, commitments...)
	hashInputs = append(hashInputs, addresses...)
	hashInputs = append(hashInputs, plainEncryptedBallots...)
	// hash the inputs to generate the inputs hash
	inputsHash, err := mimc7.Hash(hashInputs, nil)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// init final assigments stuff
	finalAssigments := aggregator.AggregatorCircuit{
		InputsHash: inputsHash,
		ValidVotes: aggregator.EncodeProofsSelector(nValidVoters),
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
		Proofs:     proofs,
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
	// fix the vote verifier verification key
	fixedVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vvVk)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// create final placeholder
	finalPlaceholder := aggregator.AggregatorCircuit{
		Proofs:              [aggregator.MaxVotes]circuits.InnerProofBLS12377{},
		BaseVerificationKey: fixedVk,
	}
	// fill placeholder and witness with dummy circuits
	finalPlaceholder, finalAssigments, err = aggregator.FillWithDummyFixed(finalPlaceholder, finalAssigments, vvCCS, nValidVoters)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	return AggregateTestResults{
		ProcessId:             vvInputs.ProcessID,
		CensusRoot:            vvInputs.CensusRoot,
		EncryptionPubKey:      vvInputs.EncryptionPubKey,
		Nullifiers:            nullifiers,
		Commitments:           commitments,
		Addresses:             addresses,
		EncryptedBallots:      vvInputs.EncryptedBallots,
		PlainEncryptedBallots: plainEncryptedBallots,
	}, finalPlaceholder, finalAssigments, nil
}
