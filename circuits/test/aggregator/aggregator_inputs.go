package aggregatortest

import (
	"fmt"
	"math"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	bw6761mimc "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	voteverifiertest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/voteverifier"
)

// AggregateTestResults struct includes relevant data after AggregateCircuit
// inputs generation, including the encrypted ballots in both formats: matrix
// and plain (for hashing)
type AggregateTestResults struct {
	ProcessId             []byte
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
	*AggregateTestResults, *aggregator.AggregatorCircuit, *aggregator.AggregatorCircuit, error,
) {
	// generate users accounts and census
	vvData := []voteverifiertest.VoterTestData{}
	for i := 0; i < nValidVoters; i++ {
		privKey, pubKey, address, err := ballottest.GenECDSAaccountForTest()
		if err != nil {
			return nil, nil, nil, err
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
		return nil, nil, nil, err
	}
	// compile vote verifier circuit
	vvCCS, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &vvPlaceholder)
	if err != nil {
		return nil, nil, nil, err
	}
	vvPk, vvVk, err := groth16.Setup(vvCCS)
	if err != nil {
		return nil, nil, nil, err
	}
	// generate voters proofs
	totalPlainEncryptedBallots := []*big.Int{}
	proofs := [aggregator.MaxVotes]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	pubInputs := [aggregator.MaxVotes]stdgroth16.Witness[emparams.BLS12377Fr]{}
	for i := range vvAssigments {
		// flat encrypted ballots
		for _, b := range vvInputs.EncryptedBallots[i] {
			totalPlainEncryptedBallots = append(totalPlainEncryptedBallots, b[0][0], b[0][1], b[1][0], b[1][1])
		}
		// parse the witness to the circuit
		fullWitness, err := frontend.NewWitness(&vvAssigments[i], ecc.BLS12_377.ScalarField())
		if err != nil {
			return nil, nil, nil, err
		}
		// generate the proof
		proof, err := groth16.Prove(vvCCS, vvPk, fullWitness, stdgroth16.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("err proving proof %d: %w", i, err)
		}
		// convert the proof to the circuit proof type
		proofs[i], err = stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
		if err != nil {
			return nil, nil, nil, err
		}
		// convert the public inputs to the circuit public inputs type
		publicWitness, err := fullWitness.Public()
		if err != nil {
			return nil, nil, nil, err
		}
		err = groth16.Verify(proof, vvVk, publicWitness, stdgroth16.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
		if err != nil {
			return nil, nil, nil, err
		}
		pubInputs[i], err = stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](publicWitness)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	// compute public inputs hash
	inputs := []*big.Int{
		big.NewInt(int64(ballottest.MaxCount)),
		big.NewInt(int64(ballottest.ForceUniqueness)),
		big.NewInt(int64(ballottest.MaxValue)),
		big.NewInt(int64(ballottest.MinValue)),
		big.NewInt(int64(math.Pow(float64(ballottest.MaxValue), float64(ballottest.CostExp))) * int64(ballottest.MaxCount)),
		big.NewInt(int64(ballottest.MaxCount)),
		big.NewInt(int64(ballottest.CostExp)),
		big.NewInt(int64(ballottest.CostFromWeight)),
		vvInputs.EncryptionPubKey[0],
		vvInputs.EncryptionPubKey[1],
		new(big.Int).SetBytes(vvInputs.ProcessID),
		vvInputs.CensusRoot,
	}
	// pad voters inputs (nullifiers, commitments, addresses, plain EncryptedBallots)
	nullifiers := circuits.BigIntArrayToN(vvInputs.Nullifiers, aggregator.MaxVotes)
	commitments := circuits.BigIntArrayToN(vvInputs.Commitments, aggregator.MaxVotes)
	bigAddresses := []*big.Int{}
	for _, d := range vvData {
		bigAddresses = append(bigAddresses, new(big.Int).SetBytes(d.Address.Bytes()))
	}
	addresses := circuits.BigIntArrayToN(bigAddresses, aggregator.MaxVotes)
	plainEncryptedBallots := circuits.BigIntArrayToN(totalPlainEncryptedBallots, aggregator.MaxVotes*ballottest.NFields*4)
	// append voters inputs (nullifiers, commitments, addresses, plain EncryptedBallots)
	inputs = append(inputs, nullifiers...)
	inputs = append(inputs, commitments...)
	inputs = append(inputs, addresses...)
	inputs = append(inputs, plainEncryptedBallots...)
	// hash the inputs to generate the inputs hash
	var buf [fr_bw6761.Bytes]byte
	aggregatorHashFn := bw6761mimc.NewMiMC()
	for _, input := range inputs {
		input.FillBytes(buf[:])
		_, err := aggregatorHashFn.Write(buf[:])
		if err != nil {
			return nil, nil, nil, err
		}
	}
	publicHash := new(big.Int).SetBytes(aggregatorHashFn.Sum(nil))
	// init final assigments stuff
	finalAssigments := &aggregator.AggregatorCircuit{
		InputsHash:         publicHash,
		ValidVotes:         aggregator.EncodeProofsSelector(nValidVoters),
		MaxCount:           ballottest.MaxCount,
		ForceUniqueness:    ballottest.ForceUniqueness,
		MaxValue:           ballottest.MaxValue,
		MinValue:           ballottest.MinValue,
		MaxTotalCost:       int(math.Pow(float64(ballottest.MaxValue), float64(ballottest.CostExp))) * ballottest.MaxCount,
		MinTotalCost:       ballottest.MaxCount,
		CostExp:            ballottest.CostExp,
		CostFromWeight:     ballottest.CostFromWeight,
		EncryptionPubKey:   [2]frontend.Variable{vvInputs.EncryptionPubKey[0], vvInputs.EncryptionPubKey[1]},
		ProcessId:          new(big.Int).SetBytes(vvInputs.ProcessID),
		CensusRoot:         vvInputs.CensusRoot,
		VerifyProofs:       proofs,
		VerifyPublicInputs: pubInputs,
	}
	// set voters final witness stuff
	for i := 0; i < nValidVoters; i++ {
		finalAssigments.Nullifiers[i] = vvInputs.Nullifiers[i]
		finalAssigments.Commitments[i] = vvInputs.Commitments[i]
		finalAssigments.Addresses[i] = new(big.Int).SetBytes(vvData[i].Address.Bytes())
		for j := 0; j < ballottest.NFields; j++ {
			for n := 0; n < 2; n++ {
				for m := 0; m < 2; m++ {
					finalAssigments.EncryptedBallots[i][j][n][m] = vvInputs.EncryptedBallots[i][j][n][m]
				}
			}
		}
	}
	// create final placeholder
	finalPlaceholder := &aggregator.AggregatorCircuit{
		VerifyPublicInputs: [aggregator.MaxVotes]stdgroth16.Witness[sw_bls12377.ScalarField]{},
		VerifyProofs:       [aggregator.MaxVotes]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{},
		VerificationKeys:   [2]stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{},
	}
	// fix the vote verifier verification key
	fixedVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vvVk)
	if err != nil {
		return nil, nil, nil, err
	}
	finalPlaceholder.VerificationKeys[1] = fixedVk
	// set the vote verififer proofs and pubInputa
	for i := 0; i < nValidVoters; i++ {
		finalPlaceholder.VerifyPublicInputs[i] = stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](vvCCS)
		finalPlaceholder.VerifyProofs[i] = stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](vvCCS)
	}
	// fill placeholder and witness with dummy circuits
	if err := aggregator.FillWithDummyFixed(finalPlaceholder, finalAssigments, vvCCS, nValidVoters); err != nil {
		return nil, nil, nil, err
	}
	return &AggregateTestResults{
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
