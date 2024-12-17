package aggregator

import (
	"fmt"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	bw6761mimc "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	circomtest "github.com/vocdoni/vocdoni-z-sandbox/circuits/circom"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/voteverifier"
)

const nVotes = 3

func TestAggregatorCircuit(t *testing.T) {
	c := qt.New(t)
	now := time.Now()
	// generate users accounts and census
	vvData := []voteverifier.VoterData{}
	for i := 0; i < nVotes; i++ {
		privKey, pubKey, address, err := circomtest.GenerateECDSAaccount()
		c.Assert(err, qt.IsNil)
		vvData = append(vvData, voteverifier.VoterData{
			PrivKey: privKey,
			PubKey:  pubKey,
			Address: address,
		})
	}
	vvInputs, vvPlaceholder, vvAssigments, err := voteverifier.GenerateInputs(vvData)
	c.Assert(err, qt.IsNil)

	// ###############################################################
	fmt.Println("\ninputs generation tooks", time.Since(now).String()+"\n")
	now = time.Now()
	// ###############################################################

	// compile vote verifier circuit
	vvCCS, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &vvPlaceholder)
	c.Assert(err, qt.IsNil)
	vvPk, vvVk, err := groth16.Setup(vvCCS)
	c.Assert(err, qt.IsNil)
	fixedVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vvVk)
	c.Assert(err, qt.IsNil)
	// generate voters proofs
	totalPlainCipherfields := []*big.Int{}
	proofs := [MaxVotes]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	pubInputs := [MaxVotes]stdgroth16.Witness[emparams.BLS12377Fr]{}
	for i := range vvAssigments {
		// flat encrypted ballots
		for _, b := range vvInputs.EncryptedBallots[i] {
			totalPlainCipherfields = append(totalPlainCipherfields, b[0][0], b[0][1], b[1][0], b[1][1])
		}
		// parse the witness to the circuit
		fullWitness, err := frontend.NewWitness(&vvAssigments[i], ecc.BLS12_377.ScalarField())
		c.Assert(err, qt.IsNil)
		// generate the proof
		proof, err := groth16.Prove(vvCCS, vvPk, fullWitness, stdgroth16.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
		c.Assert(err, qt.IsNil, qt.Commentf("proof %d", i))
		// convert the proof to the circuit proof type
		proofs[i], err = stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
		c.Assert(err, qt.IsNil)
		// convert the public inputs to the circuit public inputs type
		publicWitness, err := fullWitness.Public()
		c.Assert(err, qt.IsNil)
		err = groth16.Verify(proof, vvVk, publicWitness, stdgroth16.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
		c.Assert(err, qt.IsNil)
		pubInputs[i], err = stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](publicWitness)
		c.Assert(err, qt.IsNil)
	}
	c.Assert(totalPlainCipherfields, qt.HasLen, nVotes*MaxFields*4)

	// ###############################################################
	fmt.Println("\ninner proofs generation tooks", time.Since(now).String()+"\n")
	now = time.Now()
	// ###############################################################

	// compute public inputs hash
	inputs := []*big.Int{
		big.NewInt(int64(circomtest.MaxCount)),
		big.NewInt(int64(circomtest.ForceUniqueness)),
		big.NewInt(int64(circomtest.MaxValue)),
		big.NewInt(int64(circomtest.MinValue)),
		big.NewInt(int64(math.Pow(float64(circomtest.MaxValue), float64(circomtest.CostExp))) * int64(circomtest.MaxCount)),
		big.NewInt(int64(circomtest.MaxCount)),
		big.NewInt(int64(circomtest.CostExp)),
		big.NewInt(int64(circomtest.CostFromWeight)),
		vvInputs.EncryptionPubKey[0],
		vvInputs.EncryptionPubKey[1],
		new(big.Int).SetBytes(vvInputs.ProcessID),
		vvInputs.CensusRoot,
	}
	// append voters inputs (nullifiers, commitments, addresses, encrypted ballots)
	inputs = append(inputs, fillToN(vvInputs.Nullifiers, MaxVotes)...)
	inputs = append(inputs, fillToN(vvInputs.Commitments, MaxVotes)...)
	bigAddresses := []*big.Int{}
	for _, d := range vvData {
		bigAddresses = append(bigAddresses, new(big.Int).SetBytes(d.Address.Bytes()))
	}
	inputs = append(inputs, fillToN(bigAddresses, MaxVotes)...)
	inputs = append(inputs, fillToN(totalPlainCipherfields, MaxVotes*MaxFields*4)...)
	// hash the inputs to generate the inputs hash
	var buf [fr_bw6761.Bytes]byte
	aggregatorHashFn := bw6761mimc.NewMiMC()
	for _, input := range inputs {
		input.FillBytes(buf[:])
		_, err := aggregatorHashFn.Write(buf[:])
		c.Assert(err, qt.IsNil)
	}
	publicHash := new(big.Int).SetBytes(aggregatorHashFn.Sum(nil))
	// init fixed witness stuff
	witness := AggregatorCircuit{
		InputsHash:         publicHash,
		ValidVotes:         NBits(nVotes),
		MaxCount:           circomtest.MaxCount,
		ForceUniqueness:    circomtest.ForceUniqueness,
		MaxValue:           circomtest.MaxValue,
		MinValue:           circomtest.MinValue,
		MaxTotalCost:       int(math.Pow(float64(circomtest.MaxValue), float64(circomtest.CostExp))) * circomtest.MaxCount,
		MinTotalCost:       circomtest.MaxCount,
		CostExp:            circomtest.CostExp,
		CostFromWeight:     circomtest.CostFromWeight,
		EncryptionPubKey:   [2]frontend.Variable{vvInputs.EncryptionPubKey[0], vvInputs.EncryptionPubKey[1]},
		ProcessId:          new(big.Int).SetBytes(vvInputs.ProcessID),
		CensusRoot:         vvInputs.CensusRoot,
		VerifyProofs:       proofs,
		VerifyPublicInputs: pubInputs,
	}
	// set voters witness stuff
	for i := 0; i < nVotes; i++ {
		witness.Nullifiers[i] = vvInputs.Nullifiers[i]
		witness.Commitments[i] = vvInputs.Commitments[i]
		witness.Addresses[i] = new(big.Int).SetBytes(vvData[i].Address.Bytes())
		for j := 0; j < MaxFields; j++ {
			for n := 0; n < 2; n++ {
				for m := 0; m < 2; m++ {
					witness.EncryptedBallots[i][j][n][m] = vvInputs.EncryptedBallots[i][j][n][m]
				}
			}
		}
	}
	// fill empty votes
	finalWitness, dummyCCS, dummyVk, err := fillWithDummyValues(witness, vvCCS, nVotes)
	c.Assert(err, qt.IsNil)
	// generate circuit placeholder stuff
	finalPlaceholder := AggregatorCircuit{
		VerifyPublicInputs: [MaxVotes]stdgroth16.Witness[sw_bls12377.ScalarField]{},
		VerifyProofs:       [MaxVotes]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{},
		VerificationKeys:   [2]stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{dummyVk, fixedVk},
	}
	for i := 0; i < MaxVotes; i++ {
		if i < nVotes {
			finalPlaceholder.VerifyPublicInputs[i] = stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](vvCCS)
			finalPlaceholder.VerifyProofs[i] = stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](vvCCS)
		} else {
			finalPlaceholder.VerifyPublicInputs[i] = stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](dummyCCS)
			finalPlaceholder.VerifyProofs[i] = stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyCCS)
		}
	}

	// ###############################################################
	fmt.Println("\nfinal inputs generation tooks", time.Since(now).String()+"\n")
	now = time.Now()
	// ###############################################################

	// generate proof
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&finalPlaceholder, &finalWitness,
		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))

	// ###############################################################
	fmt.Println("\nproving tooks", time.Since(now).String()+"\n")
}
