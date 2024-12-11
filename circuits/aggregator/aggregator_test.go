package aggregator

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377mimc "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	bw6761mimc "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	gecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/vocdoni/arbo"
	ptest "github.com/vocdoni/gnark-crypto-primitives/testutil"
	ztest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/voteverifier"
	"github.com/vocdoni/vocdoni-z-sandbox/encrypt"
	"go.vocdoni.io/dvote/util"
)

const (
	nVotes  = 1
	nLevels = 160
)

func TestAggregatorCircuit(t *testing.T) {
	c := qt.New(t)
	// compile ballot verifier circuit
	ballotVerifierPlaceholder, err := ztest.Circom2GnarkPlaceholder()
	c.Assert(err, qt.IsNil)
	// compile vote verifier circuit
	voteVerifierPlaceholder := &voteverifier.VerifyVoteCircuit{
		CircomProof:            ballotVerifierPlaceholder.Proof,
		CircomPublicInputsHash: ballotVerifierPlaceholder.Witness,
		CircomVerificationKey:  ballotVerifierPlaceholder.Vk,
	}
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, voteVerifierPlaceholder)
	c.Assert(err, qt.IsNil)
	pk, vk, err := groth16.Setup(ccs)
	c.Assert(err, qt.IsNil)
	fixedVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
	c.Assert(err, qt.IsNil)
	// common process id
	processID := util.RandomBytes(20)
	// generate encryption key and user nonce k
	encryptionKey := ztest.GenerateEncryptionTestKey()
	encryptionKeyX, encryptionKeyY := encryptionKey.Point()
	// generate structs to store voters inputs
	var (
		addresses        [MaxVotes][]byte
		nullifiers       [MaxVotes]*big.Int
		commitments      [MaxVotes]*big.Int
		encryptedBallots [MaxVotes][][][]string
		proofs           [MaxVotes]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
		pubInputs        [MaxVotes]stdgroth16.Witness[sw_bls12377.ScalarField]
	)
	// generate users accounts and census
	privKeys, pubKeys, weights := []*ecdsa.PrivateKey{}, []ecdsa.PublicKey{}, [][]byte{}
	for i := 0; i < MaxVotes; i++ {
		if i < nVotes {
			// generate voter account
			privKey, pubKey, address, err := ztest.GenerateECDSAaccount()
			c.Assert(err, qt.IsNil)
			privKeys = append(privKeys, privKey)
			pubKeys = append(pubKeys, pubKey)
			weights = append(weights, new(big.Int).SetInt64(ztest.Weight).Bytes())
			addresses[i] = address.Bytes()
		} else {
			weights = append(weights, big.NewInt(0).Bytes())
			addresses[i] = big.NewInt(0).Bytes()
		}
	}
	// generate a test census proof
	testCensus, err := ptest.GenerateCensusProofForTest(ptest.CensusTestConfig{
		Dir:           "../assets/census",
		ValidSiblings: 10,
		TotalSiblings: ztest.NLevels,
		KeyLen:        20,
		Hash:          arbo.HashFunctionMiMC_BLS12_377,
		BaseFiled:     arbo.BLS12377BaseField,
	}, addresses[:nVotes], weights[:nVotes])
	c.Assert(err, qt.IsNil)
	// generate voters inputs values and proofs
	totalPlainCipherfields := []*big.Int{}
	for i := 0; i < nVotes; i++ {
		// generate random ballot fields values
		fields := ztest.GenerateBallotFields(ztest.MaxCount, ztest.MaxValue, ztest.MinValue, ztest.ForceUniqueness > 0)
		// generate voter nonce k
		k, err := encrypt.RandK()
		c.Assert(err, qt.IsNil)
		// encrypt the ballots fields
		cipherfields, plainCipherfields := ztest.CipherBallotFields(fields, MaxFields, encryptionKey, k)
		encryptedBallots[i] = cipherfields
		totalPlainCipherfields = append(totalPlainCipherfields, plainCipherfields...)
		// generate user commitment and nullifier
		secret := util.RandomBytes(16)
		commitment, nullifier, err := ztest.MockedCommitmentAndNullifier(addresses[i], processID, secret)
		c.Assert(err, qt.IsNil)
		nullifiers[i] = nullifier
		commitments[i] = commitment
		// group the circom inputs to hash
		bigCircomInputs := []*big.Int{
			big.NewInt(int64(ztest.MaxCount)),
			big.NewInt(int64(ztest.ForceUniqueness)),
			big.NewInt(int64(ztest.MaxValue)),
			big.NewInt(int64(ztest.MinValue)),
			big.NewInt(int64(math.Pow(float64(ztest.MaxValue), float64(ztest.CostExp))) * int64(ztest.MaxCount)),
			big.NewInt(int64(ztest.MaxCount)),
			big.NewInt(int64(ztest.CostExp)),
			big.NewInt(int64(ztest.CostFromWeight)),
			arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(addresses[i])),
			big.NewInt(int64(ztest.Weight)),
			arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(processID)),
			encryptionKeyX,
			encryptionKeyY,
			nullifier,
			commitment,
		}
		bigCircomInputs = append(bigCircomInputs, plainCipherfields...)
		// hash the inputs
		circomInputsHash, err := mimc7.Hash(bigCircomInputs, nil)
		c.Assert(err, qt.IsNil)
		// init circom inputs
		circomInputs := map[string]any{
			"fields":           ztest.BigIntArrayToStringArray(fields, MaxFields),
			"max_count":        fmt.Sprint(ztest.MaxCount),
			"force_uniqueness": fmt.Sprint(ztest.ForceUniqueness),
			"max_value":        fmt.Sprint(ztest.MaxValue),
			"min_value":        fmt.Sprint(ztest.MinValue),
			"max_total_cost":   fmt.Sprint(int(math.Pow(float64(ztest.MaxValue), float64(ztest.CostExp))) * ztest.MaxCount),
			"min_total_cost":   fmt.Sprint(ztest.MaxCount),
			"cost_exp":         fmt.Sprint(ztest.CostExp),
			"cost_from_weight": fmt.Sprint(ztest.CostFromWeight),
			"address":          arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(addresses[i])).String(),
			"weight":           fmt.Sprint(ztest.Weight),
			"process_id":       arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(processID)).String(),
			"pk":               []string{encryptionKeyX.String(), encryptionKeyY.String()},
			"k":                k.String(),
			"cipherfields":     cipherfields,
			"nullifier":        nullifier.String(),
			"commitment":       commitment.String(),
			"secret":           arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(secret)).String(),
			"inputs_hash":      circomInputsHash.String(),
		}
		bCircomInputs, err := json.Marshal(circomInputs)
		c.Assert(err, qt.IsNil)
		// create the proof
		circomProof, err := ztest.Circom2GnarkProof(bCircomInputs)
		c.Assert(err, qt.IsNil)
		// transform cipherfields to gnark frontend.Variable
		emulatedBallots := [MaxFields][2][2]emulated.Element[sw_bn254.ScalarField]{}
		for i, c := range cipherfields {
			emulatedBallots[i] = [2][2]emulated.Element[sw_bn254.ScalarField]{
				{
					emulated.ValueOf[sw_bn254.ScalarField](c[0][0]),
					emulated.ValueOf[sw_bn254.ScalarField](c[0][1]),
				},
				{
					emulated.ValueOf[sw_bn254.ScalarField](c[1][0]),
					emulated.ValueOf[sw_bn254.ScalarField](c[1][1]),
				},
			}
		}
		// transform the inputs hash to the field of the curve used by the circuit,
		// if it is not done, the circuit will transform it during witness
		// calculation and the hash will be different
		// the resulting hash should have 32 bytes so if it does'nt, fill with 0s
		blsCircomInputsHash := arbo.BigToFF(ecc.BLS12_377.ScalarField(), circomInputsHash)
		if b := blsCircomInputsHash.Bytes(); len(b) < 32 {
			for len(b) < 32 {
				b = append(b, 0)
			}
			blsCircomInputsHash.SetBytes(b)
		}
		// sign the inputs hash with the private key
		rSign, sSign, err := ztest.SignECDSA(privKeys[i], blsCircomInputsHash.Bytes())
		c.Assert(err, qt.IsNil)
		// transform siblings to gnark frontend.Variable
		fSiblings := [ztest.NLevels]frontend.Variable{}
		for i, s := range testCensus.Proofs[0].Siblings {
			fSiblings[i] = frontend.Variable(s)
		}
		// hash the inputs of gnark circuit (circom inputs hash + census root)
		verifyHashFn := bls12377mimc.NewMiMC()
		verifyHashFn.Write(blsCircomInputsHash.Bytes())
		verifyHashFn.Write(testCensus.Root.Bytes())
		verifyInputsHash := new(big.Int).SetBytes(verifyHashFn.Sum(nil))
		// init inputs
		witness := &voteverifier.VerifyVoteCircuit{
			InputsHash: verifyInputsHash,
			// circom inputs
			MaxCount:        emulated.ValueOf[sw_bn254.ScalarField](ztest.MaxCount),
			ForceUniqueness: emulated.ValueOf[sw_bn254.ScalarField](ztest.ForceUniqueness),
			MaxValue:        emulated.ValueOf[sw_bn254.ScalarField](ztest.MaxValue),
			MinValue:        emulated.ValueOf[sw_bn254.ScalarField](ztest.MinValue),
			MaxTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](int(math.Pow(float64(ztest.MaxValue), float64(ztest.CostExp))) * ztest.MaxCount),
			MinTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](ztest.MaxCount),
			CostExp:         emulated.ValueOf[sw_bn254.ScalarField](ztest.CostExp),
			CostFromWeight:  emulated.ValueOf[sw_bn254.ScalarField](ztest.CostFromWeight),
			Address:         emulated.ValueOf[sw_bn254.ScalarField](new(big.Int).SetBytes(addresses[i])),
			UserWeight:      emulated.ValueOf[sw_bn254.ScalarField](ztest.Weight),
			EncryptionPubKey: [2]emulated.Element[sw_bn254.ScalarField]{
				emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyX),
				emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyY),
			},
			Nullifier:       emulated.ValueOf[sw_bn254.ScalarField](nullifier),
			Commitment:      emulated.ValueOf[sw_bn254.ScalarField](commitment),
			ProcessId:       emulated.ValueOf[sw_bn254.ScalarField](arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(processID))),
			EncryptedBallot: emulatedBallots,
			// census proof
			CensusRoot:     testCensus.Root,
			CensusSiblings: fSiblings,
			// signature
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](blsCircomInputsHash),
			PublicKey: gecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](pubKeys[i].X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](pubKeys[i].Y),
			},
			Signature: gecdsa.Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](rSign),
				S: emulated.ValueOf[emulated.Secp256k1Fr](sSign),
			},
			// circom proof
			CircomProof:            circomProof.Proof,
			CircomPublicInputsHash: circomProof.PublicInputs,
		}
		// parse the witness to the circuit
		fullWitness, err := frontend.NewWitness(witness, ecc.BLS12_377.ScalarField())
		c.Assert(err, qt.IsNil)
		// generate the proof
		proof, err := groth16.Prove(ccs, pk, fullWitness, stdgroth16.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
		c.Assert(err, qt.IsNil)
		// convert the proof to the circuit proof type
		proofs[i], err = stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
		c.Assert(err, qt.IsNil)
		// convert the public inputs to the circuit public inputs type
		publicWitness, err := fullWitness.Public()
		c.Assert(err, qt.IsNil)
		err = groth16.Verify(proof, vk, publicWitness, stdgroth16.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
		c.Assert(err, qt.IsNil)
		pubInputs[i], err = stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](publicWitness)
		c.Assert(err, qt.IsNil)
	}
	c.Assert(totalPlainCipherfields, qt.HasLen, nVotes*MaxFields*4)
	// compute public inputs hash
	inputs := []*big.Int{
		big.NewInt(int64(ztest.MaxCount)),
		big.NewInt(int64(ztest.ForceUniqueness)),
		big.NewInt(int64(ztest.MaxValue)),
		big.NewInt(int64(ztest.MinValue)),
		big.NewInt(int64(math.Pow(float64(ztest.MaxValue), float64(ztest.CostExp))) * int64(ztest.MaxCount)),
		big.NewInt(int64(ztest.MaxCount)),
		big.NewInt(int64(ztest.CostExp)),
		big.NewInt(int64(ztest.CostFromWeight)),
		encryptionKeyX,
		encryptionKeyY,
		new(big.Int).SetBytes(processID),
		testCensus.Root,
	}
	// append voters inputs (nullifiers, commitments, addresses, encrypted ballots)
	inputs = append(inputs, fillToN(nullifiers[:], MaxVotes)...)
	inputs = append(inputs, fillToN(commitments[:], MaxVotes)...)
	bigAddresses := []*big.Int{}
	for _, address := range addresses {
		bigAddresses = append(bigAddresses, new(big.Int).SetBytes(address))
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
	finalWitness := AggregatorCircuit{
		InputsHash:         publicHash,
		ValidVotes:         nVotes,
		ValidVotesBin:      NBits(nVotes),
		MaxCount:           ztest.MaxCount,
		ForceUniqueness:    ztest.ForceUniqueness,
		MaxValue:           ztest.MaxValue,
		MinValue:           ztest.MinValue,
		MaxTotalCost:       int(math.Pow(float64(ztest.MaxValue), float64(ztest.CostExp))) * ztest.MaxCount,
		MinTotalCost:       ztest.MaxCount,
		CostExp:            ztest.CostExp,
		CostFromWeight:     ztest.CostFromWeight,
		EncryptionPubKey:   [2]frontend.Variable{encryptionKeyX, encryptionKeyY},
		ProcessId:          new(big.Int).SetBytes(processID),
		CensusRoot:         testCensus.Root,
		VerifyProofs:       proofs,
		VerifyPublicInputs: pubInputs,
	}
	// set voters witness stuff
	for i := 0; i < nVotes; i++ {
		finalWitness.Nullifiers[i] = nullifiers[i]
		finalWitness.Commitments[i] = commitments[i]
		finalWitness.Addresses[i] = new(big.Int).SetBytes(addresses[i])
		for j := 0; j < MaxFields; j++ {
			for n := 0; n < 2; n++ {
				for m := 0; m < 2; m++ {
					finalWitness.EncryptedBallots[i][j][n][m], _ = new(big.Int).SetString(encryptedBallots[i][j][n][m], 10)
				}
			}
		}
	}
	// fill empty votes
	finalWitness, dummyCCS, dummyVk, err := fillWithDummyValues(finalWitness, nVotes)
	c.Assert(err, qt.IsNil)
	// generate circuit placeholder stuff
	finalPlaceholder := AggregatorCircuit{
		VerifyProofs:       [MaxVotes]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{},
		VerifyPublicInputs: [MaxVotes]stdgroth16.Witness[sw_bls12377.ScalarField]{},
		VerificationKey: VerfiyingAndDummyKey{
			Vk:    fixedVk,
			Dummy: dummyVk,
		},
	}
	for i := 0; i < MaxVotes; i++ {
		if i < nVotes {
			finalPlaceholder.VerifyPublicInputs[i] = stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](ccs)
			finalPlaceholder.VerifyProofs[i] = stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](ccs)
		} else {
			finalPlaceholder.VerifyPublicInputs[i] = stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](dummyCCS)
			finalPlaceholder.VerifyProofs[i] = stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyCCS)
		}
	}
	// generate proof
	assert := test.NewAssert(t)
	now := time.Now()
	assert.SolvingSucceeded(&finalPlaceholder, &finalWitness,
		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
	fmt.Println("proving tooks", time.Since(now))
}
