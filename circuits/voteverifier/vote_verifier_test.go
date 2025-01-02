package voteverifier

import (
	"fmt"
	"math"
	"math/big"
	"testing"

	gecc "github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
	gtest "github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/testutil"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	ballotprooftest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

type checkInnerInputsCircuit struct {
	InputsHash       emulated.Element[sw_bn254.ScalarField]
	MaxCount         emulated.Element[sw_bn254.ScalarField]
	ForceUniqueness  emulated.Element[sw_bn254.ScalarField]
	MaxValue         emulated.Element[sw_bn254.ScalarField]
	MinValue         emulated.Element[sw_bn254.ScalarField]
	MaxTotalCost     emulated.Element[sw_bn254.ScalarField]
	MinTotalCost     emulated.Element[sw_bn254.ScalarField]
	CostExp          emulated.Element[sw_bn254.ScalarField]
	CostFromWeight   emulated.Element[sw_bn254.ScalarField]
	Address          emulated.Element[sw_bn254.ScalarField]
	UserWeight       emulated.Element[sw_bn254.ScalarField]
	EncryptionPubKey [2]emulated.Element[sw_bn254.ScalarField]
	Nullifier        emulated.Element[sw_bn254.ScalarField]
	Commitment       emulated.Element[sw_bn254.ScalarField]
	ProcessId        emulated.Element[sw_bn254.ScalarField]
	EncryptedBallot  [8][2][2]emulated.Element[sw_bn254.ScalarField]
}

func (c *checkInnerInputsCircuit) Define(api frontend.API) error {
	hashInputs := []emulated.Element[sw_bn254.ScalarField]{
		c.MaxCount, c.ForceUniqueness, c.MaxValue, c.MinValue, c.MaxTotalCost,
		c.MinTotalCost, c.CostExp, c.CostFromWeight, c.Address, c.UserWeight,
		c.ProcessId, c.EncryptionPubKey[0], c.EncryptionPubKey[1], c.Nullifier,
		c.Commitment,
	}
	// flatten the encrypted ballot and append to the circom public-private
	// inputs
	for i := 0; i < len(c.EncryptedBallot); i++ {
		for j := 0; j < len(c.EncryptedBallot[i]); j++ {
			hashInputs = append(hashInputs, c.EncryptedBallot[i][j][:]...)
		}
	}
	return checkInnerInputHash(api, c.InputsHash, hashInputs...)
}

func TestCheckInnerInputHash(t *testing.T) {
	c := qt.New(t)
	processId := util.RandomBytes(20)
	encryptionKey := ballotprooftest.GenEncryptionKeyForTest()
	encryptionKeyX, encryptionKeyY := encryptionKey.Point()

	_, _, address, err := ballotprooftest.GenECDSAaccountForTest()
	c.Assert(err, qt.IsNil)

	voterProof, err := ballotprooftest.BallotProofForTest(address.Bytes(), processId, encryptionKey)
	c.Assert(err, qt.IsNil)

	// group the circom inputs to hash
	ffAddress := ecc.BigToFF(gecc.BN254.BaseField(), new(big.Int).SetBytes(address.Bytes()))
	ffProcessID := ecc.BigToFF(gecc.BN254.BaseField(), new(big.Int).SetBytes(processId))
	bigCircomInputs := []*big.Int{
		big.NewInt(int64(ballotprooftest.MaxCount)),
		big.NewInt(int64(ballotprooftest.ForceUniqueness)),
		big.NewInt(int64(ballotprooftest.MaxValue)),
		big.NewInt(int64(ballotprooftest.MinValue)),
		big.NewInt(int64(math.Pow(float64(ballotprooftest.MaxValue), float64(ballotprooftest.CostExp))) * int64(ballotprooftest.MaxCount)),
		big.NewInt(int64(ballotprooftest.MaxCount)),
		big.NewInt(int64(ballotprooftest.CostExp)),
		big.NewInt(int64(ballotprooftest.CostFromWeight)),
		ffAddress,
		big.NewInt(int64(ballotprooftest.Weight)),
		ffProcessID,
		encryptionKeyX,
		encryptionKeyY,
		voterProof.Nullifier,
		voterProof.Commitment,
	}
	bigCircomInputs = append(bigCircomInputs, voterProof.PlainEcryptedFields...)
	circomInputsHash, err := mimc7.Hash(bigCircomInputs, nil)
	c.Assert(err, qt.IsNil)

	emulatedBallots := [ballotprooftest.NFields][2][2]emulated.Element[sw_bn254.ScalarField]{}
	for i, c := range voterProof.EncryptedFields {
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

	assigments := checkInnerInputsCircuit{
		InputsHash: emulated.ValueOf[sw_bn254.ScalarField](circomInputsHash),
		// circom inputs
		MaxCount:        emulated.ValueOf[sw_bn254.ScalarField](ballotprooftest.MaxCount),
		ForceUniqueness: emulated.ValueOf[sw_bn254.ScalarField](ballotprooftest.ForceUniqueness),
		MaxValue:        emulated.ValueOf[sw_bn254.ScalarField](ballotprooftest.MaxValue),
		MinValue:        emulated.ValueOf[sw_bn254.ScalarField](ballotprooftest.MinValue),
		MaxTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](int(math.Pow(float64(ballotprooftest.MaxValue), float64(ballotprooftest.CostExp))) * ballotprooftest.MaxCount),
		MinTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](ballotprooftest.MaxCount),
		CostExp:         emulated.ValueOf[sw_bn254.ScalarField](ballotprooftest.CostExp),
		CostFromWeight:  emulated.ValueOf[sw_bn254.ScalarField](ballotprooftest.CostFromWeight),
		Address:         emulated.ValueOf[sw_bn254.ScalarField](voterProof.Address),
		UserWeight:      emulated.ValueOf[sw_bn254.ScalarField](ballotprooftest.Weight),
		EncryptionPubKey: [2]emulated.Element[sw_bn254.ScalarField]{
			emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyX),
			emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyY),
		},
		Nullifier:       emulated.ValueOf[sw_bn254.ScalarField](voterProof.Nullifier),
		Commitment:      emulated.ValueOf[sw_bn254.ScalarField](voterProof.Commitment),
		ProcessId:       emulated.ValueOf[sw_bn254.ScalarField](voterProof.ProcessID),
		EncryptedBallot: emulatedBallots,
	}

	assert := gtest.NewAssert(t)
	assert.SolvingSucceeded(&checkInnerInputsCircuit{}, &assigments,
		gtest.WithCurves(gecc.BLS12_377),
		gtest.WithBackends(backend.GROTH16))
}

type checkInputsCircuit struct {
	ExpectedHash     frontend.Variable
	CensusRoot       frontend.Variable
	CircomInputsHash emulated.Element[sw_bn254.ScalarField]
}

func (c *checkInputsCircuit) Define(api frontend.API) error {
	return checkInputHash(api, c.CircomInputsHash, c.CensusRoot, c.ExpectedHash)
}

func TestCheckInputsHash(t *testing.T) {
	c := qt.New(t)
	_, _, address, err := ballotprooftest.GenECDSAaccountForTest()
	c.Assert(err, qt.IsNil)

	// generate a test census
	testCensus, err := testutil.GenerateCensusProofForTest(testutil.CensusTestConfig{
		Dir:           fmt.Sprintf("../assets/census%d", util.RandomInt(0, 1000)),
		ValidSiblings: 10,
		TotalSiblings: ballotprooftest.NLevels,
		KeyLen:        20,
		Hash:          arbo.HashFunctionMiMC_BLS12_377,
		BaseFiled:     arbo.BLS12377BaseField,
	}, [][]byte{address.Bytes()}, [][]byte{big.NewInt(10).Bytes()})
	c.Assert(err, qt.IsNil)

	voterProof, err := ballotprooftest.BallotProofForTest(address.Bytes(),
		util.RandomBytes(20), ballotprooftest.GenEncryptionKeyForTest())
	c.Assert(err, qt.IsNil)
	// convert the circom inputs hash to the field of the curve used by the
	// circuit as input for MIMC hash
	blsCircomInputsHash := circuits.BigIntToMIMCHash(voterProof.InputsHash, gecc.BLS12_377.ScalarField())
	// hash the inputs of gnark circuit (circom inputs hash + census root)
	hFn := mimc.NewMiMC()
	hFn.Write(blsCircomInputsHash)
	hFn.Write(testCensus.Root.Bytes())
	inputsHash := new(big.Int).SetBytes(hFn.Sum(nil))

	assigments := checkInputsCircuit{
		ExpectedHash:     frontend.Variable(inputsHash),
		CensusRoot:       testCensus.Root,
		CircomInputsHash: emulated.ValueOf[sw_bn254.ScalarField](voterProof.InputsHash),
	}

	assert := gtest.NewAssert(t)
	assert.SolvingSucceeded(&checkInputsCircuit{}, &assigments,
		gtest.WithCurves(gecc.BLS12_377),
		gtest.WithBackends(backend.GROTH16))
}

type verifySigForAddressCircuit struct {
	Address       emulated.Element[sw_bn254.ScalarField]
	PubKey        ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	Msg           emulated.Element[emulated.Secp256k1Fr]
	Sig           ecdsa.Signature[emulated.Secp256k1Fr]
	CensusAddress frontend.Variable
}

func (c *verifySigForAddressCircuit) Define(api frontend.API) error {
	censusAddress, err := verifySigForAddress(api, c.Address, c.PubKey, c.Msg, c.Sig)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.CensusAddress, censusAddress)
	return nil
}

func TestVerifySigForAddress(t *testing.T) {
	c := qt.New(t)
	privKey, pubKey, address, err := ballotprooftest.GenECDSAaccountForTest()
	c.Assert(err, qt.IsNil)

	voterProof, err := ballotprooftest.BallotProofForTest(address.Bytes(),
		util.RandomBytes(20), ballotprooftest.GenEncryptionKeyForTest())
	c.Assert(err, qt.IsNil)
	// convert the circom inputs hash to the field of the curve used by the
	// circuit as input for MIMC hash
	blsCircomInputsHash := circuits.BigIntToMIMCHash(voterProof.InputsHash, gecc.BLS12_377.ScalarField())
	leAddress := new(big.Int).SetBytes(arbo.SwapEndianness(address.Bytes()))
	// sign the inputs hash with the private key
	rSign, sSign, err := ballotprooftest.SignECDSAForTest(privKey, blsCircomInputsHash)
	c.Assert(err, qt.IsNil)
	assigments := verifySigForAddressCircuit{
		Address: emulated.ValueOf[sw_bn254.ScalarField](voterProof.Address),
		PubKey: ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pubKey.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pubKey.Y),
		},
		Msg: emulated.ValueOf[emulated.Secp256k1Fr](blsCircomInputsHash),
		Sig: ecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](rSign),
			S: emulated.ValueOf[emulated.Secp256k1Fr](sSign),
		},
		CensusAddress: leAddress,
	}
	assert := gtest.NewAssert(t)
	assert.SolvingSucceeded(&verifySigForAddressCircuit{}, &assigments,
		gtest.WithCurves(gecc.BLS12_377),
		gtest.WithBackends(backend.GROTH16))
}
