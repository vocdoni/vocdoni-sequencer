package verifyvote

import (
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/math/emulated"
	gecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	arbotree "github.com/vocdoni/arbo"
	"github.com/vocdoni/circom2gnark/parser"
	internaltest "github.com/vocdoni/gnark-crypto-primitives/test"
)

var (
	proofFile      = "../assets/circom/proofs/1_proof.json"
	pubSignalsFile = "../assets/circom/proofs/1_pub_signals.json"
	vKeyFile       = "../assets/circom/verification_key.json"
)

func TestVerifyVoteCircuit(t *testing.T) {
	c := qt.New(t)
	// compile circuit
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &VerifyVoteCircuit{})
	fmt.Println("compilation tooks", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	// parse input files
	proof, inputsHash, err := parseCircomInputs(vKeyFile, proofFile, pubSignalsFile)
	c.Assert(err, qt.IsNil)
	// generate account and sign the inputs hash
	testSign, err := internaltest.GenerateAccountAndSign(inputsHash.Bytes())
	c.Assert(err, qt.IsNil)
	// generate a test census proof
	testCensus, err := internaltest.GenerateCensusProofForTest(internaltest.CensusTestConfig{
		Dir:           "../assets/census",
		ValidSiblings: 10,
		TotalSiblings: 160,
		KeyLen:        20,
		Hash:          arbotree.HashFunctionMiMC_BLS12_377,
		BaseFiled:     arbotree.BLS12377BaseField,
	}, testSign.Address.Bytes(), new(big.Int).SetInt64(10).Bytes())
	c.Assert(err, qt.IsNil)
	// transform siblings to gnark frontend.Variable
	fSiblings := [160]frontend.Variable{}
	for i, s := range testCensus.Siblings {
		fSiblings[i] = frontend.Variable(s)
	}
	// init inputs
	witness := VerifyVoteCircuit{
		Address:               testSign.Address,
		InputsHash:            emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(inputsHash.Bytes())),
		CensusRoot:            testCensus.Root,
		CensusProofKey:        testCensus.Key,
		CensusProofValue:      testCensus.Value,
		CensusProofSiblings:   fSiblings,
		CircomProof:           proof.Proof,
		CircomVerificationKey: proof.Vk,
		CircomPublicInputs:    proof.PublicInputs,
		PublicKey: gecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](testSign.PublicKey.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](testSign.PublicKey.Y),
		},
		Signature: gecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](testSign.R),
			S: emulated.ValueOf[emulated.Secp256k1Fr](testSign.S),
		},
	}
	// generate proof
	assert := test.NewAssert(t)
	now = time.Now()
	assert.SolvingSucceeded(&VerifyVoteCircuit{}, &witness, test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.GROTH16))
	fmt.Println("proving tooks", time.Since(now))
}

func parseCircomInputs(vKeyFile, proofFile, pubSignalsFile string) (*parser.GnarkRecursionProof, *big.Int, error) {
	// load data from assets
	proofData, err := os.ReadFile(proofFile)
	if err != nil {
		return nil, nil, err
	}
	pubSignalsData, err := os.ReadFile(pubSignalsFile)
	if err != nil {
		return nil, nil, err
	}
	vKeyData, err := os.ReadFile(vKeyFile)
	if err != nil {
		return nil, nil, err
	}
	// transform to gnark format
	gnarkProofData, err := parser.UnmarshalCircomProofJSON(proofData)
	if err != nil {
		return nil, nil, err
	}
	gnarkPubSignalsData, err := parser.UnmarshalCircomPublicSignalsJSON(pubSignalsData)
	if err != nil {
		return nil, nil, err
	}
	gnarkVKeyData, err := parser.UnmarshalCircomVerificationKeyJSON(vKeyData)
	if err != nil {
		return nil, nil, err
	}
	proof, _, err := parser.ConvertCircomToGnarkRecursion(gnarkProofData, gnarkVKeyData, gnarkPubSignalsData)
	if err != nil {
		return nil, nil, err
	}
	// decode pub input to get the hash to sign
	inputsHash, ok := new(big.Int).SetString(gnarkPubSignalsData[0], 10)
	if !ok {
		return nil, nil, fmt.Errorf("failed to decode inputs hash")
	}
	return proof, inputsHash, nil
}
