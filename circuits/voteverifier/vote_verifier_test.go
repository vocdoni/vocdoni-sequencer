package verifyvote

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	gecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/vocdoni/circom2gnark/parser"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/pebbledb"
	"go.vocdoni.io/dvote/tree/arbo"
	"go.vocdoni.io/dvote/util"
)

func TestVerifyVoteCircuit(t *testing.T) {
	var (
		proofFile      = "../assets/circom/proofs/1_proof.json"
		pubSignalsFile = "../assets/circom/proofs/1_pub_signals.json"
		vKeyFile       = "../assets/circom/verification_key.json"
	)
	// load data from assets
	proofData, err := os.ReadFile(proofFile)
	if err != nil {
		t.Fatal(err)
	}
	pubSignalsData, err := os.ReadFile(pubSignalsFile)
	if err != nil {
		t.Fatal(err)
	}
	vKeyData, err := os.ReadFile(vKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	// transform to gnark format
	gnarkProofData, err := parser.UnmarshalCircomProofJSON(proofData)
	if err != nil {
		t.Fatal(err)
	}
	gnarkPubSignalsData, err := parser.UnmarshalCircomPublicSignalsJSON(pubSignalsData)
	if err != nil {
		t.Fatal(err)
	}
	gnarkVKeyData, err := parser.UnmarshalCircomVerificationKeyJSON(vKeyData)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := parser.ConvertCircomToGnarkRecursion(gnarkProofData, gnarkVKeyData, gnarkPubSignalsData)
	if err != nil {
		t.Fatal(err)
	}
	// decode pub input to get the hash to sign
	rawInputs := []string{}
	if err := json.Unmarshal(pubSignalsData, &rawInputs); err != nil {
		t.Fatal(err)
	} else if len(rawInputs) != 1 {
		t.Fatal("invalid public inputs")
	}
	inputsHash, _ := new(big.Int).SetString(rawInputs[0], 10)
	fmt.Println("raw inputs hash", inputsHash)
	// generate ecdsa key pair (privKey and publicKey)
	privKey, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// compute the signature of an arbitrary message
	sigBin, err := privKey.Sign(inputsHash.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if flag, err := privKey.PublicKey.Verify(sigBin, inputsHash.Bytes(), nil); !flag || err != nil {
		t.Fatal("invalid signature")
	}
	var sig ecdsa.Signature
	sig.SetBytes(sigBin)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])
	// generate a census merkle tree with some random addresses
	address := ethereum.AddrFromBytes(util.RandomBytes(20))
	censusProof, err := generateCensusProof(10, address.Bytes(), big.NewInt(10).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// init inputs
	witness := VerifyVoteCircuit{
		InputsHash: emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(inputsHash.Bytes())),
		Address:    address.Big(),
		BallotProof: circuits.CircomProof{
			Proof:        proof.Proof,
			Vk:           proof.Vk,
			PublicInputs: proof.PublicInputs,
		},
		PublicKey: gecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
		},
		Signature: gecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		CensusProof: censusProof,
	}

	// bWitness, err := json.MarshalIndent(witness, "  ", "  ")
	// if err == nil {
	// 	fmt.Println("witness")
	// 	fmt.Println(string(bWitness))
	// }

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&VerifyVoteCircuit{}, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func generateCensusProof(n int, k, v []byte) (circuits.CensusProof, error) {
	dir := os.TempDir()
	defer func() {
		_ = os.RemoveAll(dir)
	}()
	database, err := pebbledb.New(db.Options{Path: dir})
	if err != nil {
		return circuits.CensusProof{}, err
	}
	tree, err := arbo.NewTree(arbo.Config{
		Database:     database,
		MaxLevels:    160,
		HashFunction: arbo.HashFunctionPoseidon,
	})
	if err != nil {
		return circuits.CensusProof{}, err
	}
	k = util.BigToFF(new(big.Int).SetBytes(k)).Bytes()
	// add the first key-value pair
	if err = tree.Add(k, v); err != nil {
		return circuits.CensusProof{}, err
	}
	// add random addresses
	for i := 1; i < n; i++ {
		rk := util.BigToFF(new(big.Int).SetBytes(util.RandomBytes(20))).Bytes()
		rv := new(big.Int).SetBytes(util.RandomBytes(8)).Bytes()
		if err = tree.Add(rk, rv); err != nil {
			return circuits.CensusProof{}, err
		}
	}
	// generate the proof
	_, _, siblings, exist, err := tree.GenProof(k)
	if err != nil {
		return circuits.CensusProof{}, err
	}
	if !exist {
		return circuits.CensusProof{}, fmt.Errorf("error building the merkle tree: key not found")
	}
	unpackedSiblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, siblings)
	if err != nil {
		return circuits.CensusProof{}, err
	}
	paddedSiblings := [160]frontend.Variable{}
	for i := 0; i < 160; i++ {
		if i < len(unpackedSiblings) {
			paddedSiblings[i] = arbo.BytesLEToBigInt(unpackedSiblings[i])
		} else {
			paddedSiblings[i] = big.NewInt(0)
		}
	}
	root, err := tree.Root()
	if err != nil {
		return circuits.CensusProof{}, err
	}
	return circuits.CensusProof{
		Root:     arbo.BytesLEToBigInt(root),
		Key:      arbo.BytesLEToBigInt(k),
		Value:    new(big.Int).SetBytes(v),
		Siblings: paddedSiblings,
	}, nil
}
