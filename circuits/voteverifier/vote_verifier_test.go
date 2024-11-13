package verifyvote

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/math/emulated"
	gecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/vocdoni/circom2gnark/parser"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
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
	// generate ecdsa key pair (privKey and publicKey)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := &privKey.PublicKey
	// derive address from public key
	pubKeyBytes := append(publicKey.X.Bytes(), publicKey.Y.Bytes()...)
	hAddress := crypto.Keccak256(pubKeyBytes)
	address := hAddress[len(hAddress)-20:]
	// compute the signature of an arbitrary message
	rSign, sSign, err := ecdsa.Sign(rand.Reader, privKey, inputsHash.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// generate a census merkle tree with some random addresses
	censusProof, err := generateCensusProof(10, address, big.NewInt(10).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// init inputs
	witness := VerifyVoteCircuit{
		InputsHash: inputsHash,
		Address:    new(big.Int).SetBytes(address),
		BallotProof: circuits.CircomProof{
			Proof:        proof.Proof,
			VerifyingKey: proof.Vk,
			PublicInputs: proof.PublicInputs,
		},
		PublicKey: gecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](publicKey.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](publicKey.Y),
		},
		Signature: gecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](rSign),
			S: emulated.ValueOf[emulated.Secp256k1Fr](sSign),
		},
		CensusProof: censusProof,
	}

	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &VerifyVoteCircuit{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())

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
