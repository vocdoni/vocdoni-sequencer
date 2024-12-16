package circom

import (
	"crypto/ecdsa"
	"crypto/rand"
	_ "embed"
	"fmt"
	"math/big"

	gecdsa "github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/iden3/go-rapidsnark/witness"
	"github.com/vocdoni/circom2gnark/parser"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"
	bjj "github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

//go:embed ballot_proof.wasm
var circuit []byte

//go:embed ballot_proof_pkey.zkey
var pkey []byte

//go:embed ballot_proof_vkey.json
var vkey []byte

const (
	// process config
	NLevels         = 160
	NFields         = 8
	MaxCount        = 5
	ForceUniqueness = 0
	MaxValue        = 16
	MinValue        = 0
	CostExp         = 2
	CostFromWeight  = 0
	Weight          = 10
)

// GenerateECDSAaccount generates a new ECDSA account and returns the private
// key, public key and address.
func GenerateECDSAaccount() (*ecdsa.PrivateKey, ecdsa.PublicKey, common.Address, error) {
	// generate ecdsa keys and address (privKey and publicKey)
	privKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, ecdsa.PublicKey{}, common.Address{}, err
	}
	return privKey, privKey.PublicKey, crypto.PubkeyToAddress(privKey.PublicKey), nil
}

// SignECDSA signs the data with the private key provided and returns the R and
// S values of the signature.
func SignECDSA(privKey *ecdsa.PrivateKey, data []byte) (*big.Int, *big.Int, error) {
	sigBin, err := crypto.Sign(data, privKey)
	if err != nil {
		return nil, nil, err
	}
	// truncate the signature to 64 bytes (the first 32 bytes are the R value,
	// the second 32 bytes are the S value)
	sigBin = sigBin[:64]
	if valid := crypto.VerifySignature(crypto.CompressPubkey(&privKey.PublicKey), data, sigBin); !valid {
		return nil, nil, fmt.Errorf("invalid signature")
	}
	var sig gecdsa.Signature
	if _, err := sig.SetBytes(sigBin); err != nil {
		return nil, nil, err
	}
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])
	return r, s, nil
}

// GenerateEncryptionTestKey generates a new encryption key for testing
// purposes. It uses the Iden3 implementation of the BabyJubJub curve to
// simplify the process.
func GenerateEncryptionTestKey() ecc.Point {
	privkey := babyjub.NewRandPrivKey()

	x, y := privkey.Public().X, privkey.Public().Y
	return new(bjj.BJJ).SetPoint(x, y)
}

// GenerateBallotFields generates a list of n random fields between min and max
// values. If unique is true, the fields will be unique.
func GenerateBallotFields(n, max, min int, unique bool) []*big.Int {
	fields := []*big.Int{}
	stored := map[string]bool{}
	for i := 0; i < n; i++ {
		for {
			// generate random field
			field, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
			if err != nil {
				panic(err)
			}
			field.Add(field, big.NewInt(int64(min)))
			// if it should be unique and it's already stored, skip it,
			// otherwise add it to the list of fields and continue
			if !unique || !stored[field.String()] {
				fields = append(fields, field)
				stored[field.String()] = true
				break
			}
		}
	}
	return fields
}

// CipherBallotFields encrypts the fields provided using the public key and
// random k value provided. Each encrypted field includes two points (c1 and c2)
// that represent the encrypted field. The function also returns a list of the
// plain cipher fields (x and y values of c1 and c2) that simplify the process
// of hashing the inputs for the circuit.
func CipherBallotFields(fields []*big.Int, n int, pk ecc.Point, k *big.Int) ([][][]string, []*big.Int) {
	cipherfields := make([][][]string, n)
	plainCipherfields := []*big.Int{}
	for i := 0; i < n; i++ {
		if i < len(fields) {
			c1, c2, err := elgamal.EncryptWithK(pk, fields[i], k)
			if err != nil {
				panic(err)
			}
			c1X, c1Y := c1.Point()
			c2X, c2Y := c2.Point()
			cipherfields[i] = [][]string{
				{c1X.String(), c1Y.String()},
				{c2X.String(), c2Y.String()},
			}
			plainCipherfields = append(plainCipherfields, c1X, c1Y, c2X, c2Y)
		} else {
			cipherfields[i] = [][]string{
				{"0", "0"},
				{"0", "0"},
			}
			plainCipherfields = append(plainCipherfields, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0))
		}
	}
	return cipherfields, plainCipherfields
}

// MockedCommitmentAndNullifier generates a commitment and nullifier for the
// given address, processID and secret values. It uses the Poseidon hash
// function over BabyJubJub curve to generate the commitment and nullifier.
// The commitment is generated using the address, processID and secret value,
// while the nullifier is generated using the commitment and secret value.
func MockedCommitmentAndNullifier(address, processID, secret []byte) (*big.Int, *big.Int, error) {
	commitment, err := poseidon.Hash([]*big.Int{
		util.BigToFF(new(big.Int).SetBytes(address)),
		util.BigToFF(new(big.Int).SetBytes(processID)),
		util.BigToFF(new(big.Int).SetBytes(secret)),
	})
	if err != nil {
		return nil, nil, err
	}
	nullifier, err := poseidon.Hash([]*big.Int{
		commitment,
		util.BigToFF(new(big.Int).SetBytes(secret)),
	})
	if err != nil {
		return nil, nil, err
	}
	return commitment, nullifier, nil
}

// BigIntArrayToStringArray pads the big.Int array to n elements, if needed,
// with zeros.
func BigIntArrayToN(arr []*big.Int, n int) []*big.Int {
	bigArr := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		if i < len(arr) {
			bigArr[i] = arr[i]
		} else {
			bigArr[i] = big.NewInt(0)
		}
	}
	return bigArr
}

// BigIntArrayToStringArray converts the big.Int array to a string array.
func BigIntArrayToStringArray(arr []*big.Int, n int) []string {
	strArr := []string{}
	for _, b := range BigIntArrayToN(arr, n) {
		strArr = append(strArr, b.String())
	}
	return strArr
}

// CompileAndGenerateProof compiles a circom circuit, generates the witness and
// generates the proof using the inputs provided. It returns the proof and the
// public signals of the proof. It uses Rapidsnark and Groth16 prover to
// generate the proof.
func CompileAndGenerateProof(inputs []byte) (string, string, error) {
	finalInputs, err := witness.ParseInputs(inputs)
	if err != nil {
		return "", "", err
	}
	// instance witness calculator
	calc, err := witness.NewCircom2WitnessCalculator(circuit, true)
	if err != nil {
		return "", "", err
	}
	// calculate witness
	w, err := calc.CalculateWTNSBin(finalInputs, true)
	if err != nil {
		return "", "", err
	}
	// generate proof
	return prover.Groth16ProverRaw(pkey, w)
}

// Circom2GnarkProof
func Circom2GnarkProof(witness []byte) (*parser.GnarkRecursionProof, error) {
	// create circom proof and public signals
	circomProof, pubSignals, err := CompileAndGenerateProof(witness)
	if err != nil {
		return nil, err
	}
	// transform to gnark format
	gnarkProofData, err := parser.UnmarshalCircomProofJSON([]byte(circomProof))
	if err != nil {
		return nil, err
	}
	gnarkPubSignalsData, err := parser.UnmarshalCircomPublicSignalsJSON([]byte(pubSignals))
	if err != nil {
		return nil, err
	}
	gnarkVKeyData, err := parser.UnmarshalCircomVerificationKeyJSON(vkey)
	if err != nil {
		return nil, err
	}
	proof, err := parser.ConvertCircomToGnarkRecursion(gnarkVKeyData, gnarkProofData, gnarkPubSignalsData, true)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

// Circom2GnarkPlaceholder
func Circom2GnarkPlaceholder() (*parser.GnarkRecursionPlaceholders, error) {
	gnarkVKeyData, err := parser.UnmarshalCircomVerificationKeyJSON(vkey)
	if err != nil {
		return nil, err
	}
	return parser.PlaceholdersForRecursion(gnarkVKeyData, 1, true)
}
