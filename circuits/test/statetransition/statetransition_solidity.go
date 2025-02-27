package statetransitiontest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
)

func CircuitExportSolidity(t *testing.T, c, w frontend.Circuit) {
	if os.Getenv("RELEASE_SOLIDITY") == "" || os.Getenv("RELEASE_SOLIDITY") == "false" {
		t.Skip("skipping solidity export...")
	}
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)
	// generate witness
	fmt.Println("NewWitness") // debug
	witness, err := frontend.NewWitness(w, circuits.StateTransitionCurve.ScalarField())
	assert.NoError(err)
	// get public witness
	pubWitness, err := witness.Public()
	assert.NoError(err)
	// compile the circuit
	fmt.Println("Compile") // debug
	ccs, err := frontend.Compile(circuits.StateTransitionCurve.ScalarField(), r1cs.NewBuilder, c)
	assert.NoError(err)
	// generate proving and verifying keys
	fmt.Println("Setup") // debug
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	// generate proof
	fmt.Println("Prove") // debug
	proof, err := groth16.Prove(ccs, pk, witness)
	assert.NoError(err)
	// write proof into a buffer
	var buf bytes.Buffer
	_, err = proof.WriteRawTo(&buf)
	assert.NoError(err)
	proofBytes := buf.Bytes()
	// compose the proof for solidity
	type SolidityProof struct {
		Ar  [2]*big.Int    `json:"Ar"`
		Bs  [2][2]*big.Int `json:"Bs"`
		Krs [2]*big.Int    `json:"Krs"`
	}
	p := SolidityProof{}
	// proof.Ar, proof.Bs, proof.Krs
	const fpSize = 4 * 8
	p.Ar[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	p.Ar[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	p.Bs[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	p.Bs[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	p.Bs[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	p.Bs[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	p.Krs[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	p.Krs[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])
	// write proof into a file
	prooffd, err := os.Create("statetransition_proof.json")
	assert.NoError(err)
	defer prooffd.Close()
	bProof, err := json.Marshal(p)
	assert.NoError(err)
	_, err = prooffd.Write(bProof)
	assert.NoError(err)
	// generate solidity verifier
	solfd, err := os.Create("statetransition_verifier.sol")
	assert.NoError(err)
	defer solfd.Close()
	// write verifier
	err = vk.ExportSolidity(solfd)
	assert.NoError(err)
	// generate also the json of the public witness
	schema, err := frontend.NewSchema(w)
	assert.NoError(err)
	jsonWitness, err := pubWitness.ToJSON(schema)
	assert.NoError(err)
	pubWitnessJSONfd, err := os.Create("statetransition_public_witness.json")
	assert.NoError(err)
	defer pubWitnessJSONfd.Close()
	_, err = pubWitnessJSONfd.Write(jsonWitness)
	assert.NoError(err)
}
