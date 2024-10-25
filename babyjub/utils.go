package babyjub

import (
	"encoding/json"
	"os"

	"github.com/iden3/go-rapidsnark/prover"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/verifier"
	"github.com/iden3/go-rapidsnark/witness"
)

type ProofData struct {
	A []string   `json:"pi_a"`
	B [][]string `json:"pi_b"`
	C []string   `json:"pi_c"`
}

func CompileAndGenerateProof(inputs []byte, wasmFile, zkeyFile string) (string, string, error) {
	finalInputs, err := witness.ParseInputs(inputs)
	if err != nil {
		return "", "", err
	}
	// read wasm file
	bWasm, err := os.ReadFile(wasmFile)
	if err != nil {
		return "", "", err
	}
	// read zkey file
	bZkey, err := os.ReadFile(zkeyFile)
	if err != nil {
		return "", "", err
	}
	// instance witness calculator
	calc, err := witness.NewCircom2WitnessCalculator(bWasm, true)
	if err != nil {
		return "", "", err
	}
	// calculate witness
	w, err := calc.CalculateWTNSBin(finalInputs, true)
	if err != nil {
		return "", "", err
	}
	// generate proof
	return prover.Groth16ProverRaw(bZkey, w)
}

func VerifyProof(proofData, pubSignals string, vkey []byte) error {
	data := ProofData{}
	if err := json.Unmarshal([]byte(proofData), &data); err != nil {
		return err
	}
	signals := []string{}
	if err := json.Unmarshal([]byte(pubSignals), &signals); err != nil {
		return err
	}
	proof := types.ZKProof{
		Proof: &types.ProofData{
			A: data.A,
			B: data.B,
			C: data.C,
		},
		PubSignals: signals,
	}
	return verifier.VerifyGroth16(proof, vkey)
}
