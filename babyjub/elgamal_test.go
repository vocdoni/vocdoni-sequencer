package babyjub

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

const (
	// circuit assets
	wasmFile = "./artifacts/elgamal.wasm"
	pkeyFile = "./artifacts/elgamal_pkey.zkey"
	vkeyFile = "./artifacts/elgamal_vkey.json"
)

func TestElGamal(t *testing.T) {
	sMsg := "1234567890"
	msg, _ := new(big.Int).SetString(sMsg, 10)
	// generate key pair
	_, pub := GenerateKeyPair()
	c1, c2, k, err := Encrypt(msg, pub)
	if err != nil {
		t.Errorf("Failed to encrypt message: %v", err)
		return
	}
	// init circom inputs
	inputs := map[string]any{
		"pk":  []string{pub.X.String(), pub.Y.String()},
		"msg": sMsg,
		"k":   k.String(),
		"c1":  []string{c1.X.String(), c1.Y.String()},
		"c2":  []string{c2.X.String(), c2.Y.String()},
	}
	bInputs, err := json.MarshalIndent(inputs, "  ", "  ")
	if err != nil {
		t.Errorf("Failed to marshal inputs: %v", err)
		return
	}
	// generate proof
	proofData, pubSignals, err := CompileAndGenerateProof(bInputs, wasmFile, pkeyFile)
	if err != nil {
		t.Errorf("Failed to generate proof: %v", err)
		return
	}
	// read vkey file
	vkey, err := os.ReadFile(vkeyFile)
	if err != nil {
		t.Errorf("Error reading zkey file: %v\n", err)
		return
	}
	// verify proof
	if err := VerifyProof(proofData, pubSignals, vkey); err != nil {
		t.Errorf("Failed to verify proof: %v", err)
		return
	}
}
