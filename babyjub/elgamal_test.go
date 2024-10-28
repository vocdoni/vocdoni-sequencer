package babyjub

import (
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"testing"

	"github.com/vocdoni/elGamal-sandbox/ecc/curves"
	"github.com/vocdoni/elGamal-sandbox/encrypt"
)

const (
	// circuit assets
	wasmFile = "./artifacts/elgamal.wasm"
	pkeyFile = "./artifacts/elgamal_pkey.zkey"
	vkeyFile = "./artifacts/elgamal_vkey.json"
)

func TestElGamal(t *testing.T) {
	curve := flag.String("curve", curves.CurveTypeBabyJubJubIden3, "Curve type: bjj_gnark or bjj_iden3 (BabyJubJub) or bn254 (BN254)")
	xArg := flag.String("xPub", "13052078511204024488949486741416871154659396670901193795368120342268124622748", "Public key x coordinate")
	yArg := flag.String("yPub", "802024463101706411390857091171354344842692936563515496965191447843200271207", "Public key y coordinate")
	flag.Parse()

	sMsg := "1234567890"
	msg, _ := new(big.Int).SetString(sMsg, 10)
	// mock public key
	pub, err := curves.New(*curve)
	if err != nil {
		t.Errorf("Failed to create curve point: %v", err)
		return
	}
	bXArg, _ := new(big.Int).SetString(*xArg, 10)
	bYArg, _ := new(big.Int).SetString(*yArg, 10)
	pub = pub.SetPoint(bXArg, bYArg)
	c1, c2, k, err := encrypt.Encrypt(msg, pub)
	if err != nil {
		t.Errorf("Failed to encrypt message: %v", err)
		return
	}
	// init circom inputs
	pubX, pubY := pub.Point()
	c1X, c1Y := c1.Point()
	c2X, c2Y := c2.Point()
	inputs := map[string]any{
		"pk":  []string{pubX.String(), pubY.String()},
		"msg": sMsg,
		"k":   k.String(),
		"c1":  []string{c1X.String(), c1Y.String()},
		"c2":  []string{c2X.String(), c2Y.String()},
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
