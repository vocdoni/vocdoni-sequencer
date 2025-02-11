package circuits

import (
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion/groth16"
)

// These are the curves used by each step

// ### 1. ballotproof
// native bn254

// ### 2. voteverifier
// native bls12377
// inner bn254

// ### 3. aggregator
// native bw6761
// inner bls12377

// ### 4. statetransition
// native bn254
// inner bw6761

type InnerProofBN254 struct {
	Proof groth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VK    groth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
}
type InnerProofBLS12377 struct {
	Proof   groth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	Witness groth16.Witness[sw_bls12377.ScalarField]
	VK      groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
}

type InnerProofBW6761 struct {
	Proof groth16.Proof[sw_bw6761.G1Affine, sw_bw6761.G2Affine]
	VK    groth16.VerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl] `gnark:"-"`
}
