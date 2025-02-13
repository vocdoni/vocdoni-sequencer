package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/recursion/groth16"
)

var (
	BallotProofCurve     = ecc.BN254     // ecc.BN254
	VoteVerifierCurve    = ecc.BLS12_377 // ecc.BLS12_377
	AggregatorCurve      = ecc.BW6_761   // ecc.BW6_761
	StateTransitionCurve = ecc.BN254     // ecc.BN254
)

type InnerProofBW6761 struct {
	Proof groth16.Proof[sw_bw6761.G1Affine, sw_bw6761.G2Affine]
	VK    groth16.VerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl] `gnark:"-"`
}
