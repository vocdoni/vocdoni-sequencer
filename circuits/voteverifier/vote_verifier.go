// verifyvote package contains the Gnark circuit definition that verifies a
// vote package to be aggregated by the vote aggregator and included in a new
// state transition. A vote package includes a ballot proof (generated from
// a circom circuit with snarkjs), the public inputs of the ballot proof
// circuit, the signature of the public inputs, and a census proof. The vote
// package is valid if the ballot proof is valid if:
//   - The signature of the public inputs is valid for the public key of the
//     voter (derived from the voter's address provided).
//   - The census proof is valid for and matches with the user weight.
//   - The ballot proof is valid for the public inputs.
//
// To verify the vote package, the circuit requires the following public inputs:
//   - The public inputs of the ballot proof circuit (including user weight).
//   - The ecdsa signature of the public inputs.
//   - The voter's ecdsa public key.
//   - The census proof.
//   - The ballot proof (in the Gnark format, read more: https://github.com/vocdoni/circom2gnark).
package verifyvote

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/vocdoni/gnark-crypto-primitives/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
)

type VerifyVoteCircuit struct {
	Address     frontend.Variable                      `gnark:",public"`
	InputsHash  emulated.Element[emulated.Secp256k1Fr] `gnark:",public"`
	Signature   ecdsa.Signature[emulated.Secp256k1Fr]
	PublicKey   ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	BallotProof circuits.CircomProof
	CensusProof circuits.CensusProof
}

func (c *VerifyVoteCircuit) Define(api frontend.API) error {
	// check the signature of the inputs hash
	c.PublicKey.Verify(api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp](), &c.InputsHash, &c.Signature)
	// verify the census proof
	api.Println(c.CensusProof.Key, c.CensusProof.Value, c.CensusProof.Root)
	if err := arbo.CheckProof(api, c.CensusProof.Key, c.CensusProof.Value,
		c.CensusProof.Root, c.CensusProof.Siblings[:]); err != nil {
		return fmt.Errorf("error verifying census proof: %w", err)
	}
	// verify the ballot proof
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.BallotProof.Vk, c.BallotProof.Proof,
		c.BallotProof.PublicInputs, stdgroth16.WithCompleteArithmetic())
}
