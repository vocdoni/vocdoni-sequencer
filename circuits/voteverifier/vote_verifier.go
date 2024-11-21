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
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/vocdoni/gnark-crypto-primitives/address"
	"github.com/vocdoni/gnark-crypto-primitives/arbo"
)

type VerifyVoteCircuit struct {
	Address               frontend.Variable                      `gnark:",public"`
	InputsHash            emulated.Element[emulated.Secp256k1Fr] `gnark:",public"`
	Signature             ecdsa.Signature[emulated.Secp256k1Fr]
	PublicKey             ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	CensusRoot            frontend.Variable
	CensusProofKey        frontend.Variable
	CensusProofValue      frontend.Variable
	CensusProofSiblings   [160]frontend.Variable
	CircomProof           groth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	CircomVerificationKey groth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	CircomPublicInputs    groth16.Witness[sw_bn254.ScalarField]
}

func hashFn(api frontend.API, data ...frontend.Variable) (frontend.Variable, error) {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return 0, err
	}
	h.Write(data...)
	return h.Sum(), nil
}

func (c *VerifyVoteCircuit) Define(api frontend.API) error {
	// check the signature of the inputs hash
	c.PublicKey.Verify(api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp](), &c.InputsHash, &c.Signature)
	// derive the address from the public key and check it matches the provided
	// address
	derivedAddr, err := address.DeriveAddress(api, c.PublicKey)
	if err != nil {
		return fmt.Errorf("derive address: %w", err)
	}
	// verify the census proof
	if err := arbo.CheckInclusionProof(api, hashFn, c.CensusProofKey, c.CensusProofValue,
		c.CensusRoot, c.CensusProofSiblings[:]); err != nil {
		return fmt.Errorf("error verifying census proof: %w", err)
	}
	api.AssertIsEqual(c.Address, derivedAddr)
	// verify the ballot proof
	verifier, err := groth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.CircomVerificationKey, c.CircomProof,
		c.CircomPublicInputs, groth16.WithCompleteArithmetic())
}
