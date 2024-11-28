// voteverifier package contains the Gnark circuit definition that verifies a
// vote package to be aggregated by the vote aggregator and included in a new
// state transition. A vote package includes a ballot proof (generated from
// a circom circuit with snarkjs), the public inputs of the ballot proof
// circuit, the signature of the public inputs, and a census proof. The vote
// package is valid if the ballot proof is valid if:
//   - The public inputs of the ballot proof are valid (match with the hash
//     provided).
//   - The ballot proof is valid for the public inputs.
//   - The public inputs of the verification circuit are valid (match with the
//     hash provided).
//   - The signature of the public inputs is valid for the public key of the
//     voter.
//   - The address derived from the user public key is part of the census, and
//     verifies the census proof with the user weight provided.
//
// Public inputs:
//   - InputsHash: The hash of all the inputs that could be public.
//
// Private inputs:
//   - MaxCount: The maximum number of votes that can be included in the
//     package.
//   - ForceUniqueness: A flag that indicates if the votes in the package
//     values should be unique.
//   - MaxValue: The maximum value that a vote can have.
//   - MinValue: The minimum value that a vote can have.
//   - MaxTotalCost: The maximum total cost of the votes in the package.
//   - MinTotalCost: The minimum total cost of the votes in the package.
//   - CostExp: The exponent used to calculate the cost of a vote.
//   - CostFromWeight: A flag that indicates if the cost of a vote is
//     calculated from the weight of the user or from the value of the vote.
//   - Address: The address of the voter.
//   - UserWeight: The weight of the user that is voting.
//   - EncryptionPubKey: The public key used to encrypt the votes in the
//     package.
//   - Nullifier: The nullifier of the votes in the package.
//   - Commitment: The commitment of the votes in the package.
//   - ProcessId: The process id of the votes in the package.
//   - EncryptedBallot: The encrypted votes in the package.
//   - CensusRoot: The root of the census tree.
//   - CensusSiblings: The siblings of the address in the census tree.
//   - PublicKey: The public key of the voter.
//   - Signature: The signature of the inputs hash.
//   - CircomProof: The proof of the ballot proof.
//   - CircomPublicInputsHash: The hash of the public inputs of the ballot proof.
//   - CircomVerificationKey: The verification key of the ballot proof (fixed).
package voteverifier

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/vocdoni/gnark-crypto-primitives/address"
	"github.com/vocdoni/gnark-crypto-primitives/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/emulated/bn254/twistededwards/mimc7"
)

type VerifyVoteCircuit struct {
	// Single public input that is the hash of all the public inputs
	InputsHash frontend.Variable `gnark:",public"`
	// The following variables are priv-public inputs, so should be hashed
	// and compared with the InputsHash or CircomPublicInputsHash. All the
	// variables should be hashed in the same order as they are defined here.
	MaxCount         emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	ForceUniqueness  emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	MaxValue         emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	MinValue         emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	MaxTotalCost     emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	MinTotalCost     emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	CostExp          emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	CostFromWeight   emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	Address          emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	UserWeight       emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	EncryptionPubKey [2]emulated.Element[sw_bn254.ScalarField]       // Part of CircomPublicInputsHash & InputsHash
	Nullifier        emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	Commitment       emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	ProcessId        emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	EncryptedBallot  [8][2][2]emulated.Element[sw_bn254.ScalarField] // Part of CircomPublicInputsHash & InputsHash
	CensusRoot       frontend.Variable                               // Part of InputsHash
	CensusSiblings   [160]frontend.Variable
	// The following variables are private inputs and they are used to verify
	// the user identity ownership
	PublicKey ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	Signature ecdsa.Signature[emulated.Secp256k1Fr]
	// The following variables are private inputs and they are used to verify
	// the ballot proof
	CircomProof            groth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	CircomPublicInputsHash groth16.Witness[sw_bn254.ScalarField]
	CircomVerificationKey  groth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
}

// circomInputs returns the circom public-private inputs that are used to hash
// them and compare them with the unique public input of the circom circuit. It
// asserts that the length of the flat encrypted ballot is correct and returns
// the circom public-private inputs.
func (c *VerifyVoteCircuit) circomInputs(api frontend.API) []emulated.Element[sw_bn254.ScalarField] {
	// group the circom public-private inputs to hash them
	circomPubPrivInputs := []emulated.Element[sw_bn254.ScalarField]{
		c.MaxCount, c.ForceUniqueness, c.MaxValue, c.MinValue, c.MaxTotalCost,
		c.MinTotalCost, c.CostExp, c.CostFromWeight, c.Address, c.UserWeight,
		c.ProcessId, c.EncryptionPubKey[0], c.EncryptionPubKey[1], c.Nullifier,
		c.Commitment,
	}
	// flatten the encrypted ballot and append to the circom public-private
	// inputs
	var flatEncryptedBallot []emulated.Element[sw_bn254.ScalarField]
	for i := 0; i < len(c.EncryptedBallot); i++ {
		for j := 0; j < len(c.EncryptedBallot[i]); j++ {
			flatEncryptedBallot = append(flatEncryptedBallot, c.EncryptedBallot[i][j][:]...)
		}
	}
	// check the length of the resulting flat encrypted ballot and append it
	api.AssertIsEqual(len(flatEncryptedBallot), len(c.EncryptedBallot)*len(c.EncryptedBallot[0])*len(c.EncryptedBallot[0][0]))
	return append(circomPubPrivInputs, flatEncryptedBallot...)
}

// checkCircomProof checks the circom proof provided by the user. It hashes the
// circom public-private inputs and compares them with the unique public input
// of the circom circuit. It verifies the ballot proof using the verification
// key provided. It returns the hash of the circom public-private inputs if the
// verification succeeds and an error if it fails.
func (c *VerifyVoteCircuit) checkCircomProof(api frontend.API) error {
	// check that the circom witness only contains a single public input
	// (the hash of all the public-private inputs)
	api.AssertIsEqual(len(c.CircomPublicInputsHash.Public), 1)
	// hash the circom public-private inputs and compare them with the unique
	// public input of the circom circuit
	circomInputs := c.circomInputs(api)
	h, err := mimc7.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(circomInputs...)
	h.AssertSumIsEqual(c.CircomPublicInputsHash.Public[0])
	// api.AssertIsEqual(circomInputsHash, pubCircomInputsHash)
	// verify the ballot proof over the bn254 curve (used by circom)
	verifier, err := groth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	// return circomInputsHash, verifier.AssertProof(
	return verifier.AssertProof(
		c.CircomVerificationKey, c.CircomProof, c.CircomPublicInputsHash,
		groth16.WithCompleteArithmetic())
}

func (c *VerifyVoteCircuit) Define(api frontend.API) error {
	// check circom circuit stuff
	if err := c.checkCircomProof(api); err != nil {
		return err
	}
	_, err := packScalarToVar(api, &c.CircomPublicInputsHash.Public[0])
	if err != nil {
		return err
	}
	// // hash the circom inputs with the census root to be compared with the
	// // inputs hash provided by the user
	// inputsHash, err := censusHashFn(api, append(cInputs, c.CensusRoot)...)
	// if err != nil {
	// 	return err
	// }
	// // convert the inputs hash to the scalar field of the bn254 curve to be
	// // compared with the inputs hash provided by the user
	// api.AssertIsEqual(c.InputsHash, inputsHash)
	// check the signature of the circom inputs hash
	// msg := emulated.ValueOf[emparams.Secp256k1Fr](circomInputsHash)
	// c.PublicKey.Verify(api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp](), &msg, &c.Signature)
	// derive the address from the public key and check it matches the provided
	// address
	derivedAddr, censusAddress, err := address.DeriveAddress(api, c.PublicKey)
	if err != nil {
		return err
	}
	address, err := packScalarToVar(api, &c.Address)
	if err != nil {
		return err
	}
	api.AssertIsEqual(address, derivedAddr)
	userWeight, err := packScalarToVar(api, &c.UserWeight)
	if err != nil {
		return err
	}
	// verify the census proof using the derived address and the user weight
	// provided as leaf key-value, adn the root and siblings provided
	if err := arbo.CheckInclusionProof(api, censusHashFn, censusAddress,
		userWeight, c.CensusRoot, c.CensusSiblings[:]); err != nil {
		return err
	}
	return nil
}
