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
//   - Msg: The hash of the public inputs of the ballot proof but as scalar
//     element of the Secp256k1 curve.
//   - PublicKey: The public key of the voter.
//   - Signature: The signature of the inputs hash.
//   - CircomProof: The proof of the ballot proof.
//   - CircomPublicInputsHash: The hash of the public inputs of the ballot proof.
//   - CircomVerificationKey: The verification key of the ballot proof (fixed).
//
// Note: The inputs of the circom circuit should be provided as elements of
// the bn254 scalar field, and the inputs of the gnark circuit should be
// provided as elements of the current compiler field (BLS12377 expected).
package voteverifier

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/vocdoni/gnark-crypto-primitives/emulated/bn254/twistededwards/mimc7"
	address "github.com/vocdoni/gnark-crypto-primitives/emulated/ecdsa"
	"github.com/vocdoni/gnark-crypto-primitives/tree/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
)

type VerifyVoteCircuit struct {
	// Single public input that is the hash of all the public inputs
	InputsHash frontend.Variable `gnark:",public"`
	// The following variables are priv-public inputs, so should be hashed
	// and compared with the InputsHash or CircomPublicInputsHash. All the
	// variables should be hashed in the same order as they are defined here.

	// BallotMode is a struct that contains the common values for the ballot
	circuits.BallotMode[emulated.Element[sw_bn254.ScalarField]]
	// User public inputs
	Address         emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	UserWeight      emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	Nullifier       emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	Commitment      emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	ProcessId       emulated.Element[sw_bn254.ScalarField]          // Part of CircomPublicInputsHash & InputsHash
	EncryptedBallot [8][2][2]emulated.Element[sw_bn254.ScalarField] // Part of CircomPublicInputsHash & InputsHash
	CensusRoot      frontend.Variable                               // Part of InputsHash
	CensusSiblings  [160]frontend.Variable
	// The following variables are private inputs and they are used to verify
	// the user identity ownership
	Msg       emulated.Element[emulated.Secp256k1Fr]
	PublicKey ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	Signature ecdsa.Signature[emulated.Secp256k1Fr]
	// The following variables are private inputs and they are used to verify
	// the ballot proof
	CircomProof            groth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	CircomPublicInputsHash groth16.Witness[sw_bn254.ScalarField]
	CircomVerificationKey  groth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
}

// nativeMiMCHashFn is a hash function that hashes the data provided using the
// mimc hash function and the current compiler field. It is used to hash the
// leaves of the census tree during the proof verification.
func nativeMiMCHashFn(api frontend.API, data ...frontend.Variable) (frontend.Variable, error) {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return 0, fmt.Errorf("failed to create native MiMC hash function: %w", err)
	}
	h.Write(data...)
	return h.Sum(), nil
}

func (c VerifyVoteCircuit) checkCircomInputsHash(api frontend.API) {
	// ensure that the circom public inputs hash only contains a single public
	// input (the hash of all the public-private inputs)
	api.AssertIsEqual(len(c.CircomPublicInputsHash.Public), 1)
	// group the circom public-private inputs to hash them
	hashInputs := []emulated.Element[sw_bn254.ScalarField]{
		c.MaxCount, c.ForceUniqueness, c.MaxValue, c.MinValue, c.MaxTotalCost,
		c.MinTotalCost, c.CostExp, c.CostFromWeight, c.Address, c.UserWeight,
		c.ProcessId, c.EncryptionPubKey[0], c.EncryptionPubKey[1], c.Nullifier,
		c.Commitment,
	}
	for i := 0; i < len(c.EncryptedBallot); i++ {
		for j := 0; j < len(c.EncryptedBallot[i]); j++ {
			hashInputs = append(hashInputs, c.EncryptedBallot[i][j][:]...)
		}
	}
	// hash the circom public-private inputs and compare them with the unique
	// public input of the circom circuit
	h, err := mimc7.NewMiMC(api)
	if err != nil {
		api.Println("failed to create emulated MiMC hash function: %w", err)
		api.AssertIsEqual(0, 1)
	}
	h.Write(hashInputs...)
	h.AssertSumIsEqual(c.CircomPublicInputsHash.Public[0])
}

// checkInputsHash hashes the inputs provided by the user and compares them with
// the unique public input of the circuit. It returns an error if the hash of
// the inputs does not match the unique public input of the circuit. The inputs
// hash is calculated by hashing all the inputs provided by the user, including
// the census root, except the user weight and siblings.
func (c VerifyVoteCircuit) checkInputsHash(api frontend.API) {
	// group all, including the census root, except the user weight
	emulatedHashInputs := []emulated.Element[sw_bn254.ScalarField]{
		c.ProcessId, c.EncryptionPubKey[0], c.EncryptionPubKey[1], c.MaxCount,
		c.ForceUniqueness, c.MaxValue, c.MinValue, c.MaxTotalCost, c.MinTotalCost,
		c.CostExp, c.CostFromWeight, c.Address, c.Nullifier, c.Commitment,
	}
	for i := 0; i < len(c.EncryptedBallot); i++ {
		for j := 0; j < len(c.EncryptedBallot[i]); j++ {
			emulatedHashInputs = append(emulatedHashInputs, c.EncryptedBallot[i][j][:]...)
		}
	}
	// convert all the emulated elements to the current compiler field
	hashInputs := []frontend.Variable{c.CensusRoot}
	var err error
	for i := 0; i < len(emulatedHashInputs); i++ {
		input, err := utils.PackScalarToVar(api, emulatedHashInputs[i])
		if err != nil {
			api.Println("failed to convert emulated to var: %w", err)
			api.AssertIsEqual(0, 1)
		}
		hashInputs = append(hashInputs, input)
	}
	// hash the inputs (including census root) and compare them with the unique
	// public input of the circuit
	inputsHash, err := nativeMiMCHashFn(api, hashInputs...)
	if err != nil {
		api.Println("failed to hash inputs: %w", err)
		api.AssertIsEqual(0, 1)
	}
	api.AssertIsEqual(c.InputsHash, inputsHash)
}

// verifySigForAddress function verifies the signature provided with the public
// key and message provided. It derives the address from the public key and
// verifies it matches the provided address. It returns the derived address in
// little endian format and an error if the verification fails.
func (c VerifyVoteCircuit) verifySigForAddress(api frontend.API) {
	// check the signature of the circom inputs hash provided as Secp256k1
	// emulated element
	c.PublicKey.Verify(api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp](), &c.Msg, &c.Signature)
	// derive the address from the public key and check it matches the provided
	// address
	derivedAddr, err := address.DeriveAddress(api, c.PublicKey)
	if err != nil {
		api.Println("failed to derive address: %w", err)
		api.AssertIsEqual(0, 1)
	}
	// convert the derived address from the scalar field of the bn254 curve to
	// the current compiler field as a variable to compare it with the address
	// derived from the public key and to be used in the census proof
	address, err := utils.PackScalarToVar(api, c.Address)
	if err != nil {
		api.Println("failed to convert emulated to var: %w", err)
		api.AssertIsEqual(0, 1)
	}
	api.AssertIsEqual(address, derivedAddr)
}

func (c VerifyVoteCircuit) verifyCircomProof(api frontend.API) {
	// verify the ballot proof over the bn254 curve (used by circom)
	verifier, err := groth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		api.Println("failed to create BN254 verifier: %w", err)
		api.AssertIsEqual(0, 1)
	}
	if err := verifier.AssertProof(c.CircomVerificationKey, c.CircomProof,
		c.CircomPublicInputsHash, groth16.WithCompleteArithmetic(),
	); err != nil {
		api.Println("failed to verify circom proof: %w", err)
		api.AssertIsEqual(0, 1)
	}
}

func (c VerifyVoteCircuit) verifyCensusProof(api frontend.API) {
	// convert user address to bytes to swap the endianness
	bAddress, err := utils.ElemToU8(api, c.Address)
	if err != nil {
		api.Println("failed to convert element to bytes: %w", err)
		api.AssertIsEqual(0, 1)
	}
	// swap the endianness of the address to le to be used in the census proof
	address, err := utils.U8ToVar(api, bAddress[:20])
	if err != nil {
		api.Println("failed to convert bytes to var: %w", err)
		api.AssertIsEqual(0, 1)
	}
	// convert the user weight from the scalar field of the bn254 curve to the
	// current compiler field as a variable to be used in the census proof
	userWeight, err := utils.PackScalarToVar(api, c.UserWeight)
	if err != nil {
		api.Println("failed to convert emulated to var: %w", err)
		api.AssertIsEqual(0, 1)
	}
	// verify the census proof using the derived address and the user weight
	// provided as leaf key-value, adn the root and siblings provided
	if err := arbo.CheckInclusionProof(api, nativeMiMCHashFn, address,
		userWeight, c.CensusRoot, c.CensusSiblings[:]); err != nil {
		api.Println("failed to check census proof: %w", err)
		api.AssertIsEqual(0, 1)
	}
}

func (c VerifyVoteCircuit) Define(api frontend.API) error {
	// check the hash of the inputs provided by the user
	c.checkInputsHash(api)
	// check the hash of the circom inputs provided by the user
	c.checkCircomInputsHash(api)
	// verify the signature of the public inputs
	c.verifySigForAddress(api)
	// verify the census proof
	c.verifyCensusProof(api)
	// verify the ballot proof
	c.verifyCircomProof(api)
	return nil
}
