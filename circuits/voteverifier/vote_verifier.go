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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
)

type VerifyVoteCircuit struct {
	ProcessID       frontend.Variable          `gnark:",public"`
	ProcessMetadata circuits.ProcessMetadata   `gnark:",public"`
	EncryptedBallot [8][2][2]frontend.Variable `gnark:",public"`
	Weight          frontend.Variable          `gnark:",public"`
	EncryptionKey   [2]frontend.Variable       `gnark:",public"`
	Nullifier       frontend.Variable          `gnark:",public"`
	Commitment      frontend.Variable          `gnark:",public"`
	CensusRoot      frontend.Variable          `gnark:",public"`
	BallotProof     circuits.CircomProof
	PublicKey       ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	Signature       ecdsa.Signature[emulated.Secp256k1Fr]
	CensusProof     circuits.CensusProof
}