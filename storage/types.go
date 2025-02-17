package storage

import (
	"math/big"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	recursion "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

type Process struct {
	CensusRoot    types.HexBytes   `json:"censusRoot"`
	BallotMode    types.BallotMode `json:"ballotMode"`
	MetadataHash  types.HexBytes   `json:"metadataID"`
	EncryptionKey EncryptionKeys   `json:"encryptionKey"`
}

type EncryptionKeys struct {
	X          *big.Int `json:"publicKeyX"`
	Y          *big.Int `json:"publicKeyY"`
	PrivateKey *big.Int `json:"-"`
}

type VerifiedBallot struct {
	ProcessID       types.HexBytes `json:"processId"`
	VoterWeight     *big.Int       `json:"voterWeight"`
	Nullifier       types.HexBytes `json:"nullifier"`
	Commitment      types.HexBytes `json:"commitment"`
	EncryptedBallot elgamal.Ballot `json:"encryptedBallot"`
	Address         types.HexBytes `json:"address"`
	Proof           groth16.Proof  `json:"proof"`
}

type Ballot struct {
	ProcessID        types.HexBytes                                        `json:"processId"`
	VoterWeight      types.HexBytes                                        `json:"voterWeight"`
	EncryptedBallot  elgamal.Ballot                                        `json:"encryptedBallot"`
	Nullifier        types.HexBytes                                        `json:"nullifier"`
	Commitment       types.HexBytes                                        `json:"commitment"`
	Address          types.HexBytes                                        `json:"address"`
	BallotInputsHash types.HexBytes                                        `json:"ballotInputsHash"`
	BallotProof      recursion.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine] `json:"ballotProof"`
	Signature        types.BallotSignature                                 `json:"signature"`
	CensusProof      types.CensusProof                                     `json:"censusProof"`
	PubKey           types.HexBytes                                        `json:"publicKey"`
}

type AggregatorBallotBatch struct {
	ProcessID types.HexBytes     `json:"processId"`
	Proof     groth16.Proof      `json:"proof"`
	Ballots   []AggregatorBallot `json:"ballots"`
}
type AggregatorBallot struct {
	Nullifier       types.HexBytes     `json:"nullifiers"`
	Commitment      types.HexBytes     `json:"commitments"`
	Address         types.HexBytes     `json:"address"`
	EncryptedBallot elgamal.Ciphertext `json:"encryptedBallots"`
}
