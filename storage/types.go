package storage

import (
	"math/big"

	"github.com/consensys/gnark/backend/groth16"
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
	ProcessID       types.HexBytes     `json:"processId"`
	VoterWeight     *big.Int           `json:"voterWeight"`
	Nullifier       types.HexBytes     `json:"nullifier"`
	Commitment      types.HexBytes     `json:"commitment"`
	EncryptedBallot elgamal.Ciphertext `json:"encryptedBallot"`
	Address         types.HexBytes     `json:"address"`

	Proof groth16.Proof `json:"proof"`
}

type Ballot struct {
	ProcessID        types.HexBytes     `json:"processId"`
	VoterWeight      *big.Int           `json:"voterWeight"`
	EncryptedBallot  elgamal.Ciphertext `json:"encryptedBallot"`
	Nullifier        types.HexBytes     `json:"nullifier"`
	Commitment       types.HexBytes     `json:"commitment"`
	Address          types.HexBytes     `json:"address"`
	BallotInputsHash types.HexBytes     `json:"ballotInputsHash"`
	BallotProof      CircomProof        `json:"ballotProof"`
	Signature        types.HexBytes     `json:"signature"`
	CensusProof      CensusProof        `json:"censusProof"`
}

type CensusProof struct {
	Root     types.HexBytes   `json:"root"`
	Siblings []types.HexBytes `json:"siblings"`
}

type CircomProof struct {
	A        []string   `json:"pi_a"`
	B        [][]string `json:"pi_b"`
	C        []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
}

type AggregatedBallotBatch struct {
	ProcessID types.HexBytes     `json:"processId"`
	Proof     groth16.Proof      `json:"proof"`
	Ballots   []AggregatedBallot `json:"ballots"`
}
type AggregatedBallot struct {
	Nullifier       types.HexBytes     `json:"nullifiers"`
	Commitment      types.HexBytes     `json:"commitments"`
	Address         types.HexBytes     `json:"address"`
	EncryptedBallot elgamal.Ciphertext `json:"encryptedBallots"`
}
