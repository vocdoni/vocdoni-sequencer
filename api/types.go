package api

import (
	"github.com/vocdoni/circom2gnark/parser"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// Process is the struct to create a new voting process
type Process struct {
	CensusRoot types.HexBytes   `json:"censusRoot"`
	BallotMode types.BallotMode `json:"ballotRules"`
	Nonce      uint64           `json:"nonce"`
	ChainID    uint32           `json:"chainId"`
	Signature  []byte           `json:"signature"`
}

// ProcessResponse represents the response of a voting process
type ProcessResponse struct {
	ProcessID        types.HexBytes  `json:"processId"`
	EncryptionPubKey [2]types.BigInt `json:"encryptionPubKey,omitempty"`
	StateRoot        types.HexBytes  `json:"stateRoot,omitempty"`
	ChainID          uint32          `json:"chainId,omitempty"`
	Nonce            uint64          `json:"nonce,omitempty"`
	Address          string          `json:"address,omitempty"`
}

// Vote is the struct to represent a vote in the system. It will be provided by
// the user to cast a vote in a process.
type Vote struct {
	ProcessID        types.HexBytes      `json:"processId"`
	Commitment       types.HexBytes      `json:"commitment"`
	Nullifier        types.HexBytes      `json:"nullifier"`
	Cipherfields     elgamal.Ciphertexts `json:"cipherfields"`
	CensusProof      types.CensusProof   `json:"censusProof"`
	BallotProof      parser.CircomProof  `json:"ballotProof"`
	BallotInputsHash types.HexBytes      `json:"ballotInputsHash"`
	PublicKey        types.HexBytes      `json:"publicKey"`
	Signature        types.HexBytes      `json:"signature"`
}
