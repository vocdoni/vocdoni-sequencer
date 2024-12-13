package api

import "github.com/vocdoni/vocdoni-z-sandbox/types"

// Process is the struct to create a new voting process
type Process struct {
	CensusRoot types.HexBytes `json:"censusRoot"`
	BallotMode BallotMode     `json:"ballotRules"`
	Nonce      uint64         `json:"nonce"`
	ChainID    uint32         `json:"chainId"`
	Signature  []byte         `json:"signature"`
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

// BallotMode is the struct to define the rules of a ballot
type BallotMode struct {
	MaxCount        uint8        `json:"maxCount"`
	ForceUniqueness bool         `json:"forceUniqueness"`
	MaxValue        types.BigInt `json:"maxValue"`
	MinValue        types.BigInt `json:"minValue"`
	MaxTotalCost    types.BigInt `json:"maxTotalCost"`
	MinTotalCost    types.BigInt `json:"minTotalCost"`
	CostExponent    uint8        `json:"costExponent"`
	CostFromWeight  bool         `json:"costFromWeight"`
}
