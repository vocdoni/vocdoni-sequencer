package types

import "go.vocdoni.io/dvote/types"

// CensusProof is the struct to represent a proof of inclusion in the census
// tree. It will be provided by the user to verify that he or she can vote in
// the process.
type CensusProof struct {
	Root      types.HexBytes   `json:"root"`
	Address   types.HexBytes   `json:"address"`
	Weight    types.HexBytes   `json:"weight"`
	Siblings  []types.HexBytes `json:"siblings"`
	Existence bool             `json:"-"`
}
