package types

// CensusProof is the struct to represent a proof of inclusion in the census
// tree. It will be provided by the user to verify that he or she can vote in
// the process.
type CensusProof struct {
	Root      HexBytes   `json:"root"`
	Address   HexBytes   `json:"address"`
	Weight    HexBytes   `json:"weight"`
	Siblings  []HexBytes `json:"siblings"`
	Existence bool       `json:"-"`
}
