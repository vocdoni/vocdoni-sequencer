package poseidon

import (
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

func MultiPoseidon(inputs ...*big.Int) (*big.Int, error) {
	if len(inputs) > 256 {
		return nil, fmt.Errorf("too many inputs")
	} else if len(inputs) == 0 {
		return nil, fmt.Errorf("no inputs provided")
	}
	// calculate chunk hashes
	hashes := []*big.Int{}
	chunk := []*big.Int{}
	for _, input := range inputs {
		if len(chunk) == 16 {
			hash, err := poseidon.Hash(chunk)
			if err != nil {
				return nil, err
			}
			hashes = append(hashes, hash)
			chunk = []*big.Int{}
		}
		chunk = append(chunk, input)
	}
	// if the final chunk is not empty, hash it to get the last chunk hash
	if len(chunk) > 0 {
		hash, err := poseidon.Hash(chunk)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	// if there is only one chunk hash, return it
	if len(hashes) == 1 {
		return hashes[0], nil
	}
	// return the hash of all chunk hashes
	return poseidon.Hash(hashes)
}
