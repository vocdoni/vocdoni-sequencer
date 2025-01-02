package ecc

import "math/big"

// BigToFF function returns the finite field representation of the big.Int
// provided. It uses the curve scalar field to represent the provided number.
func BigToFF(baseField, iv *big.Int) *big.Int {
	z := big.NewInt(0)
	if c := iv.Cmp(baseField); c == 0 {
		return z
	} else if c != 1 && iv.Cmp(z) != -1 {
		return iv
	}
	return z.Mod(iv, baseField)
}
