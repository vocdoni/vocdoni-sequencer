package circuits

import (
	"math/big"

	"github.com/vocdoni/arbo"
)

// BigIntArrayToN pads the big.Int array to n elements, if needed,
// with zeros.
func BigIntArrayToN(arr []*big.Int, n int) []*big.Int {
	bigArr := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		if i < len(arr) {
			bigArr[i] = arr[i]
		} else {
			bigArr[i] = big.NewInt(0)
		}
	}
	return bigArr
}

// BigIntArrayToStringArray converts the big.Int array to a string array.
func BigIntArrayToStringArray(arr []*big.Int, n int) []string {
	strArr := []string{}
	for _, b := range BigIntArrayToN(arr, n) {
		strArr = append(strArr, b.String())
	}
	return strArr
}

// BigIntToMIMCHash transform the inputs hash to the field provided, if it is
// not done, the circuit will transform it during the witness calculation and
// the resulting hash will be different. Moreover, the input hash should be
// 32 bytes so if it is not, fill with zeros at the beginning of the bytes
// representation.
func BigIntToMIMCHash(input, base *big.Int) []byte {
	hash := arbo.BigToFF(base, input).Bytes()
	for len(hash) < 32 {
		hash = append([]byte{0}, hash...)
	}
	return hash
}
