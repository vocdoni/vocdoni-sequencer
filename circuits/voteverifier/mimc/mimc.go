package mimc

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

var curves map[string]ecc.ID

func init() {
	curves = make(map[string]ecc.ID)
	for _, c := range gnark.Curves() {
		fHex := c.ScalarField().Text(16)
		curves[fHex] = c
	}
}

type MiMC struct {
	params []big.Int           // slice containing constants for the encryption rounds
	id     ecc.ID              // id needed to know which encryption function to use
	h      frontend.Variable   // current vector in the Miyaguchi–Preneel scheme
	data   []frontend.Variable // state storage. data is updated when Write() is called. Sum sums the data.
	api    frontend.API        // underlying constraint system
}

// TODO: Try to wrap the std hash function setting the current compiler field to
// the desired curve instead of use this reimplementation.

// NewMiMC function returns a initialized MiMC hash function into the curve
// for the given field. If field is nil, the default api compiler field is
// used. If the curve is not supported, an error is returned.
func NewMiMC(api frontend.API, field *big.Int) (MiMC, error) {
	if field == nil {
		field = api.Compiler().Field()
	}
	if constructor, ok := newMimc[fieldToCurve(field)]; ok {
		return constructor(api), nil
	}
	return MiMC{}, errors.New("unknown curve id")
}

// Write adds more data to the running hash.
func (h *MiMC) Write(data ...frontend.Variable) {
	h.data = append(h.data, data...)
}

// Reset resets the Hash to its initial state.
func (h *MiMC) Reset() {
	h.data = nil
	h.h = 0
}

// Sum hash using [Miyaguchi–Preneel] where the XOR operation is replaced by
// field addition.
//
// [Miyaguchi–Preneel]: https://en.wikipedia.org/wiki/One-way_compression_function
func (h *MiMC) Sum() frontend.Variable {
	//h.Write(data...)s
	for _, stream := range h.data {
		r := encryptFuncs[h.id](*h, stream)
		h.h = h.api.Add(h.h, r, stream)
	}
	h.data = nil // flush the data already hashed
	return h.h
}

func fieldToCurve(q *big.Int) ecc.ID {
	fHex := q.Text(16)
	curve, ok := curves[fHex]
	if !ok {
		return ecc.UNKNOWN
	}
	return curve
}
