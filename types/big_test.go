package types

import (
	"encoding/json"
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/fxamacker/cbor/v2"
)

func TestBigMarshalUnmarshalJSON(t *testing.T) {
	c := qt.New(t)
	bi := (*BigInt)(big.NewInt(1234567890))
	jsonBigInt := map[string]*BigInt{
		"bi": bi,
	}
	bBigInt, err := json.Marshal(jsonBigInt)
	c.Assert(err, qt.IsNil)

	var unmarshaled map[string]*BigInt
	c.Assert(json.Unmarshal(bBigInt, &unmarshaled), qt.IsNil)
	c.Assert(unmarshaled["bi"], qt.DeepEquals, bi)
}

func TestBigMarshalUnmarshalCBOR(t *testing.T) {
	c := qt.New(t)
	bi := (*BigInt)(big.NewInt(1234567890))
	cborBigInt := map[string]*BigInt{
		"bi": bi,
	}
	bBigInt, err := cbor.Marshal(cborBigInt)
	c.Assert(err, qt.IsNil)

	var unmarshaled map[string]*BigInt
	c.Assert(cbor.Unmarshal(bBigInt, &unmarshaled), qt.IsNil)
	c.Assert(unmarshaled["bi"], qt.DeepEquals, bi)
}
