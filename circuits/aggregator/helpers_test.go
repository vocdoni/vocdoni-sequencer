package aggregator

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

type helperCircuit struct {
	One emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
	Two emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
}

func (c helperCircuit) Define(api frontend.API) error {
	return nil
}

func TestInnerOuterEmulatedInputs(t *testing.T) {
	assert := test.NewAssert(t)
	// hash the inputs to generate the inputs hash
	one := new(big.Int).SetBytes(util.RandomBytes(32))
	two := new(big.Int).SetBytes(util.RandomBytes(32))
	emulatedOne := emulated.ValueOf[sw_bn254.ScalarField](one)
	emulatedTwo := emulated.ValueOf[sw_bn254.ScalarField](two)

	fullWitness, err := frontend.NewWitness(helperCircuit{emulatedOne, emulatedTwo}, ecc.BLS12_377.ScalarField())
	assert.NoError(err)

	pubWitness, err := fullWitness.Public()
	assert.NoError(err)

	emulatedPubWitness, err := VectorToEmulatedElements[sw_bls12377.ScalarField](pubWitness.Vector())
	assert.NoError(err)

	for i, limb := range emulatedPubWitness[0].Limbs {
		assert.Equal(limb, emulatedOne.Limbs[i])
	}

	for i, limb := range emulatedPubWitness[1].Limbs {
		assert.Equal(limb, emulatedTwo.Limbs[i])
	}
}
