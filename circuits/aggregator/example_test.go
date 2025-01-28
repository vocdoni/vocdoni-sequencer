package aggregator

import (
	"log"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

type circuit struct {
	Input    emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
	EmuInput emulated.Element[sw_bls12377.ScalarField]
}

func (c circuit) Define(api frontend.API) error {
	resInput, err := utils.PackScalarToVar(api, c.Input)
	if err != nil {
		return err
	}
	api.Println("input", resInput)

	resEmuInput, err := utils.PackScalarToVar(api, c.EmuInput)
	if err != nil {
		return err
	}
	api.Println("emuInput", resEmuInput)

	return nil
}

func TestLostLimbsExample(t *testing.T) {
	assert := test.NewAssert(t)

	r := new(big.Int).SetBytes(util.RandomBytes(31))
	log.Println(r)
	input := emulated.ValueOf[sw_bn254.ScalarField](r)
	expected := emulated.ValueOf[sw_bls12377.ScalarField](r)

	innerWitness, err := frontend.NewWitness(circuit{input, expected}, ecc.BLS12_377.ScalarField())
	assert.NoError(err)

	pubInnerWitness, err := innerWitness.Public()
	assert.NoError(err)

	recursionPubWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](pubInnerWitness)
	assert.NoError(err)

	log.Println(input.Limbs)                         // [279681381222631249 13667822273213900685 4788813682071594981 2286825782783219846]
	log.Println(recursionPubWitness.Public[0].Limbs) // [279681381222631249 0 0 0]
	log.Println(expected.Limbs)

	assert.SolvingSucceeded(&circuit{}, &circuit{input, expected},
		test.WithCurves(ecc.BLS12_377),
		test.WithBackends(backend.GROTH16))
}
