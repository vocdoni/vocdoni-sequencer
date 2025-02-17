package dummy

import (
	"errors"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

type Circuit struct {
	nbConstraints int
	SecretInput   frontend.Variable                      `gnark:",secret"`
	PublicInput   emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
	cmtr, ok := api.(frontend.Committer)
	if !ok {
		return errors.New("api is not a commiter")
	}
	public, err := cmtr.Commit(c.PublicInput.Limbs...)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(public, 0)

	res := api.Mul(c.SecretInput, c.SecretInput)
	for i := 2; i < c.nbConstraints; i++ {
		res = api.Mul(res, c.SecretInput)
	}
	return nil
}

// Placeholder function returns the placeholder of a dummy circuit for
// the constraint.ConstraintSystem provided.
func Placeholder(mainCircuit constraint.ConstraintSystem) *Circuit {
	return &Circuit{nbConstraints: mainCircuit.GetNbConstraints()}
}

// PlaceholderWithConstraints returns the placeholder of a dummy circuit
// with the desired number of constraints.
func PlaceholderWithConstraints(nbConstraints int) *Circuit {
	return &Circuit{nbConstraints: nbConstraints}
}

// Assignment returns the assignment of a dummy circuit.
func Assignment(publicInput frontend.Variable) *Circuit {
	return &Circuit{
		PublicInput: emulated.ValueOf[sw_bn254.ScalarField](publicInput),
		SecretInput: 1,
	}
}
