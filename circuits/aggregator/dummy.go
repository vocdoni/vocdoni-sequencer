package aggregator

import (
	"errors"

	"github.com/consensys/gnark/frontend"
)

type DummyCircuit struct {
	A frontend.Variable `gnark:",public"`
	B frontend.Variable
}

func DummyWitness() *DummyCircuit {
	return &DummyCircuit{1, 1}
}

func (c *DummyCircuit) Define(api frontend.API) error {
	cmter, ok := api.(frontend.Committer)
	if !ok {
		return errors.New("api not committer")
	}
	b, err := cmter.Commit(c.B)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(b, 0)
	return nil
}
