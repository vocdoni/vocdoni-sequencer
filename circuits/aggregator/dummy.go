package aggregator

import (
	"errors"

	"github.com/consensys/gnark/frontend"
)

type DummyCircuit struct {
	A frontend.Variable `gnark:",public"`
}

func DummyWitness() *DummyCircuit {
	return &DummyCircuit{1}
}

func (c *DummyCircuit) Define(api frontend.API) error {
	cmter, ok := api.(frontend.Committer)
	if !ok {
		return errors.New("api not committer")
	}
	b, err := cmter.Commit(frontend.Variable(1))
	if err != nil {
		return err
	}
	api.AssertIsDifferent(b, 0)
	return nil
}
