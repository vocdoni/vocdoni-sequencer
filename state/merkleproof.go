package state

import (
	"errors"
	"fmt"

	"github.com/vocdoni/arbo"
)

// ArboProof stores the proof in arbo native types
type ArboProof struct {
	// Key+Value hashed through Siblings path, should produce Root hash
	Root      []byte
	Siblings  [][]byte
	Key       []byte
	Value     []byte
	Existence bool
}

// GenArboProof generates a ArboProof for the given key
func (o *State) GenArboProof(k []byte) (*ArboProof, error) {
	root, err := o.tree.Root()
	if err != nil {
		return nil, err
	}
	leafK, leafV, packedSiblings, existence, err := o.tree.GenProof(k)
	if err != nil {
		return nil, err
	}
	unpackedSiblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, packedSiblings)
	if err != nil {
		return nil, err
	}
	return &ArboProof{
		Root:      root,
		Siblings:  unpackedSiblings,
		Key:       leafK,
		Value:     leafV,
		Existence: existence,
	}, nil
}

// ArboProofsFromAddOrUpdate generates an ArboProof before adding (or updating) the given leaf,
// and another ArboProof after updating, and returns both.
func (o *State) ArboProofsFromAddOrUpdate(k []byte, v []byte) (*ArboProof, *ArboProof, error) {
	mpBefore, err := o.GenArboProof(k)
	if err != nil {
		return nil, nil, err
	}
	if _, _, err := o.tree.Get(k); errors.Is(err, arbo.ErrKeyNotFound) {
		if err := o.tree.Add(k, v); err != nil {
			return nil, nil, fmt.Errorf("add key failed: %w", err)
		}
	} else {
		if err := o.tree.Update(k, v); err != nil {
			return nil, nil, fmt.Errorf("update key failed: %w", err)
		}
	}
	mpAfter, err := o.GenArboProof(k)
	if err != nil {
		return nil, nil, err
	}
	return mpBefore, mpAfter, nil
}
