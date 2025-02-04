package state

import (
	"bytes"
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

// ArboTransition stores a pair of leaves and root hashes, and a single path common to both proofs
type ArboTransition struct {
	// NewKey + NewValue hashed through Siblings path, should produce NewRoot hash
	NewRoot  []byte
	Siblings [][]byte
	NewKey   []byte
	NewValue []byte

	// OldKey + OldValue hashed through same Siblings should produce OldRoot hash
	OldRoot  []byte
	OldKey   []byte
	OldValue []byte
	IsOld0   int
	Fnc0     int
	Fnc1     int
}

// ArboTransitionFromArboProofPair generates a ArboTransition based on the pair of proofs passed
func ArboTransitionFromArboProofPair(before, after *ArboProof) *ArboTransition {
	//	Fnction
	//	fnc[0]  fnc[1]
	//	0       0       NOP
	//	0       1       UPDATE
	//	1       0       INSERT
	//	1       1       DELETE
	fnc0, fnc1 := 0, 0
	switch {
	case !before.Existence && !after.Existence: // exclusion, exclusion = NOOP
		fnc0, fnc1 = 0, 0
	case before.Existence && after.Existence: // inclusion, inclusion = UPDATE
		fnc0, fnc1 = 0, 1
	case !before.Existence && after.Existence: // exclusion, inclusion = INSERT
		fnc0, fnc1 = 1, 0
	case before.Existence && !after.Existence: // inclusion, exclusion = DELETE
		fnc0, fnc1 = 1, 1
	}

	isOld0 := 0
	if bytes.Equal(before.Key, []byte{}) && bytes.Equal(before.Value, []byte{}) {
		isOld0 = 1
	}

	return &ArboTransition{
		Siblings: before.Siblings,
		OldRoot:  before.Root,
		OldKey:   before.Key,
		OldValue: before.Value,
		NewRoot:  after.Root,
		NewKey:   after.Key,
		NewValue: after.Value,
		IsOld0:   isOld0,
		Fnc0:     fnc0,
		Fnc1:     fnc1,
	}
}

// ArboTransitionFromAddOrUpdate adds or updates a key in the tree,
// and returns a ArboTransition.
func ArboTransitionFromAddOrUpdate(o *State, k []byte, v []byte) (*ArboTransition, error) {
	mpBefore, mpAfter, err := o.ArboProofsFromAddOrUpdate(k, v)
	if err != nil {
		return &ArboTransition{}, err
	}
	return ArboTransitionFromArboProofPair(mpBefore, mpAfter), nil
}

// ArboTransitionFromNoop returns a NOOP ArboTransition.
func ArboTransitionFromNoop(o *State) (*ArboTransition, error) {
	root, err := o.Root()
	if err != nil {
		return &ArboTransition{}, err
	}
	mp := &ArboProof{
		Root:      root,
		Siblings:  [][]byte{},
		Key:       []byte{},
		Value:     []byte{},
		Existence: false,
	}
	return ArboTransitionFromArboProofPair(mp, mp), nil
}
